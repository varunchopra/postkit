"""
Regression tests for concurrent commit() and release_expired_reservations().

Before the fix, these two functions acquired locks in opposite order:
- release_expired_reservations(): accounts row → reservations row
- commit(): reservations row → accounts row

This caused deadlocks when both targeted the same expired reservation.
The fix combines release_expired_reservations() into a single statement
that locks reservations first (matching commit()'s order).
"""

import threading

import psycopg
from postkit.meter import MeterClient
from tests.conftest import DATABASE_URL
from tests.meter.helpers import cleanup_namespace


def _make_client(namespace: str) -> tuple[psycopg.Connection, MeterClient]:
    """Create a new connection and MeterClient for concurrent use."""
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    cursor = conn.cursor()
    return conn, MeterClient(cursor, namespace)


def _force_expire(conn: psycopg.Connection, reservation_id: str, namespace: str):
    """Set a reservation's expires_at to the past."""
    conn.execute(
        "UPDATE meter.reservations SET expires_at = now() - interval '1 hour' "
        "WHERE reservation_id = %s AND namespace = %s",
        (reservation_id, namespace),
    )


class TestCommitExpiredReservation:
    """Tests for committing reservations that have expired but not been cleaned up."""

    def test_commit_succeeds_on_expired_but_uncleaned_reservation(
        self, meter, test_helpers, db_connection
    ):
        """Commit succeeds on an expired reservation because it only checks status, not expires_at.

        This documents current behavior: the maintenance job (release_expired_reservations)
        is the sole enforcer of expiry. Until it runs, expired reservations remain committable.
        """
        meter.allocate("alice", "llm_call", 1000, "tokens")
        reservation = meter.reserve(
            "alice", "llm_call", 200, "tokens", ttl_seconds=3600
        )

        # Force expiration without running the cleanup job.
        test_helpers.set_reservation_expired(reservation["reservation_id"])

        # Commit should succeed — it checks status='active', not expires_at.
        result = meter.commit(reservation["reservation_id"], 150)
        assert result["success"] is True
        assert result["consumed"] == 150

        # Verify account state is consistent.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 850  # 1000 - 150
        assert balance["reserved"] == 0  # Hold released by commit.

    def test_no_deadlock_on_concurrent_commit_and_expire(self, db_connection):
        """Concurrent commit and release_expired_reservations do not deadlock.

        Both now lock reservations before accounts, so no lock ordering conflict.
        Regression test: before the fix, this deadlocked within ~4 attempts.
        """
        namespace = "t_deadlock_commit_expire"
        conn_setup, meter_setup = _make_client(namespace)

        try:
            # Setup: create reservation and force-expire it.
            meter_setup.allocate("alice", "llm_call", 5000, "tokens")
            reservation = meter_setup.reserve(
                "alice", "llm_call", 1000, "tokens", ttl_seconds=3600
            )
            res_id = reservation["reservation_id"]
            _force_expire(conn_setup, res_id, namespace)

            deadlock_observed = False
            # Try multiple times since deadlock is timing-dependent.
            for attempt in range(10):
                if deadlock_observed:
                    break

                # Reset: re-create scenario if previous attempt consumed it.
                if attempt > 0:
                    # Clean up previous attempt's state.
                    cleanup_namespace(conn_setup, namespace)
                    meter_setup.allocate("alice", "llm_call", 5000, "tokens")
                    reservation = meter_setup.reserve(
                        "alice", "llm_call", 1000, "tokens", ttl_seconds=3600
                    )
                    res_id = reservation["reservation_id"]
                    _force_expire(conn_setup, res_id, namespace)

                results = {"commit_error": None, "expire_error": None}
                barrier = threading.Barrier(2, timeout=5)

                def do_commit():
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        client.commit(res_id, 500)
                    except Exception as e:
                        results["commit_error"] = e
                    finally:
                        conn.close()

                def do_expire():
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        client.release_expired_reservations()
                    except Exception as e:
                        results["expire_error"] = e
                    finally:
                        conn.close()

                t1 = threading.Thread(target=do_commit)
                t2 = threading.Thread(target=do_expire)
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                # Check if deadlock occurred.
                for err in [results["commit_error"], results["expire_error"]]:
                    if err and hasattr(err, "__cause__"):
                        cause = err.__cause__
                        if hasattr(cause, "sqlstate") and cause.sqlstate == "40P01":
                            deadlock_observed = True
                    if err and hasattr(err, "sqlstate") and err.sqlstate == "40P01":
                        deadlock_observed = True

            # Verify account consistency regardless of deadlock.
            # Re-read state with a fresh client.
            discrepancies = meter_setup.reconcile()
            assert discrepancies == [], (
                f"Account inconsistency after race: {discrepancies}"
            )

            assert not deadlock_observed, (
                "Deadlock between commit() and release_expired_reservations() — "
                "lock ordering regression."
            )

        finally:
            cleanup_namespace(conn_setup, namespace)
            conn_setup.close()


class TestExpireReleaseConcurrencyStress:
    """Stress tests for concurrent reservation commits and expiry cleanup."""

    def test_many_concurrent_commits_with_expire(self, db_connection):
        """Many threads committing expired reservations while cleanup runs concurrently.

        Verifies account consistency under high contention.
        """
        namespace = "t_stress_commit_expire"
        conn_setup, meter_setup = _make_client(namespace)
        num_reservations = 20

        try:
            meter_setup.allocate("alice", "llm_call", 100_000, "tokens")

            # Create reservations and expire them all.
            reservation_ids = []
            for _ in range(num_reservations):
                r = meter_setup.reserve(
                    "alice", "llm_call", 500, "tokens", ttl_seconds=3600
                )
                reservation_ids.append(r["reservation_id"])
                _force_expire(conn_setup, r["reservation_id"], namespace)

            # State: 20 expired-but-active reservations, reserved=10000.
            balance = meter_setup.get_balance("alice", "llm_call", "tokens")
            assert balance["reserved"] == 10_000

            results_lock = threading.Lock()
            results = {
                "commits": 0,
                "commit_errors": 0,
                "deadlocks": 0,
                "expire_errors": 0,
            }

            half = num_reservations // 2
            barrier = threading.Barrier(half + 1, timeout=10)

            def do_commit(res_id):
                conn, client = _make_client(namespace)
                try:
                    barrier.wait()
                    client.commit(res_id, 300)
                    with results_lock:
                        results["commits"] += 1
                except Exception as e:
                    with results_lock:
                        cause = getattr(e, "__cause__", e)
                        if hasattr(cause, "sqlstate") and cause.sqlstate == "40P01":
                            results["deadlocks"] += 1
                        else:
                            results["commit_errors"] += 1
                finally:
                    conn.close()

            def do_expire():
                conn, client = _make_client(namespace)
                try:
                    barrier.wait()
                    client.release_expired_reservations()
                except Exception:
                    with results_lock:
                        results["expire_errors"] += 1
                finally:
                    conn.close()

            # Launch half the reservations as commits + 1 expire thread.
            threads = []
            for res_id in reservation_ids[:half]:
                threads.append(threading.Thread(target=do_commit, args=(res_id,)))
            threads.append(threading.Thread(target=do_expire))

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            # Verify account consistency.
            discrepancies = meter_setup.reconcile()
            assert discrepancies == [], (
                f"Account inconsistency under stress: {discrepancies}\n"
                f"Results: {results}"
            )

            balance = meter_setup.get_balance("alice", "llm_call", "tokens")
            # All 20 reservations resolved (committed or expired), none active.
            assert balance["reserved"] == 0, (
                f"Leaked reservation hold: {balance['reserved']}\nResults: {results}"
            )

            assert results["deadlocks"] == 0, (
                f"Lock ordering regression: {results['deadlocks']} deadlocks\n"
                f"Results: {results}"
            )

        finally:
            cleanup_namespace(conn_setup, namespace)
            conn_setup.close()
