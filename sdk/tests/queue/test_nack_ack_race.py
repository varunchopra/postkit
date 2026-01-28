"""
Tests for race conditions between concurrent ack, nack, and fail operations.

Before the fix, nack() and fail() used SELECT without FOR UPDATE, allowing
concurrent operations to corrupt job state: creating duplicate dead letter
entries when two fail() calls race on the same job.
"""

import threading

import psycopg
from postkit.queue import QueueClient

from tests.conftest import DATABASE_URL


def _make_client(namespace: str) -> tuple[psycopg.Connection, QueueClient]:
    """Create a new connection and QueueClient for concurrent use."""
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    cursor = conn.cursor()
    return conn, QueueClient(cursor, namespace)


def _push_and_pull(conn: psycopg.Connection, namespace: str) -> int:
    """Push a job via raw SQL and pull it to 'running' status. Returns job ID."""
    conn.execute(
        "SELECT queue.push("
        "  p_namespace := %s, p_queue := 'tasks',"
        "  p_payload := '{}'::jsonb"
        ")",
        (namespace,),
    )

    row = conn.execute(
        "SELECT * FROM queue.pull(p_namespace := %s, p_queue := 'tasks',"
        "  p_worker_id := 'test-worker')",
        (namespace,),
    ).fetchone()
    assert row is not None, "pull() returned no job"
    return row[0]


def _cleanup(conn: psycopg.Connection, namespace: str):
    """Clean up all queue data for a namespace."""
    conn.execute("DELETE FROM queue.dead_letters WHERE namespace = %s", (namespace,))
    conn.execute("DELETE FROM queue.jobs WHERE namespace = %s", (namespace,))
    conn.execute("DELETE FROM queue.config WHERE namespace = %s", (namespace,))


class TestConcurrentFail:
    """Tests for concurrent fail operations on the same job."""

    def test_concurrent_fail_does_not_create_duplicate_dead_letters(
        self, db_connection
    ):
        """Two concurrent fail() calls must produce exactly one dead letter entry.

        Without FOR UPDATE, both threads read the running job, both insert into
        dead_letters, and both update to 'dead' — creating duplicate entries.
        """
        namespace = "t_race_double_fail"
        conn_setup, _ = _make_client(namespace)

        try:
            duplicates_observed = False

            for attempt in range(10):
                if duplicates_observed:
                    break

                job_id = _push_and_pull(conn_setup, namespace)

                results: dict = {"fail1": None, "fail2": None}
                barrier = threading.Barrier(2, timeout=5)

                def do_fail(key: str):
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        results[key] = client.fail(job_id, error=f"error from {key}")
                    except Exception as e:
                        results[key] = e
                    finally:
                        conn.close()

                t1 = threading.Thread(target=do_fail, args=("fail1",))
                t2 = threading.Thread(target=do_fail, args=("fail2",))
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                # Exactly one dead letter entry for this job.
                count = conn_setup.execute(
                    "SELECT COUNT(*) FROM queue.dead_letters "
                    "WHERE namespace = %s AND original_job_id = %s",
                    (namespace, job_id),
                ).fetchone()[0]

                if count > 1:
                    duplicates_observed = True

                # Clean up for next attempt.
                conn_setup.execute(
                    "DELETE FROM queue.dead_letters WHERE namespace = %s",
                    (namespace,),
                )
                conn_setup.execute(
                    "DELETE FROM queue.jobs WHERE namespace = %s", (namespace,)
                )

            assert not duplicates_observed, (
                "Race condition: concurrent fail() created duplicate "
                "dead_letters entries."
            )

        finally:
            _cleanup(conn_setup, namespace)
            conn_setup.close()

    def test_concurrent_fail_exactly_one_returns_true(self, db_connection):
        """Of two concurrent fail() calls, exactly one should return true."""
        namespace = "t_race_fail_returns"
        conn_setup, _ = _make_client(namespace)

        try:
            both_true_observed = False

            for attempt in range(10):
                if both_true_observed:
                    break

                job_id = _push_and_pull(conn_setup, namespace)

                results: dict = {"fail1": None, "fail2": None}
                barrier = threading.Barrier(2, timeout=5)

                def do_fail(key: str):
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        results[key] = client.fail(job_id, error=f"error from {key}")
                    except Exception as e:
                        results[key] = e
                    finally:
                        conn.close()

                t1 = threading.Thread(target=do_fail, args=("fail1",))
                t2 = threading.Thread(target=do_fail, args=("fail2",))
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                # At most one should return True.
                true_count = sum(1 for v in results.values() if v is True)
                if true_count > 1:
                    both_true_observed = True

                # Clean up for next attempt.
                conn_setup.execute(
                    "DELETE FROM queue.dead_letters WHERE namespace = %s",
                    (namespace,),
                )
                conn_setup.execute(
                    "DELETE FROM queue.jobs WHERE namespace = %s", (namespace,)
                )

            assert not both_true_observed, (
                "Race condition: both concurrent fail() calls returned True."
            )

        finally:
            _cleanup(conn_setup, namespace)
            conn_setup.close()


class TestNackStatusGuard:
    """Tests that nack's UPDATE only affects running jobs."""

    def test_nack_does_not_overwrite_dead_status(self, db_connection):
        """nack's UPDATE must not change a job that is no longer running.

        Verifies that the status guard (AND status = 'running') on nack's UPDATE
        prevents overwriting a 'dead' status back to 'pending'.
        """
        namespace = "t_nack_guard"
        conn_setup, _ = _make_client(namespace)

        try:
            corruption_observed = False

            for attempt in range(10):
                if corruption_observed:
                    break

                job_id = _push_and_pull(conn_setup, namespace)

                results: dict = {"fail_result": None, "nack_error": None}
                barrier = threading.Barrier(2, timeout=5)

                def do_fail():
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        results["fail_result"] = client.fail(job_id, error="permanent")
                    except Exception as e:
                        results["fail_result"] = e
                    finally:
                        conn.close()

                def do_nack():
                    conn, client = _make_client(namespace)
                    try:
                        barrier.wait()
                        client.nack(job_id, error="temporary")
                    except Exception as e:
                        results["nack_error"] = e
                    finally:
                        conn.close()

                t1 = threading.Thread(target=do_fail)
                t2 = threading.Thread(target=do_nack)
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                # Verify state consistency: if fail returned True, job must be
                # 'dead', not 'pending' (nack must not have overwritten it).
                if results["fail_result"] is True:
                    row = conn_setup.execute(
                        "SELECT status FROM queue.jobs "
                        "WHERE namespace = %s AND id = %s",
                        (namespace, job_id),
                    ).fetchone()

                    if row and row[0] == "pending":
                        corruption_observed = True

                # Clean up for next attempt.
                conn_setup.execute(
                    "DELETE FROM queue.dead_letters WHERE namespace = %s",
                    (namespace,),
                )
                conn_setup.execute(
                    "DELETE FROM queue.jobs WHERE namespace = %s", (namespace,)
                )

            assert not corruption_observed, (
                "Race condition: nack() overwrote a dead job back to pending "
                "after fail() had already committed."
            )

        finally:
            _cleanup(conn_setup, namespace)
            conn_setup.close()
