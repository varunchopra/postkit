"""Namespace-level pool accounts (user_id = None) are usable end to end.

A pool is a shared namespace balance; allocate, consume, reserve, commit, and
adjust all accept a NULL user_id and operate on that shared row.
"""

import threading

import psycopg
from postkit.meter import MeterClient, MeterError
from tests.conftest import DATABASE_URL
from tests.meter.helpers import cleanup_namespace


def _make_client(namespace: str) -> tuple[psycopg.Connection, MeterClient]:
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    return conn, MeterClient(conn.cursor(), namespace)


class TestPoolAccounts:
    def test_allocate_creates_a_pool_account(self, meter):
        result = meter.allocate(None, "llm_call", 1000, "tokens")
        assert result["balance"] == 1000

    def test_pool_balance_is_readable_after_allocate(self, meter):
        meter.allocate(None, "llm_call", 1000, "tokens")

        meter.cursor.execute(
            "SELECT balance FROM meter.accounts "
            "WHERE namespace = %s AND user_id IS NULL",
            (meter.namespace,),
        )
        row = meter.cursor.fetchone()
        assert row is not None
        assert row[0] == 1000

    def test_consume_draws_from_the_pool(self, meter):
        meter.allocate(None, "llm_call", 1000, "tokens")

        result = meter.consume(None, "llm_call", 300, "tokens")
        assert result["success"] is True
        assert result["balance"] == 700

        # Persisted account state, not just the returned value.
        assert meter.get_balance(None, "llm_call", "tokens")["balance"] == 700

    def test_reserve_and_commit_against_the_pool(self, meter):
        meter.allocate(None, "llm_call", 1000, "tokens")

        res = meter.reserve(None, "llm_call", 400, "tokens")
        assert res["granted"] is True
        # The hold lands on the pool account.
        assert meter.get_balance(None, "llm_call", "tokens")["reserved"] == 400

        committed = meter.commit(res["reservation_id"], 250)
        assert committed["success"] is True

        pool = meter.get_balance(None, "llm_call", "tokens")
        assert pool["balance"] == 750
        assert pool["reserved"] == 0


class TestPoolAccountColdStartRace:
    """Two concurrent first-touches of the same pool account both succeed,
    rather than the losing caller hitting a unique_violation (23505)."""

    def test_concurrent_pool_allocate_does_not_raise(self, db_connection):
        namespace = "t_pool_cold_start"
        conn_setup, _ = _make_client(namespace)

        try:
            for attempt in range(10):
                # A fresh pool account per attempt (distinct resource) avoids
                # touching the immutable ledger between iterations.
                resource = f"model-{attempt}"
                results: dict = {"a": None, "b": None}
                barrier = threading.Barrier(2, timeout=5)

                def do_allocate(key, current_resource, round_barrier, round_results):
                    conn, client = _make_client(namespace)
                    try:
                        round_barrier.wait()
                        round_results[key] = client.allocate(
                            None, "llm_call", 100, "tokens", resource=current_resource
                        )
                    except (MeterError, threading.BrokenBarrierError) as e:
                        round_results[key] = e
                    finally:
                        conn.close()

                worker_args = (resource, barrier, results)
                t1 = threading.Thread(target=do_allocate, args=("a", *worker_args))
                t2 = threading.Thread(target=do_allocate, args=("b", *worker_args))
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                for key in ("a", "b"):
                    assert not isinstance(results[key], Exception), (
                        f"allocate raised {results[key]!r} (attempt {attempt})"
                    )

                row = conn_setup.execute(
                    "SELECT count(*), coalesce(sum(balance), 0) FROM meter.accounts "
                    "WHERE namespace = %s AND user_id IS NULL AND resource = %s",
                    (namespace, resource),
                ).fetchone()
                assert row == (1, 200), (
                    f"unexpected pool state {row} (attempt {attempt})"
                )
        finally:
            cleanup_namespace(conn_setup.cursor(), namespace)
            conn_setup.close()
