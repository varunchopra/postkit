"""Ledger-retention regression tests."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from threading import Barrier

import psycopg
import pytest
from postkit.meter import MeterClient
from psycopg import sql
from tests.helpers import connect_as_rls_user, ensure_rls_role


def _wait_until_blocked_by(
    observer, backend_pid: int, blocker_pid: int, timeout: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT %s = ANY(pg_blocking_pids(%s))",
            (blocker_pid, backend_pid),
        ).fetchone()
        if row is not None and row[0]:
            return
        time.sleep(0.01)

    raise AssertionError(
        f"backend {backend_pid} was not blocked by backend {blocker_pid}"
    )


def _drop_partition(db_connection, partition: str) -> None:
    db_connection.execute(
        sql.SQL("DROP TABLE IF EXISTS meter.{}").format(sql.Identifier(partition))
    )


@pytest.mark.parametrize("user_id", ["alice", None])
def test_reconcile_remains_valid_after_old_partition_is_dropped(
    meter, db_connection, user_id
):
    partition = "ledger_y2000m01"
    created = db_connection.execute(
        "SELECT meter.create_partition(2000, 1)"
    ).fetchone()[0]
    assert created == partition

    meter.allocate(
        user_id,
        "llm_call",
        1000,
        "tokens",
        event_time=datetime(2000, 1, 15, tzinfo=timezone.utc),
    )
    assert meter.reconcile() == []

    dropped = {
        row[0]
        for row in db_connection.execute(
            "SELECT * FROM meter.drop_old_partitions(1)"
        ).fetchall()
    }
    assert partition in dropped
    assert meter.get_balance(user_id, "llm_call", "tokens")["balance"] == 1000
    assert meter.reconcile() == []


def test_reconcile_combines_cumulative_checkpoint_with_retained_ledger(
    meter, db_connection
):
    partitions = ["ledger_y1993m01", "ledger_y1994m01"]
    for year in (1993, 1994):
        assert (
            db_connection.execute(
                "SELECT meter.create_partition(%s, 1)", (year,)
            ).fetchone()[0]
            == f"ledger_y{year}m01"
        )

    try:
        for amount, event_time in (
            (100, datetime(1993, 1, 15, tzinfo=timezone.utc)),
            (200, datetime(1994, 1, 15, tzinfo=timezone.utc)),
            (300, None),
        ):
            meter.allocate(
                "alice",
                "llm_call",
                amount,
                "tokens",
                event_time=event_time,
            )

        dropped = {
            row[0]
            for row in db_connection.execute(
                "SELECT * FROM meter.drop_old_partitions(1)"
            ).fetchall()
        }
        assert set(partitions) <= dropped

        account = db_connection.execute(
            """SELECT balance, ledger_checkpoint
               FROM meter.accounts
               WHERE namespace = %s
                 AND user_id = 'alice'
                 AND event_type = 'llm_call'
                 AND resource = ''
                 AND unit = 'tokens'""",
            (meter.namespace,),
        ).fetchone()
        assert account == (600, 300)
        assert db_connection.execute(
            "SELECT sum(amount) FROM meter.ledger WHERE namespace = %s",
            (meter.namespace,),
        ).fetchone() == (300,)
        assert meter.reconcile() == []
    finally:
        for partition in partitions:
            _drop_partition(db_connection, partition)


def test_open_period_retry_survives_ledger_retention(meter, db_connection):
    partition = "ledger_y1995m01"
    period_start = date(1995, 1, 1)
    assert (
        db_connection.execute(
            "SELECT meter.create_partition(%s, %s)", (1995, 1)
        ).fetchone()[0]
        == partition
    )

    meter.set_period_config(
        "alice",
        "llm_call",
        "tokens",
        None,
        date(1994, 12, 1),
        1000,
    )
    # open_period writes at now(), so seed the old ledger entry and
    # period_openings row.
    opened_balance = meter.allocate(
        "alice",
        "llm_call",
        1000,
        "tokens",
        event_time=datetime(1995, 1, 15, tzinfo=timezone.utc),
    )["balance"]
    account_id = db_connection.execute(
        """SELECT account_id
           FROM meter.accounts
           WHERE namespace = %s
             AND user_id = 'alice'
             AND event_type = 'llm_call'
             AND resource = ''
             AND unit = 'tokens'""",
        (meter.namespace,),
    ).fetchone()[0]
    db_connection.execute(
        """INSERT INTO meter.period_openings
               (namespace, account_id, period_start, balance_after)
           VALUES (%s, %s, %s, %s)""",
        (meter.namespace, account_id, period_start, opened_balance),
    )

    try:
        dropped = {
            row[0]
            for row in db_connection.execute(
                "SELECT * FROM meter.drop_old_partitions(1)"
            ).fetchall()
        }
        assert partition in dropped

        retry = meter.open_period(
            "alice", "llm_call", "tokens", None, period_start, allocation=2000
        )

        assert retry == 1000
        assert meter.get_balance("alice", "llm_call", "tokens")["balance"] == 1000
        assert (
            db_connection.execute(
                "SELECT count(*) FROM meter.ledger WHERE namespace = %s",
                (meter.namespace,),
            ).fetchone()[0]
            == 0
        )
        assert meter.reconcile() == []
    finally:
        _drop_partition(db_connection, partition)


@pytest.mark.parametrize(
    ("begin_sql", "year"),
    [
        ("BEGIN ISOLATION LEVEL REPEATABLE READ", 1998),
        ("BEGIN ISOLATION LEVEL SERIALIZABLE", 1999),
    ],
)
def test_drop_old_partitions_rejects_fixed_snapshot(
    db_connection, connect, begin_sql, year
):
    partition = f"ledger_y{year}m01"
    assert (
        db_connection.execute(
            "SELECT meter.create_partition(%s, %s)", (year, 1)
        ).fetchone()[0]
        == partition
    )
    conn = connect()

    try:
        conn.execute(begin_sql)
        conn.execute("SELECT count(*) FROM meter.accounts").fetchone()

        with pytest.raises(psycopg.errors.InvalidTransactionState) as exc_info:
            conn.execute("SELECT * FROM meter.drop_old_partitions(1)").fetchall()

        assert exc_info.value.sqlstate == "25000"
        assert exc_info.value.diag.message_hint == (
            "postkit:meter:BIZ_RETENTION_REQUIRES_READ_COMMITTED"
        )
        conn.rollback()
        assert (
            db_connection.execute(
                "SELECT to_regclass(%s)", (f"meter.{partition}",)
            ).fetchone()[0]
            is not None
        )
    finally:
        conn.rollback()
        _drop_partition(db_connection, partition)


def test_drop_old_partitions_requires_rls_bypass(db_connection):
    partition = "ledger_y1992m01"
    assert (
        db_connection.execute("SELECT meter.create_partition(1992, 1)").fetchone()[0]
        == partition
    )
    ensure_rls_role(db_connection, "meter")
    conn = connect_as_rls_user(db_connection, "meter")

    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc_info:
            conn.execute("SELECT * FROM meter.drop_old_partitions(1)").fetchall()

        assert exc_info.value.diag.message_hint == (
            "postkit:meter:BIZ_ALL_NAMESPACES_REQUIRES_BYPASS"
        )
        conn.rollback()
        assert (
            db_connection.execute(
                "SELECT to_regclass(%s)", (f"meter.{partition}",)
            ).fetchone()[0]
            is not None
        )
    finally:
        conn.rollback()
        conn.close()
        _drop_partition(db_connection, partition)


def test_retention_includes_write_committed_during_lock_wait(
    meter, db_connection, connect
):
    partition = "ledger_y1997m01"
    assert (
        db_connection.execute(
            "SELECT meter.create_partition(%s, %s)", (1997, 1)
        ).fetchone()[0]
        == partition
    )
    writer_conn = connect()
    retention_conn = connect()
    writer = MeterClient(writer_conn.cursor(), meter.namespace)

    writer.allocate(
        "concurrent-writer",
        "llm_call",
        1000,
        "tokens",
        event_time=datetime(1997, 1, 15, tzinfo=timezone.utc),
    )
    retention_conn.execute("BEGIN ISOLATION LEVEL READ COMMITTED")

    def drop_old_partitions() -> set[str]:
        rows = retention_conn.execute(
            "SELECT * FROM meter.drop_old_partitions(1)"
        ).fetchall()
        retention_conn.commit()
        return {row[0] for row in rows}

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(drop_old_partitions)
            try:
                _wait_until_blocked_by(
                    db_connection,
                    retention_conn.info.backend_pid,
                    writer_conn.info.backend_pid,
                )
                writer_conn.commit()
                dropped = future.result(timeout=10)
            finally:
                writer_conn.rollback()

        assert partition in dropped
        assert (
            db_connection.execute(
                """
                SELECT ledger_checkpoint
                FROM meter.accounts
                WHERE namespace = %s
                  AND user_id = 'concurrent-writer'
                  AND event_type = 'llm_call'
                  AND resource = ''
                  AND unit = 'tokens'
                """,
                (meter.namespace,),
            ).fetchone()[0]
            == 1000
        )
        assert (
            meter.get_balance("concurrent-writer", "llm_call", "tokens")["balance"]
            == 1000
        )
        assert meter.reconcile() == []
    finally:
        writer_conn.rollback()
        retention_conn.rollback()
        _drop_partition(db_connection, partition)


def test_concurrent_retention_drops_partition_once(meter, db_connection, connect):
    partition = "ledger_y1996m01"
    assert (
        db_connection.execute(
            "SELECT meter.create_partition(%s, %s)", (1996, 1)
        ).fetchone()[0]
        == partition
    )
    meter.allocate(
        "alice",
        "llm_call",
        1000,
        "tokens",
        event_time=datetime(1996, 1, 15, tzinfo=timezone.utc),
    )

    blocker = connect()
    left = connect()
    right = connect()
    blocker.execute(
        "SELECT pg_advisory_xact_lock(meter._hash64('meter.drop_old_partitions'))"
    )
    start = Barrier(3, timeout=5)

    def drop_old_partitions(conn) -> set[str]:
        start.wait()
        rows = conn.execute("SELECT * FROM meter.drop_old_partitions(1)").fetchall()
        conn.commit()
        return {row[0] for row in rows}

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            left_future = executor.submit(drop_old_partitions, left)
            right_future = executor.submit(drop_old_partitions, right)
            start.wait()
            try:
                _wait_until_blocked_by(
                    db_connection, left.info.backend_pid, blocker.info.backend_pid
                )
                _wait_until_blocked_by(
                    db_connection, right.info.backend_pid, blocker.info.backend_pid
                )
            finally:
                blocker.commit()
            results = [
                left_future.result(timeout=10),
                right_future.result(timeout=10),
            ]

        assert sum(partition in result for result in results) == 1
        assert meter.get_balance("alice", "llm_call", "tokens")["balance"] == 1000
        assert meter.reconcile() == []
    finally:
        blocker.rollback()
        left.rollback()
        right.rollback()
        _drop_partition(db_connection, partition)
