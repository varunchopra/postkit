"""Ledger immutability tests."""

import psycopg
import pytest


def _transactional_connection(db_connection):
    info = db_connection.info
    return psycopg.connect(
        host=info.host,
        port=info.port,
        dbname=info.dbname,
        user=info.user,
        password=info.password,
    )


def _assert_truncate_rejected(connection, statement):
    try:
        with pytest.raises(psycopg.errors.RestrictViolation) as exc_info:
            connection.execute(statement)
        assert exc_info.value.diag.message_hint == "postkit:meter:BIZ_LEDGER_IMMUTABLE"
    finally:
        connection.rollback()
        connection.close()


class TestLedgerTruncateImmutability:
    def test_parent_ledger_cannot_be_truncated(self, meter, db_connection):
        meter.allocate("alice", "tokens", 100, "token")

        connection = _transactional_connection(db_connection)
        _assert_truncate_rejected(connection, "TRUNCATE meter.ledger")

        assert len(meter.get_ledger("alice", "tokens", "token")) == 1

    def test_direct_partition_cannot_be_truncated(self, meter, db_connection):
        meter.allocate("alice", "tokens", 100, "token")
        meter.cursor.execute(
            "SELECT tableoid::regclass::text FROM meter.ledger "
            "WHERE namespace = %s LIMIT 1",
            (meter.namespace,),
        )
        partition = meter.cursor.fetchone()[0]

        connection = _transactional_connection(db_connection)
        _assert_truncate_rejected(connection, f"TRUNCATE {partition}")

        assert len(meter.get_ledger("alice", "tokens", "token")) == 1
