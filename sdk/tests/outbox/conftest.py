"""Pytest fixtures for postkit.outbox tests."""

import psycopg
import pytest
from postkit.outbox import OutboxClient

from tests.helpers import db_connection_for, make_namespace
from tests.outbox.helpers import OutboxTestHelpers, cleanup_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the outbox schema installed."""
    yield from db_connection_for("outbox")


@pytest.fixture
def outbox(db_connection, request):
    """SDK-style OutboxClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = OutboxClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """Test helper utilities for direct table access.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = OutboxTestHelpers(cursor, namespace)

    yield helpers

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def connect(db_connection):
    """Factory for extra non-autocommit connections (multi-connection cases).

    Every connection gets a statement_timeout so a locking regression fails
    the suite loudly instead of hanging CI.
    """
    conns: list[psycopg.Connection] = []
    info = db_connection.info

    def _connect(statement_timeout_ms: int = 10000) -> psycopg.Connection:
        conn = psycopg.connect(
            host=info.host,
            port=info.port,
            dbname=info.dbname,
            user=info.user,
            password=info.password,
        )
        conn.execute(f"SET statement_timeout = {statement_timeout_ms}")
        conn.commit()
        conns.append(conn)
        return conn

    yield _connect

    for conn in conns:
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
