"""Pytest fixtures for postkit.outbox tests."""

import pytest
from postkit.outbox import OutboxClient

from tests.helpers import connection_factory_for, db_connection_for, make_namespace
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
    """Factory for extra non-autocommit connections (multi-connection cases)."""
    yield from connection_factory_for(db_connection)
