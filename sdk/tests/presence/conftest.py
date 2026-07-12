"""Pytest fixtures for postkit.presence tests."""

import pytest
from postkit.presence import PresenceClient

from tests.helpers import connection_factory_for, db_connection_for, make_namespace
from tests.presence.helpers import PresenceTestHelpers, cleanup_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the presence schema installed."""
    yield from db_connection_for("presence")


@pytest.fixture
def presence(db_connection, request):
    """SDK-style PresenceClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = PresenceClient(cursor, namespace)

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
    helpers = PresenceTestHelpers(cursor, namespace)

    yield helpers

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def connect(db_connection):
    """Factory for extra non-autocommit connections (two-connection races)."""
    yield from connection_factory_for(db_connection)
