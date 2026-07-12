"""Pytest fixtures for postkit.lease tests."""

import pytest
from postkit.lease import LeaseClient

from tests.helpers import connection_factory_for, db_connection_for, make_namespace
from tests.lease.helpers import LeaseTestHelpers, cleanup_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the lease schema installed."""
    yield from db_connection_for("lease")


@pytest.fixture
def lease(db_connection, request):
    """SDK-style LeaseClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = LeaseClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def make_lease(db_connection):
    """Factory fixture that creates LeaseClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> LeaseClient:
        created.append(namespace)
        return LeaseClient(cursor, namespace)

    yield _make

    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """Test helper utilities for direct table access.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = LeaseTestHelpers(cursor, namespace)

    yield helpers

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def connect(db_connection):
    """Factory for extra non-autocommit connections (two-connection races)."""
    yield from connection_factory_for(db_connection)
