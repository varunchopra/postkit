"""Pytest fixtures for postkit.meter tests."""

import pytest
from postkit.meter import MeterClient
from tests.helpers import connection_factory_for, db_connection_for, make_namespace
from tests.meter.helpers import MeterTestHelpers, cleanup_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the meter schema installed."""
    yield from db_connection_for("meter")


@pytest.fixture
def connect(db_connection):
    """Create isolated connections for transaction and concurrency tests."""
    yield from connection_factory_for(db_connection)


@pytest.fixture
def meter(db_connection, request):
    """
    SDK-style MeterClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.

    Example:
        def test_allocate_consume(meter):
            meter.allocate("alice", "llm_call", 1000, "tokens")
            result = meter.consume("alice", "llm_call", 100, "tokens")
            assert result["success"] is True
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = MeterClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """
    Test helper utilities for direct table access.

    Example:
        def test_ledger_entries(meter, test_helpers):
            meter.allocate("alice", "llm_call", 1000, "tokens")
            assert test_helpers.count_ledger_entries() == 1
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = MeterTestHelpers(cursor, namespace)

    yield helpers

    cursor.close()


@pytest.fixture
def make_meter(db_connection):
    """
    Factory fixture that creates MeterClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.

    Example:
        def test_isolation(make_meter):
            tenant_a = make_meter("tenant_a")
            tenant_b = make_meter("tenant_b")
            # ... test code, no manual cleanup needed
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> MeterClient:
        created.append(namespace)
        return MeterClient(cursor, namespace)

    yield _make

    # Cleanup all created namespaces (runs even if test fails)
    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()
