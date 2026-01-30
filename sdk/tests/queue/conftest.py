"""Pytest fixtures for postkit.queue tests."""

import pytest
from postkit.queue import QueueClient

from tests.helpers import db_connection_for, make_namespace
from tests.queue.helpers import QueueTestHelpers, cleanup_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the queue schema installed."""
    yield from db_connection_for("queue")


@pytest.fixture
def queue(db_connection, request):
    """SDK-style QueueClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.

    Example:
        def test_push_pull(queue):
            job_id = queue.push("email", {"to": "alice@example.com"})
            job = queue.pull("email")
            assert job["id"] == job_id
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = QueueClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """Test helper utilities for direct table access.

    Example:
        def test_job_counts(queue, test_helpers):
            queue.push("tasks", {"task": 1})
            assert test_helpers.count_jobs(queue="tasks") == 1
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = QueueTestHelpers(cursor, namespace)

    yield helpers

    cursor.close()


@pytest.fixture
def make_queue(db_connection):
    """Factory fixture that creates QueueClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.

    Example:
        def test_isolation(make_queue):
            tenant_a = make_queue("tenant_a")
            tenant_b = make_queue("tenant_b")
            # ... test code, no manual cleanup needed
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> QueueClient:
        created.append(namespace)
        return QueueClient(cursor, namespace)

    yield _make

    # Cleanup all created namespaces (runs even if test fails)
    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


@pytest.fixture
def raw_cursor(db_connection, request):
    """Raw cursor for direct SQL access in tests.

    Use when you need to verify database state directly.
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()

    # Set tenant context
    cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))

    yield cursor, namespace

    cleanup_namespace(cursor, namespace)
    cursor.close()
