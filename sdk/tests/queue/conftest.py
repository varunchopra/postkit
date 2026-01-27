"""Pytest fixtures for postkit.queue tests."""

from pathlib import Path

import psycopg
import pytest
from postkit.queue import Client as QueueClient

from tests.conftest import DATABASE_URL


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection.

    Installs the queue schema once at the start of the test session.
    """
    conn = psycopg.connect(DATABASE_URL, autocommit=True)

    # Install fresh schema
    conn.execute("DROP SCHEMA IF EXISTS queue CASCADE")

    # Load the built SQL file (sdk/tests/queue/ -> root/dist/)
    dist_sql = Path(__file__).parent.parent.parent.parent / "dist" / "queue.sql"
    if not dist_sql.exists():
        pytest.fail("dist/queue.sql not found. Run 'make build' first.")

    conn.execute(dist_sql.read_text())

    yield conn

    # Cleanup at end of session
    conn.execute("DROP SCHEMA IF EXISTS queue CASCADE")
    conn.close()


def _make_namespace(request) -> str:
    """Generate a unique namespace from test name."""
    namespace = request.node.name.replace("[", "_").replace("]", "_").replace("-", "_")
    return "t_" + namespace.lower()[:50]


def _cleanup(cursor, namespace: str):
    """Clean up all data for a namespace."""
    cursor.execute("DELETE FROM queue.dead_letters WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.schedules WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.jobs WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.config WHERE namespace = %s", (namespace,))


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
    namespace = _make_namespace(request)
    cursor = db_connection.cursor()
    client = QueueClient(cursor, namespace)

    yield client

    _cleanup(cursor, namespace)
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
        _cleanup(cursor, ns)
    cursor.close()


@pytest.fixture
def raw_cursor(db_connection, request):
    """Raw cursor for direct SQL access in tests.

    Use when you need to verify database state directly.
    """
    namespace = _make_namespace(request)
    cursor = db_connection.cursor()

    # Set tenant context
    cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))

    yield cursor, namespace

    _cleanup(cursor, namespace)
    cursor.close()
