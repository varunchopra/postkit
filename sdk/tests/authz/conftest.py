"""Pytest fixtures for postkit.authz tests."""

from pathlib import Path

import psycopg
import pytest
from postkit.authz import AuthzClient

from tests.authz.helpers import AuthzTestHelpers
from tests.conftest import DATABASE_URL


@pytest.fixture(scope="session")
def db_connection():
    """
    Session-scoped database connection.
    Installs the authz schema once at the start of the test session.
    """
    conn = psycopg.connect(DATABASE_URL, autocommit=True)

    # Install fresh schema
    conn.execute("DROP SCHEMA IF EXISTS authz CASCADE")

    # Load the built SQL file (sdk/tests/authz/ -> root/dist/)
    dist_sql = Path(__file__).parent.parent.parent.parent / "dist" / "authz.sql"
    if not dist_sql.exists():
        pytest.fail("dist/authz.sql not found. Run 'make build' first.")

    conn.execute(dist_sql.read_text())

    yield conn

    # Cleanup at end of session
    conn.execute("DROP SCHEMA IF EXISTS authz CASCADE")
    conn.close()


def _make_namespace(request) -> str:
    """Generate a unique namespace from test name."""
    namespace = request.node.name.replace("[", "_").replace("]", "_").replace("-", "_")
    return "t_" + namespace.lower()[:50]


def _cleanup(cursor, namespace: str):
    """Clean up all data for a namespace."""
    cursor.execute("DELETE FROM authz.audit_events WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM authz.permission_hierarchy WHERE namespace = %s", (namespace,)
    )


@pytest.fixture
def authz(db_connection, request):
    """
    SDK-style AuthzClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.

    Example:
        def test_permissions(authz):
            authz.grant("admin", resource=("repo", "api"), subject=("user", "alice"))
            assert authz.check(("user", "alice"), "read", ("repo", "api"))
    """
    namespace = _make_namespace(request)
    cursor = db_connection.cursor()
    client = AuthzClient(cursor, namespace)

    yield client

    _cleanup(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """
    Test helper utilities for direct table access.

    Example:
        def test_tuple_counts(authz, test_helpers):
            authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
            assert test_helpers.count_tuples(resource=("doc", "1")) == 1
    """
    namespace = _make_namespace(request)
    cursor = db_connection.cursor()
    helpers = AuthzTestHelpers(cursor, namespace)

    yield helpers

    cursor.close()


@pytest.fixture
def make_authz(db_connection):
    """
    Factory fixture that creates AuthzClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.

    Example:
        def test_isolation(make_authz):
            tenant_a = make_authz("tenant_a")
            tenant_b = make_authz("tenant_b")
            # ... test code, no manual cleanup needed
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> AuthzClient:
        created.append(namespace)
        return AuthzClient(cursor, namespace)

    yield _make

    # Cleanup all created namespaces (runs even if test fails)
    for ns in created:
        _cleanup(cursor, ns)
    cursor.close()


@pytest.fixture(autouse=True)
def cleanup_global_hierarchies(db_connection):
    """Clean up global hierarchies before and after each test.

    Since hierarchies are global (Zanzibar-style), tests that modify
    hierarchies need explicit cleanup to avoid affecting other tests.
    """
    with db_connection.cursor() as cur:
        cur.execute("DELETE FROM authz.permission_hierarchy WHERE namespace = 'global'")
    yield
    with db_connection.cursor() as cur:
        cur.execute("DELETE FROM authz.permission_hierarchy WHERE namespace = 'global'")
