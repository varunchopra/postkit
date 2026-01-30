"""Pytest fixtures for integration tests across multiple postkit modules.

These tests verify that authn, authz, and config work correctly together
in real-world scenarios where companies integrate multiple modules.
"""

from pathlib import Path

import psycopg
import pytest
from postkit.authn import AuthnClient
from postkit.authz import AuthzClient
from postkit.config import ConfigClient
from tests.authn.helpers import cleanup_namespace as _cleanup_authn
from tests.authz.helpers import cleanup_namespace as _cleanup_authz
from tests.config.helpers import cleanup_namespace as _cleanup_config
from tests.conftest import DATABASE_URL
from tests.helpers import make_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection.

    Installs all schemas (authn, authz, config) once at the start of the test session.
    """
    conn = psycopg.connect(DATABASE_URL, autocommit=True)

    conn.execute("DROP SCHEMA IF EXISTS authn CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS authz CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS config CASCADE")

    dist_dir = Path(__file__).parent.parent.parent.parent / "dist"
    for schema in ["authn", "authz", "config"]:
        sql_file = dist_dir / f"{schema}.sql"
        if not sql_file.exists():
            pytest.fail(f"dist/{schema}.sql not found. Run 'make build' first.")
        conn.execute(sql_file.read_text())

    yield conn

    conn.execute("DROP SCHEMA IF EXISTS authn CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS authz CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS config CASCADE")
    conn.close()


def _cleanup_all(cursor, namespace: str):
    """Clean up all data for a namespace across all schemas."""
    _cleanup_authn(cursor, namespace)
    _cleanup_authz(cursor, namespace)
    _cleanup_config(cursor, namespace)


@pytest.fixture
def clients(db_connection, request):
    """
    All three SDK clients sharing the same namespace.

    Returns a tuple of (authn, authz, config) clients.

    Example:
        def test_user_with_permissions(clients):
            authn, authz, config = clients
            user_id = authn.create_user("alice@example.com", "hash")
            authz.grant("read", resource=("doc", "1"), subject=("user", user_id))
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()

    authn = AuthnClient(cursor, namespace)
    authz = AuthzClient(cursor, namespace)
    config = ConfigClient(cursor, namespace)

    yield authn, authz, config

    _cleanup_all(cursor, namespace)
    cursor.close()


@pytest.fixture
def authn(db_connection, request):
    """Standalone authn client for integration tests."""
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = AuthnClient(cursor, namespace)

    yield client

    _cleanup_all(cursor, namespace)
    cursor.close()


@pytest.fixture
def authz(db_connection, request):
    """Standalone authz client for integration tests."""
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = AuthzClient(cursor, namespace)

    yield client

    _cleanup_all(cursor, namespace)
    cursor.close()


@pytest.fixture
def config(db_connection, request):
    """Standalone config client for integration tests."""
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = ConfigClient(cursor, namespace)

    yield client

    _cleanup_all(cursor, namespace)
    cursor.close()


@pytest.fixture
def make_clients(db_connection):
    """
    Factory fixture that creates client tuples for specific namespaces.

    Use for multi-tenant tests where you need isolated environments.

    Example:
        def test_tenant_isolation(make_clients):
            authn_a, authz_a, config_a = make_clients("tenant_a")
            authn_b, authz_b, config_b = make_clients("tenant_b")
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> tuple[AuthnClient, AuthzClient, ConfigClient]:
        created.append(namespace)
        return (
            AuthnClient(cursor, namespace),
            AuthzClient(cursor, namespace),
            ConfigClient(cursor, namespace),
        )

    yield _make

    for ns in created:
        _cleanup_all(cursor, ns)
    cursor.close()
