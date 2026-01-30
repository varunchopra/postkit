"""Pytest fixtures for postkit.authz tests."""

import pytest
from postkit.authz import AuthzClient

from tests.authz.helpers import AuthzTestHelpers, cleanup_namespace
from tests.helpers import db_connection_for, make_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the authz schema installed."""
    yield from db_connection_for("authz")


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
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = AuthzClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
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
    namespace = make_namespace(request)
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
        cleanup_namespace(cursor, ns)
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
