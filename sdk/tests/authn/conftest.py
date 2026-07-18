"""Pytest fixtures for postkit.authn tests."""

import pytest
from postkit.authn import AuthnClient

from tests.authn.helpers import AuthnTestHelpers, cleanup_namespace
from tests.helpers import connection_factory_for, db_connection_for, make_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the authn schema installed."""
    yield from db_connection_for("authn")


@pytest.fixture
def connect(db_connection):
    yield from connection_factory_for(db_connection)


@pytest.fixture
def authn(db_connection, request):
    """
    SDK-style AuthnClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.

    Example:
        def test_create_user(authn):
            user_id = authn.create_user("alice@example.com", "hashed_password")
            user = authn.get_user(user_id)
            assert user["email"] == "alice@example.com"
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = AuthnClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """
    Test helper utilities for direct table access.

    Example:
        def test_user_counts(authn, test_helpers):
            authn.create_user("alice@example.com", "hash")
            assert test_helpers.count_users() == 1
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = AuthnTestHelpers(cursor, namespace)

    yield helpers

    cursor.close()


@pytest.fixture
def make_authn(db_connection):
    """
    Factory fixture that creates AuthnClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.

    Example:
        def test_isolation(make_authn):
            tenant_a = make_authn("tenant_a")
            tenant_b = make_authn("tenant_b")
            # ... test code, no manual cleanup needed
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> AuthnClient:
        created.append(namespace)
        return AuthnClient(cursor, namespace)

    yield _make

    # Cleanup all created namespaces (runs even if test fails)
    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


@pytest.fixture
def user_with_session(authn):
    """
    Create a user with an active session.

    Returns dict with user_id and session_id.

    Example:
        def test_something(authn, user_with_session):
            result = authn.some_action(user_with_session["session_id"])
    """
    user_id = authn.create_user("alice@example.com", "hash")
    session_id = authn.create_session(user_id, "session_hash")
    return {"user_id": user_id, "session_id": session_id}


@pytest.fixture
def user_with_refresh_token(authn, user_with_session):
    """
    Create a user with session and refresh token.

    Returns dict with user_id, session_id, refresh_token_id, and family_id.

    Example:
        def test_rotation(authn, user_with_refresh_token):
            result = authn.rotate_refresh_token("refresh_hash", "new_hash")
    """
    result = authn.create_refresh_token(user_with_session["session_id"], "refresh_hash")
    return {
        **user_with_session,
        "refresh_token_id": str(result["refresh_token_id"]),
        "family_id": str(result["family_id"]),
    }
