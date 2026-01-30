"""Pytest fixtures for postkit.config tests."""

import pytest
from postkit.config import ConfigClient

from tests.config.helpers import ConfigTestHelpers, cleanup_namespace
from tests.helpers import db_connection_for, make_namespace


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped database connection with the config schema installed."""
    yield from db_connection_for("config")


@pytest.fixture
def config(db_connection, request):
    """
    SDK-style ConfigClient for tests.

    Each test gets its own namespace for isolation.
    Cleanup is automatic after each test.

    Example:
        def test_set_get(config):
            config.set("prompts/bot", {"template": "Hello"})
            result = config.get("prompts/bot")
            assert result["value"]["template"] == "Hello"
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = ConfigClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """
    Test helper utilities for direct table access.

    Example:
        def test_version_count(config, test_helpers):
            config.set("prompts/bot", {"v": 1})
            config.set("prompts/bot", {"v": 2})
            assert test_helpers.count_versions("prompts/bot") == 2
    """
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = ConfigTestHelpers(cursor, namespace)

    yield helpers

    cursor.close()


@pytest.fixture
def make_config(db_connection):
    """
    Factory fixture that creates ConfigClients and tracks namespaces for cleanup.

    Use this when tests need multiple namespaces. Cleanup happens automatically
    even if the test fails mid-execution.

    Example:
        def test_isolation(make_config):
            tenant_a = make_config("tenant_a")
            tenant_b = make_config("tenant_b")
            # ... test code, no manual cleanup needed
    """
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> ConfigClient:
        created.append(namespace)
        return ConfigClient(cursor, namespace)

    yield _make

    # Cleanup all created namespaces (runs even if test fails)
    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()
