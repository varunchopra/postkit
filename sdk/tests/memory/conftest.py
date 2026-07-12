"""Pytest fixtures for postkit.memory tests."""

import pytest
from postkit.memory import MemoryClient

from tests.helpers import (
    connection_factory_for,
    db_connection_for,
    make_namespace,
    require_pgvector,
)
from tests.memory.helpers import MemoryTestHelpers, cleanup_namespace

# The whole memory suite shares one embedding dimension because set_dimension is
# database-global DDL. The unset/error paths live in test_dimension.py, which
# runs on its own throwaway database (see that file) so it never collides here.
SUITE_DIM = 4


@pytest.fixture(scope="session")
def db_connection():
    """Session-scoped connection with the memory schema installed and a fixed dim."""
    require_pgvector()
    yield from db_connection_for("memory")


@pytest.fixture(scope="session", autouse=True)
def _set_dimension(db_connection):
    """Fix the embedding dimension once for the whole suite (DDL is global)."""
    db_connection.execute("SELECT memory.set_dimension(%s)", (SUITE_DIM,))


@pytest.fixture
def memory(db_connection, request):
    """SDK-style MemoryClient for tests, one namespace per test."""
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    client = MemoryClient(cursor, namespace)

    yield client

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def make_memory(db_connection):
    """Factory that creates MemoryClients and tracks namespaces for cleanup."""
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> MemoryClient:
        created.append(namespace)
        return MemoryClient(cursor, namespace)

    yield _make

    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


@pytest.fixture
def test_helpers(db_connection, request):
    """Direct table access for setup/teardown, one namespace per test."""
    namespace = make_namespace(request)
    cursor = db_connection.cursor()
    helpers = MemoryTestHelpers(cursor, namespace)

    yield helpers

    cleanup_namespace(cursor, namespace)
    cursor.close()


@pytest.fixture
def connect(db_connection):
    """Factory for extra non-autocommit connections (two-connection races)."""
    yield from connection_factory_for(db_connection)
