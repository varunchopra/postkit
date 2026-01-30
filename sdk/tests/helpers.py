"""Shared test utilities and data used across all SDK test modules."""

from pathlib import Path

import psycopg
import pytest

from tests.conftest import DATABASE_URL


def db_connection_for(schema: str):
    """Yield a session-scoped connection that installs and tears down a schema.

    Each module's conftest wraps this in a ``@pytest.fixture(scope="session")``
    to get a connection with the module's schema installed.  The schema name is
    a build-time constant from our own conftest files, not user input.
    """
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    dist_sql = Path(__file__).parent.parent.parent / "dist" / f"{schema}.sql"
    if not dist_sql.exists():
        pytest.fail(f"dist/{schema}.sql not found. Run 'make build' first.")

    conn.execute(dist_sql.read_text())
    yield conn

    conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    conn.close()


def make_namespace(request) -> str:
    """Generate a unique namespace from test name.

    Used by all module conftest files for per-test namespace isolation.
    """
    namespace = request.node.name.replace("[", "_").replace("]", "_").replace("-", "_")
    return "t_" + namespace.lower()[:50]


def fetch_row(cursor) -> dict | None:
    """Convert the current cursor result row to a dict, or None if no row.

    Replaces the repeated fetchone-to-dict pattern in test helpers.
    """
    row = cursor.fetchone()
    if row is None:
        return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


INVALID_NAMESPACES = [
    pytest.param(None, id="null"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace_only"),
    pytest.param(" leading", id="leading_whitespace"),
    pytest.param("trailing ", id="trailing_whitespace"),
    pytest.param("has\ttab", id="control_chars"),
    pytest.param("a" * 1025, id="over_max_length"),
]

VALID_NAMESPACES = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]

NAMESPACE_ERROR_CASES = [
    pytest.param(None, "VAL_NAMESPACE_NULL", id="null"),
    pytest.param("", "VAL_NAMESPACE_EMPTY", id="empty"),
    pytest.param("a" * 1025, "VAL_NAMESPACE_TOO_LONG", id="too_long"),
    pytest.param("has\ttab", "VAL_NAMESPACE_INVALID_CHARS", id="control_chars"),
]


def assert_audit_fields(event: dict, **expected) -> None:
    """Assert specific fields on an audit event dict.

    Provides clear error messages showing which field mismatched.

    Usage:
        assert_audit_fields(events[0],
            actor_id="user:alice",
            request_id="req-123",
            on_behalf_of=None,
        )
    """
    for field, value in expected.items():
        assert event[field] == value, (
            f"Audit event {field}: expected {value!r}, got {event.get(field)!r}"
        )


def assert_partition_create(cursor, schema: str, year: int, month: int) -> str:
    """Create a partition and assert it returns the expected name."""
    cursor.execute(
        f"SELECT {schema}.create_audit_partition(%s, %s)",
        (year, month),
    )
    result = cursor.fetchone()[0]
    expected = f"audit_events_y{year}m{month:02d}"
    assert result == expected
    return expected


def assert_partition_idempotent(cursor, schema: str, year: int, month: int) -> None:
    """Assert that creating the same partition twice returns NULL the second time."""
    cursor.execute(
        f"SELECT {schema}.create_audit_partition(%s, %s)",
        (year, month),
    )
    first = cursor.fetchone()[0]
    assert first is not None

    cursor.execute(
        f"SELECT {schema}.create_audit_partition(%s, %s)",
        (year, month),
    )
    second = cursor.fetchone()[0]
    assert second is None


def assert_partition_rejects_invalid_month(cursor, schema: str) -> None:
    """Assert that invalid month values (0, 13) are rejected."""
    with pytest.raises(
        psycopg.errors.InvalidParameterValue, match="Month must be between 1 and 12"
    ):
        cursor.execute(
            f"SELECT {schema}.create_audit_partition(%s, %s)",
            (2024, 0),
        )

    with pytest.raises(
        psycopg.errors.InvalidParameterValue, match="Month must be between 1 and 12"
    ):
        cursor.execute(
            f"SELECT {schema}.create_audit_partition(%s, %s)",
            (2024, 13),
        )


def cleanup_partition(cursor, schema: str, name: str) -> None:
    """Drop a test partition."""
    cursor.execute(f"DROP TABLE IF EXISTS {schema}.{name}")
