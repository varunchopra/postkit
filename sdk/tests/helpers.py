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


VALID_NAMESPACES = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]

NAMESPACE_ERROR_CASES = [
    pytest.param(None, "VAL_NAMESPACE_NULL", id="null"),
    pytest.param("", "VAL_NAMESPACE_EMPTY", id="empty"),
    pytest.param("   ", "VAL_NAMESPACE_EMPTY", id="whitespace_only"),
    pytest.param("a" * 1025, "VAL_NAMESPACE_TOO_LONG", id="too_long"),
    pytest.param("has\ttab", "VAL_NAMESPACE_INVALID_CHARS", id="control_chars"),
    pytest.param(" leading", "VAL_NAMESPACE_WHITESPACE", id="leading_whitespace"),
    pytest.param("trailing ", "VAL_NAMESPACE_WHITESPACE", id="trailing_whitespace"),
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


def assert_partition_rejects_invalid_year(cursor, schema: str) -> None:
    """Assert that invalid year values (1969, 10000) are rejected."""
    with pytest.raises(
        psycopg.errors.InvalidParameterValue, match="Year must be between"
    ):
        cursor.execute(
            f"SELECT {schema}.create_audit_partition(%s, %s)",
            (1969, 6),
        )

    with pytest.raises(
        psycopg.errors.InvalidParameterValue, match="Year must be between"
    ):
        cursor.execute(
            f"SELECT {schema}.create_audit_partition(%s, %s)",
            (10000, 6),
        )


def cleanup_partition(cursor, schema: str, name: str) -> None:
    """Drop a test partition."""
    cursor.execute(f"DROP TABLE IF EXISTS {schema}.{name}")


def ensure_rls_role(db_connection, schema: str) -> None:
    """Create non-superuser role for RLS testing. Idempotent.

    Creates role '{schema}_rls_user' with grants on the schema. The role has no
    BYPASSRLS attribute, so RLS policies are enforced when connected as this role.

    Args:
        db_connection: Superuser connection to execute DDL
        schema: Schema name (e.g., 'authn', 'queue')
    """
    role = f"{schema}_rls_user"
    password = f"{schema}_rls_pass"
    db_connection.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
                CREATE ROLE {role} LOGIN PASSWORD '{password}';
            END IF;
        END $$;
        """
    )
    db_connection.execute(f"GRANT USAGE ON SCHEMA {schema} TO {role}")
    db_connection.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO {role}")
    db_connection.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {role}")
    db_connection.execute(
        f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO {role}"
    )


def connect_as_rls_user(db_connection, schema: str, *, autocommit: bool = False):
    """Connect as non-superuser for RLS testing.

    Args:
        db_connection: Existing connection to get host/port/dbname from
        schema: Schema name (determines role name)
        autocommit: Whether to enable autocommit mode

    Returns:
        New psycopg connection as the RLS test user
    """
    info = db_connection.info
    role = f"{schema}_rls_user"
    password = f"{schema}_rls_pass"
    return psycopg.connect(
        host=info.host,
        port=info.port,
        dbname=info.dbname,
        user=role,
        password=password,
        autocommit=autocommit,
    )
