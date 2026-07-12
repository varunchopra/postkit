"""Shared test utilities and data used across all SDK test modules."""

from pathlib import Path

import psycopg
import pytest

from tests.conftest import DATABASE_URL


def db_connection_for(*schemas: str):
    """Yield an autocommit connection that installs and tears down schemas.

    Each conftest wraps this in a session- or module-scoped fixture to get a
    connection with the schemas it needs installed.  The schema names are
    build-time constants from our own conftest files, not user input.
    """
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    for schema in schemas:
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    dist_dir = Path(__file__).parent.parent.parent / "dist"
    for schema in schemas:
        dist_sql = dist_dir / f"{schema}.sql"
        if not dist_sql.exists():
            pytest.fail(f"dist/{schema}.sql not found. Run 'make build' first.")
        conn.execute(dist_sql.read_text())

    yield conn

    for schema in schemas:
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    conn.close()


def connection_factory_for(db_connection):
    """Yield a factory for extra non-autocommit connections to the same database.

    Each conftest wraps this in a ``connect`` fixture for multi-connection
    cases (races, worker transactions).  Every connection gets a
    statement_timeout so a locking regression fails the suite loudly instead
    of hanging CI; teardown rolls back and closes whatever the test left open.
    """
    conns: list[psycopg.Connection] = []
    info = db_connection.info

    def _connect(statement_timeout_ms: int = 10000) -> psycopg.Connection:
        conn = psycopg.connect(
            host=info.host,
            port=info.port,
            dbname=info.dbname,
            user=info.user,
            password=info.password,
        )
        conn.execute(f"SET statement_timeout = {statement_timeout_ms}")
        conn.commit()
        conns.append(conn)
        return conn

    yield _connect

    for conn in conns:
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass


def require_pgvector():
    """Skip the calling fixture or test when the server cannot install pgvector."""
    with psycopg.connect(DATABASE_URL) as conn:
        row = conn.execute(
            "SELECT 1 FROM pg_available_extensions WHERE name = 'vector'"
        ).fetchone()
    if row is None:
        pytest.skip("pgvector is not available on this server")


def assert_global_row_delete_protected(db_connection, schema, table, *, seed=None):
    """A forged 'global' tenant context cannot delete a module's global row(s).

    Every module that seeds a namespace='global' row write-protects it with a
    RESTRICTIVE policy pair. Postgres consults only USING on DELETE, so the
    delete half is the load-bearing one; this drives it as a non-bypass role.
    Lives here so each module's suite asserts it against its own installed
    schema without the check drifting per copy.
    """
    if seed:
        db_connection.execute(seed)
    ensure_rls_role(db_connection, schema)
    conn = connect_as_rls_user(db_connection, schema)
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT set_config('{schema}.tenant_id', 'global', true)")
        cur.execute(f"DELETE FROM {table} WHERE namespace = 'global'")
        deleted = cur.rowcount
        conn.rollback()

        cur.execute(f"SELECT count(*) FROM {table} WHERE namespace = 'global'")
        assert deleted == 0
        assert cur.fetchone()[0] >= 1
    finally:
        conn.close()


def make_namespace(request) -> str:
    """Generate a unique namespace from test name.

    Used by all module conftest files for per-test namespace isolation.
    """
    namespace = request.node.name.replace("[", "_").replace("]", "_").replace("-", "_")
    return "t_" + namespace.lower()[:50]


def channel_name(cursor, schema: str, namespace: str, name: str) -> str:
    """Resolve a module's NOTIFY channel through its SQL contract."""
    cursor.execute(f"SELECT {schema}.channel_name(%s, %s)", (namespace, name))
    return cursor.fetchone()[0]


def fetch_row(cursor) -> dict | None:
    """Convert the current cursor result row to a dict, or None if no row.

    Replaces the repeated fetchone-to-dict pattern in test helpers.
    """
    row = cursor.fetchone()
    if row is None:
        return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


# Characters every name field must reject. NUL is missing because Postgres
# text values cannot contain it, so it cannot be tested.
CONTROL_CHARS = {
    "tab": chr(9),
    "lf": chr(10),
    "cr": chr(13),
    "u0085_nel": chr(0x85),
    "u2028_ls": chr(0x2028),
    "u2029_ps": chr(0x2029),
}

# Non-breaking space (U+00A0) is Unicode whitespace but not a control
# character, so names may contain it; the rules only reject characters that
# could forge log lines.
VALID_NAMESPACES = [
    "default",
    "tenant_123",
    "org:my-org",
    "MyOrg",
    "a" * 1024,
    "org" + chr(0xA0) + "eu",
]

ACCEPTED_NAMES = [
    "sensor:eu:42",
    "order.created",
    "team/backend",
    "café",
    "123-leading",
    "has space",
    "mid" + chr(0xA0) + "nbsp",
]


def name_error_cases(prefix: str) -> list:
    """Reject cases for one name field, keyed by its error-code prefix: every
    CONTROL_CHARS character, leading/trailing whitespace, and whitespace-only
    input (which counts as empty rather than whitespace)."""
    return [
        pytest.param("bad" + char + "name", f"{prefix}_INVALID_CHARS", id=name)
        for name, char in CONTROL_CHARS.items()
    ] + [
        pytest.param(" leading", f"{prefix}_WHITESPACE", id="leading_whitespace"),
        pytest.param("trailing ", f"{prefix}_WHITESPACE", id="trailing_whitespace"),
        pytest.param("   ", f"{prefix}_EMPTY", id="whitespace_only"),
    ]


NAMESPACE_ERROR_CASES = [
    pytest.param(None, "VAL_NAMESPACE_NULL", id="null"),
    pytest.param("", "VAL_NAMESPACE_EMPTY", id="empty"),
    pytest.param("a" * 1025, "VAL_NAMESPACE_TOO_LONG", id="too_long"),
] + name_error_cases("VAL_NAMESPACE")


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
