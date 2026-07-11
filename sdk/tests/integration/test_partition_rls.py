"""Every partition of an RLS-forced table must itself enable and force RLS.

Postgres does not propagate RLS to partitions, so a partition shipped bare
is a tenant-isolation bypass. The test_rls.py module tests prove the
behavior for one partition each; this proves coverage across all of them.
"""

from pathlib import Path

import pytest

POSTKIT_SCHEMAS = [
    "authn",
    "authz",
    "config",
    "lease",
    "meter",
    "outbox",
    "presence",
    "queue",
]

# A new partitioned RLS table fails the equality below until listed here,
# which puts its partitions under the same check.
EXPECTED_PARENTS = {
    ("authn", "audit_events"),
    ("authz", "audit_events"),
    ("config", "audit_events"),
    ("meter", "ledger"),
}


@pytest.fixture(scope="module")
def partition_connection(db_connection):
    """Session connection (authn, authz, config) plus every remaining module
    schema, so catalog discovery sees all of POSTKIT_SCHEMAS.

    A schema another suite in this run already installed (e.g. presence and
    queue from test_presence_hooks.py) is reused rather than reinstalled;
    dropping it mid-session would break that suite's connections.
    """
    dist_dir = Path(__file__).parent.parent.parent.parent / "dist"
    installed = []
    for schema in ("lease", "meter", "outbox", "presence", "queue"):
        row = db_connection.execute(
            "SELECT 1 FROM pg_namespace WHERE nspname = %s", (schema,)
        ).fetchone()
        if row:
            continue
        sql_file = dist_dir / f"{schema}.sql"
        if not sql_file.exists():
            pytest.fail(f"dist/{schema}.sql not found. Run 'make build' first.")
        db_connection.execute(sql_file.read_text())
        installed.append(schema)

    yield db_connection

    for schema in installed:
        db_connection.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")


def test_every_partition_enforces_rls(partition_connection):
    cursor = partition_connection.cursor()

    cursor.execute(
        """
        SELECT n.nspname, c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'p'
          AND c.relrowsecurity
          AND c.relforcerowsecurity
          AND n.nspname = ANY(%s)
        """,
        (POSTKIT_SCHEMAS,),
    )
    parents = set(cursor.fetchall())
    assert parents == EXPECTED_PARENTS

    for schema, parent in sorted(EXPECTED_PARENTS):
        cursor.execute(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            JOIN pg_namespace n ON n.oid = p.relnamespace
            WHERE n.nspname = %s AND p.relname = %s
            """,
            (schema, parent),
        )
        partitions = cursor.fetchall()
        assert partitions, f"{schema}.{parent} has no partitions to check"

        unprotected = [
            name for name, enabled, forced in partitions if not (enabled and forced)
        ]
        assert unprotected == [], (
            f"partitions of {schema}.{parent} without enforced RLS: {unprotected}"
        )
