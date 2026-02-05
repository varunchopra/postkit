"""Row-Level Security tests for the config module.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly, including
tenant context recovery after commits and in autocommit mode.
"""

import psycopg
import pytest
from postkit.config import ConfigClient

from tests.config.helpers import cleanup_namespace
from tests.helpers import connect_as_rls_user, ensure_rls_role


class TestConfigRowLevelSecurity:
    """Verify RLS enforces tenant isolation for config tables."""

    @pytest.fixture
    def rls_connection(self, db_connection):
        """Non-superuser connection for RLS testing.

        Uses autocommit=False because tenant context is transaction-local.
        """
        ensure_rls_role(db_connection, "config")
        conn = connect_as_rls_user(db_connection, "config", autocommit=False)
        yield conn
        conn.close()

    @pytest.fixture(autouse=True)
    def cleanup(self, db_connection):
        """Remove test data after each test via superuser (bypasses RLS)."""
        yield
        cursor = db_connection.cursor()
        for ns in ("rls_a", "rls_b", "rls_commit", "rls_autocommit"):
            cleanup_namespace(cursor, ns)

    # =========================================================================
    # Core RLS Tests
    # =========================================================================

    def test_no_tenant_returns_empty(self, rls_connection):
        """Without tenant context, queries return nothing (fail-closed)."""
        cursor = rls_connection.cursor()
        cursor.execute("RESET config.tenant_id")

        cursor.execute("SELECT * FROM config.entries")
        assert cursor.fetchall() == []

    def test_tenant_isolation_read(self, rls_connection, db_connection):
        """Tenant A's data is invisible to tenant B."""
        # Superuser creates entry in rls_a.
        su = db_connection.cursor()
        tenant_a = ConfigClient(su, "rls_a")
        tenant_a.set("app/setting", {"value": "a"})

        # Non-superuser as rls_b cannot see rls_a's entries.
        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM config.entries WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

        # Non-superuser as rls_a CAN see rls_a's entries.
        ConfigClient(cursor, "rls_a")
        cursor.execute("SELECT * FROM config.entries WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection):
        """Cannot write to a different namespace than tenant context."""
        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_a")

        # Direct INSERT into rls_b namespace is blocked by RLS.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cursor.execute(
                """
                INSERT INTO config.entries (namespace, key, value, version, is_active)
                VALUES ('rls_b', 'app/setting', '{}', 1, true)
                """
            )

    def test_context_survives_commit(self, rls_connection):
        """SDK operations work after an explicit commit.

        This is the core regression test. Before the fix, set_tenant was
        called once in __init__ with is_local=true. After commit, the
        transaction-local setting was gone and subsequent operations saw
        an empty tenant_id, causing RLS to silently block everything.
        """
        cursor = rls_connection.cursor()
        config = ConfigClient(cursor, "rls_commit")

        # First operation within the __init__ transaction.
        config.set("app/setting", {"value": 1})

        rls_connection.commit()

        # After commit, tenant context is gone at the PostgreSQL level.
        # The SDK must re-apply it for subsequent operations.
        value = config.get_value("app/setting")
        assert value is not None
        assert value["value"] == 1

    def test_autocommit_mode(self, db_connection):
        """Each autocommit statement is its own transaction — context must be re-applied.

        In autocommit mode, __init__'s set_tenant call commits immediately.
        Every subsequent SDK call starts a fresh transaction with no tenant
        context. The SDK must re-apply tenant context per operation.
        """
        ensure_rls_role(db_connection, "config")
        conn = connect_as_rls_user(db_connection, "config", autocommit=True)
        try:
            cursor = conn.cursor()
            config = ConfigClient(cursor, "rls_autocommit")

            # set runs in a separate implicit transaction from __init__.
            config.set("app/setting", {"value": 1})

            # Read operations also work.
            value = config.get_value("app/setting")
            assert value is not None
        finally:
            conn.close()

    def test_set_tenant_clears_on_commit(self, rls_connection):
        """Tenant context is transaction-local and clears on commit.

        This is a safety property: is_local=true prevents cross-tenant
        leakage when connections are returned to a pool without cleanup.
        """
        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_a")

        cursor.execute("SELECT current_setting('config.tenant_id', true)")
        assert cursor.fetchone()[0] == "rls_a"

        rls_connection.commit()

        # After commit, the transaction-local setting is gone.
        cursor.execute("SELECT current_setting('config.tenant_id', true)")
        assert cursor.fetchone()[0] == ""

    def test_superuser_bypasses_rls(self, db_connection):
        """Superusers can see all data regardless of tenant context."""
        cursor = db_connection.cursor()

        ConfigClient(cursor, "rls_a").set("app/setting", {"owner": "a"})

        # Switch to rls_b context — superuser still sees rls_a data.
        ConfigClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM config.entries WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) >= 1

    # =========================================================================
    # Table-Specific RLS Tests
    # =========================================================================

    def test_entries_rls(self, rls_connection, db_connection):
        """Entries table respects RLS."""
        su = db_connection.cursor()
        tenant_a = ConfigClient(su, "rls_a")
        tenant_a.set("app/key1", {"v": 1})
        tenant_a.set("app/key2", {"v": 2})

        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM config.entries WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_version_counters_rls(self, rls_connection, db_connection):
        """Version counters table respects RLS."""
        su = db_connection.cursor()
        tenant_a = ConfigClient(su, "rls_a")
        tenant_a.set("app/setting", {"v": 1})  # Creates version counter

        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_b")
        cursor.execute(
            "SELECT * FROM config.version_counters WHERE namespace = 'rls_a'"
        )
        assert cursor.fetchall() == []

    def test_schemas_read_all(self, rls_connection, db_connection):
        """Schemas table has read-all policy — all tenants can read schemas.

        Note: schemas_read_all policy uses USING (true) for SELECT only.
        There are no INSERT/UPDATE/DELETE policies, so writes are blocked.
        """
        # Create a schema as superuser (schemas are typically created by admins)
        su = db_connection.cursor()
        su.execute(
            """
            INSERT INTO config.schemas (key_pattern, schema, description)
            VALUES ('test_rls/**', '{"type": "object"}', 'Test schema')
            ON CONFLICT (key_pattern) DO NOTHING
            """
        )

        # Non-superuser can read schemas regardless of tenant context
        cursor = rls_connection.cursor()
        ConfigClient(cursor, "rls_b")  # Different tenant
        cursor.execute("SELECT * FROM config.schemas WHERE key_pattern = 'test_rls/**'")
        result = cursor.fetchall()
        assert len(result) == 1  # Can read even though different tenant

        # Cleanup
        su.execute("DELETE FROM config.schemas WHERE key_pattern = 'test_rls/**'")
