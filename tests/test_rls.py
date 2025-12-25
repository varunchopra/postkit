"""Row-Level Security tests.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly.
"""

import pytest
import psycopg

from sdk import AuthzClient


class TestRowLevelSecurity:
    """Verify RLS enforces tenant isolation."""

    @pytest.fixture
    def rls_connection(self, db_connection):
        """Create a non-superuser role for RLS testing."""
        # Create role if not exists (superuser connection)
        db_connection.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rls_test_user') THEN
                    CREATE ROLE rls_test_user LOGIN PASSWORD 'rls_test_pass';
                END IF;
            END $$;
        """
        )
        db_connection.execute("GRANT USAGE ON SCHEMA authz TO rls_test_user")
        db_connection.execute(
            "GRANT ALL ON ALL TABLES IN SCHEMA authz TO rls_test_user"
        )
        db_connection.execute(
            "GRANT ALL ON ALL SEQUENCES IN SCHEMA authz TO rls_test_user"
        )
        db_connection.execute(
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO rls_test_user"
        )

        # Connect as the non-superuser (use same host/port as db_connection)
        info = db_connection.info
        conn = psycopg.connect(
            host=info.host,
            port=info.port,
            dbname=info.dbname,
            user="rls_test_user",
            password="rls_test_pass",
            autocommit=True,
        )

        yield conn

        conn.close()

    @pytest.fixture
    def cleanup_tenant_a(self, db_connection):
        """Cleanup tenant-a data after test."""
        yield
        # Superuser cleanup (bypasses RLS)
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'tenant-a'"
        )
        db_connection.execute("DELETE FROM authz.tuples WHERE namespace = 'tenant-a'")
        db_connection.execute("DELETE FROM authz.computed WHERE namespace = 'tenant-a'")

    def test_no_tenant_returns_empty(self, rls_connection):
        """Without tenant context, queries return nothing."""
        cursor = rls_connection.cursor()

        # Clear tenant context
        cursor.execute("RESET authz.tenant_id")

        # Direct table query returns nothing without tenant context
        cursor.execute("SELECT * FROM authz.tuples")
        assert cursor.fetchall() == []

    def test_tenant_isolation_read(
        self, rls_connection, db_connection, cleanup_tenant_a
    ):
        """Tenants cannot see each other's data."""
        # Superuser creates data in tenant-a (bypasses RLS for setup)
        superuser_cursor = db_connection.cursor()
        tenant_a_admin = AuthzClient(superuser_cursor, "tenant-a")
        tenant_a_admin.grant(
            "read", resource=("doc", "rls-1"), subject=("user", "alice")
        )

        # Non-superuser as tenant-b cannot see tenant-a's data
        cursor = rls_connection.cursor()
        tenant_b = AuthzClient(cursor, "tenant-b")

        # tenant-b's SDK sets tenant context to tenant-b
        # Direct query for tenant-a namespace returns nothing
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert cursor.fetchall() == []

        # Non-superuser as tenant-a CAN see tenant-a's data
        tenant_a = AuthzClient(cursor, "tenant-a")
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection, cleanup_tenant_a):
        """Cannot write to different namespace than tenant context."""
        cursor = rls_connection.cursor()

        # Set tenant context to tenant-a
        tenant_a = AuthzClient(cursor, "tenant-a")

        # Try to write to tenant-b namespace directly - should fail with RLS violation
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cursor.execute(
                """
                INSERT INTO authz.tuples
                    (namespace, resource_type, resource_id, relation, subject_type, subject_id)
                VALUES
                    ('tenant-b', 'doc', '1', 'read', 'user', 'alice')
            """
            )

    def test_tenant_isolation_check(
        self, rls_connection, db_connection, cleanup_tenant_a
    ):
        """check() respects tenant isolation."""
        # Superuser creates permission in tenant-a
        superuser_cursor = db_connection.cursor()
        tenant_a_admin = AuthzClient(superuser_cursor, "tenant-a")
        tenant_a_admin.grant(
            "read", resource=("doc", "rls-2"), subject=("user", "alice")
        )

        cursor = rls_connection.cursor()

        # As tenant-a, can verify permission
        tenant_a = AuthzClient(cursor, "tenant-a")
        assert tenant_a.check("alice", "read", ("doc", "rls-2")) is True

        # As tenant-b, cannot see tenant-a's permission
        tenant_b = AuthzClient(cursor, "tenant-b")
        assert tenant_b.check("alice", "read", ("doc", "rls-2")) is False

    def test_tenant_isolation_audit(
        self, rls_connection, db_connection, cleanup_tenant_a
    ):
        """Audit events respect tenant isolation."""
        # Superuser creates data in tenant-a (generates audit event)
        superuser_cursor = db_connection.cursor()
        tenant_a_admin = AuthzClient(superuser_cursor, "tenant-a")
        tenant_a_admin.grant(
            "read", resource=("doc", "rls-3"), subject=("user", "alice")
        )

        cursor = rls_connection.cursor()

        # As tenant-a, can see audit events
        tenant_a = AuthzClient(cursor, "tenant-a")
        events = tenant_a.get_audit_events()
        assert len(events) >= 1

        # As tenant-b, cannot see tenant-a's audit events
        tenant_b = AuthzClient(cursor, "tenant-b")
        events = tenant_b.get_audit_events()
        # Filter to tenant-a events (should be none visible)
        cursor.execute("SELECT * FROM authz.audit_events WHERE namespace = 'tenant-a'")
        assert cursor.fetchall() == []

    def test_set_tenant_persists_across_transactions(self, rls_connection):
        """Tenant context is session-level."""
        cursor = rls_connection.cursor()

        # SDK sets tenant in __init__
        tenant_a = AuthzClient(cursor, "tenant-a")

        cursor.execute("SELECT current_setting('authz.tenant_id', true)")
        assert cursor.fetchone()[0] == "tenant-a"

        # Commit doesn't affect session-level setting
        rls_connection.commit()

        cursor.execute("SELECT current_setting('authz.tenant_id', true)")
        assert cursor.fetchone()[0] == "tenant-a"

    def test_superuser_bypasses_rls(self, db_connection):
        """Superusers can see all data regardless of tenant context."""
        cursor = db_connection.cursor()

        # Create data as tenant-a
        tenant_a = AuthzClient(cursor, "tenant-a")
        tenant_a.grant("read", resource=("doc", "rls-4"), subject=("user", "alice"))

        # Switch to tenant-b context
        tenant_b = AuthzClient(cursor, "tenant-b")

        # Superuser can still see tenant-a data (bypasses RLS)
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert len(cursor.fetchall()) >= 1

        # Cleanup
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'tenant-a'"
        )
        db_connection.execute("DELETE FROM authz.tuples WHERE namespace = 'tenant-a'")
        db_connection.execute("DELETE FROM authz.computed WHERE namespace = 'tenant-a'")
