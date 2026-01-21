"""Row-Level Security tests.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly.
"""

import psycopg
import pytest
from postkit.authz import AuthzClient, AuthzError


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
        AuthzClient(cursor, "tenant-b")

        # tenant-b's SDK sets tenant context to tenant-b
        # Direct query for tenant-a namespace returns nothing
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert cursor.fetchall() == []

        # Non-superuser as tenant-a CAN see tenant-a's data
        AuthzClient(cursor, "tenant-a")
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection, cleanup_tenant_a):
        """Cannot write to different namespace than tenant context."""
        cursor = rls_connection.cursor()

        # Set tenant context to tenant-a
        AuthzClient(cursor, "tenant-a")

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
        assert tenant_a.check(("user", "alice"), "read", ("doc", "rls-2")) is True

        # As tenant-b, cannot see tenant-a's permission
        tenant_b = AuthzClient(cursor, "tenant-b")
        assert tenant_b.check(("user", "alice"), "read", ("doc", "rls-2")) is False

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
        AuthzClient(cursor, "tenant-a")

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
        AuthzClient(cursor, "tenant-b")

        # Superuser can still see tenant-a data (bypasses RLS)
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert len(cursor.fetchall()) >= 1

        # Cleanup
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'tenant-a'"
        )
        db_connection.execute("DELETE FROM authz.tuples WHERE namespace = 'tenant-a'")

    def test_clear_tenant(self, rls_connection, db_connection, cleanup_tenant_a):
        """clear_tenant() removes tenant context."""
        # Setup: create data as superuser
        superuser_cursor = db_connection.cursor()
        tenant_a_admin = AuthzClient(superuser_cursor, "tenant-a")
        tenant_a_admin.grant(
            "read", resource=("doc", "rls-clear"), subject=("user", "alice")
        )

        cursor = rls_connection.cursor()

        # Set tenant context
        cursor.execute("SELECT authz.set_tenant('tenant-a')")
        cursor.execute("SELECT current_setting('authz.tenant_id', true)")
        assert cursor.fetchone()[0] == "tenant-a"

        # Can see data
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert len(cursor.fetchall()) >= 1

        # Clear tenant context
        cursor.execute("SELECT authz.clear_tenant()")
        cursor.execute("SELECT current_setting('authz.tenant_id', true)")
        assert cursor.fetchone()[0] == ""

        # No longer see data (RLS filters out)
        cursor.execute("SELECT * FROM authz.tuples WHERE namespace = 'tenant-a'")
        assert cursor.fetchall() == []

    def test_recipient_can_leave_cross_org_share(self, rls_connection, db_connection):
        """Recipients can delete/leave shares where they are the subject."""
        # Org A (superuser) shares a doc with alice
        superuser_cursor = db_connection.cursor()
        org_a = AuthzClient(superuser_cursor, "org-a")
        org_a.grant("read", resource=("doc", "shared-1"), subject=("user", "alice"))

        # Verify share exists
        superuser_cursor.execute(
            "SELECT * FROM authz.tuples WHERE namespace = 'org-a' AND resource_id = 'shared-1'"
        )
        assert len(superuser_cursor.fetchall()) == 1

        # Alice (in org-b) connects as non-superuser
        cursor = rls_connection.cursor()

        # Set tenant to org-b (alice's org, different from where share exists)
        org_b = AuthzClient(cursor, "org-b")

        # Set alice's viewer context (required for recipient policies)
        org_b.set_viewer(("user", "alice"))

        # Alice can SEE the share (recipient_visibility policy)
        cursor.execute(
            """
            SELECT * FROM authz.tuples
            WHERE subject_type = 'user' AND subject_id = 'alice'
            AND namespace = 'org-a'
            """
        )
        shares = cursor.fetchall()
        assert len(shares) == 1

        # Alice can DELETE/LEAVE the share (recipient_can_leave policy)
        cursor.execute(
            """
            DELETE FROM authz.tuples
            WHERE namespace = 'org-a'
            AND resource_type = 'doc' AND resource_id = 'shared-1'
            AND subject_type = 'user' AND subject_id = 'alice'
            """
        )

        # Verify share is gone
        superuser_cursor.execute(
            "SELECT * FROM authz.tuples WHERE namespace = 'org-a' AND resource_id = 'shared-1'"
        )
        assert len(superuser_cursor.fetchall()) == 0

        # Cleanup
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'org-a'"
        )

    def test_recipient_cannot_delete_others_shares(self, rls_connection, db_connection):
        """Recipients can only delete shares where THEY are the subject."""
        # Org A shares a doc with bob (not alice)
        superuser_cursor = db_connection.cursor()
        org_a = AuthzClient(superuser_cursor, "org-a")
        org_a.grant("read", resource=("doc", "bobs-share"), subject=("user", "bob"))

        # Alice tries to delete bob's share
        cursor = rls_connection.cursor()
        org_b = AuthzClient(cursor, "org-b")
        org_b.set_viewer(("user", "alice"))

        # Alice cannot see bob's share (recipient_visibility only shows YOUR shares)
        cursor.execute(
            """
            SELECT * FROM authz.tuples
            WHERE namespace = 'org-a' AND resource_id = 'bobs-share'
            """
        )
        assert len(cursor.fetchall()) == 0

        # Alice cannot delete bob's share (even with direct DELETE)
        cursor.execute(
            """
            DELETE FROM authz.tuples
            WHERE namespace = 'org-a' AND resource_id = 'bobs-share'
            """
        )
        # Should delete 0 rows (RLS filters it out)

        # Verify bob's share still exists
        superuser_cursor.execute(
            "SELECT * FROM authz.tuples WHERE namespace = 'org-a' AND resource_id = 'bobs-share'"
        )
        assert len(superuser_cursor.fetchall()) == 1

        # Cleanup
        db_connection.execute("DELETE FROM authz.tuples WHERE namespace = 'org-a'")
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'org-a'"
        )

    def test_cannot_write_to_global_hierarchy(self, rls_connection):
        """Non-superusers cannot write to global permission_hierarchy.

        The hierarchy_global_write_protection RESTRICTIVE policy blocks all
        writes to namespace='global', even if a tenant sets their context to 'global'.
        """
        cursor = rls_connection.cursor()

        # Create client targeting 'global' namespace
        global_authz = AuthzClient(cursor, "global")

        # Should be blocked by hierarchy_global_write_protection policy
        with pytest.raises(AuthzError, match="hierarchy_global_write_protection"):
            global_authz.add_hierarchy_rule("doc", "admin", "read")

    def test_audit_events_fail_closed(self, rls_connection, db_connection):
        """Audit events are not visible when tenant context is not set (fail-closed)."""
        # Create audit event via superuser
        superuser_cursor = db_connection.cursor()
        tenant_a = AuthzClient(superuser_cursor, "tenant-a")
        tenant_a.grant(
            "read", resource=("doc", "audit-fail-closed"), subject=("user", "alice")
        )

        # Non-superuser with cleared tenant context should see nothing
        cursor = rls_connection.cursor()
        cursor.execute("SELECT authz.clear_tenant()")
        cursor.execute("SELECT * FROM authz.audit_events")
        assert cursor.fetchall() == []

        # Cleanup
        db_connection.execute(
            "DELETE FROM authz.audit_events WHERE namespace = 'tenant-a'"
        )
        db_connection.execute("DELETE FROM authz.tuples WHERE namespace = 'tenant-a'")
