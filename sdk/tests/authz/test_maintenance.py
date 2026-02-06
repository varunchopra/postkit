"""
Maintenance and operational tests for postkit/authz.

With lazy evaluation, there is no computed table. These tests verify
that the system works correctly under various operational conditions.
"""

import os

import psycopg

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/postgres"
)


class TestVacuumBehavior:
    """Test that VACUUM doesn't break authorization."""

    def test_vacuum_preserves_permissions(self, authz):
        """VACUUM should not affect permissions."""
        # Setup permissions
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("admin", resource=("doc", "1"), subject=("team", "eng"))

        # Verify initial state
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Run VACUUM
        conn = psycopg.connect(DATABASE_URL, autocommit=True)
        try:
            cursor = conn.cursor()
            cursor.execute("VACUUM authz.tuples")
            cursor.execute("VACUUM authz.permission_hierarchy")
        finally:
            conn.close()

        # Permissions should still work
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_vacuum_full_preserves_permissions(self, authz):
        """VACUUM FULL should not affect permissions."""
        # Setup permissions
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("write", resource=("doc", "2"), subject=("user", "bob"))

        # Verify initial state
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "bob"), "write", ("doc", "2"))

        # Run VACUUM FULL (requires exclusive lock)
        conn = psycopg.connect(DATABASE_URL, autocommit=True)
        try:
            cursor = conn.cursor()
            cursor.execute("VACUUM FULL authz.tuples")
        finally:
            conn.close()

        # Permissions should still work
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "bob"), "write", ("doc", "2"))


class TestVerifyIntegrityCycleDetection:
    """Test that verify_integrity detects cycles created via direct SQL."""

    def test_verify_detects_group_cycle(self, authz, db_connection):
        """verify() detects group membership cycles created via direct SQL."""
        cursor = db_connection.cursor()
        # Create cycle via direct SQL (bypasses SDK's cycle prevention).
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id)
            VALUES
                (%s, 'team', 'a', 'member', 'team', 'b'),
                (%s, 'team', 'b', 'member', 'team', 'a')
            """,
            (authz.namespace, authz.namespace),
        )

        issues = authz.verify()

        # A<->B cycle produces 2 issues: one starting from A (A->B->A), one from B (B->A->B).
        assert len(issues) == 2
        assert all(issue["resource_id"] == "group_cycles" for issue in issues)
        assert all(issue["status"] == "warning" for issue in issues)
        assert all("Circular group membership" in issue["details"] for issue in issues)

    def test_verify_detects_resource_cycle(self, authz, db_connection):
        """verify() detects resource hierarchy cycles created via direct SQL."""
        cursor = db_connection.cursor()
        # Create resource cycle via direct SQL (bypasses SDK's cycle prevention).
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id)
            VALUES
                (%s, 'folder', 'a', 'parent', 'folder', 'b'),
                (%s, 'folder', 'b', 'parent', 'folder', 'a')
            """,
            (authz.namespace, authz.namespace),
        )

        issues = authz.verify()

        # A<->B cycle produces 2 issues: one starting from A (A->B->A), one from B (B->A->B).
        assert len(issues) == 2
        assert all(issue["resource_id"] == "resource_cycles" for issue in issues)
        assert all(issue["status"] == "warning" for issue in issues)
        assert all(
            "Circular resource hierarchy" in issue["details"] for issue in issues
        )


class TestBulkOperations:
    """Bulk import functionality."""

    def test_bulk_grant_many_users(self, authz):
        """bulk_grant handles many users efficiently."""
        subjects = [("user", f"user-{i}") for i in range(100)]
        count = authz.bulk_grant("read", resource=("doc", "1"), subjects=subjects)
        assert count == 100

        for subject in subjects:
            assert authz.check(subject, "read", ("doc", "1"))

    def test_bulk_grant_resources(self, authz):
        """bulk_grant_resources grants to subject on many resources."""
        resource_ids = [f"doc-{i}" for i in range(50)]
        count = authz.bulk_grant_resources(
            "read",
            resource_type="doc",
            resource_ids=resource_ids,
            subject=("team", "eng"),
        )
        assert count == 50

        # Add a user to the team and verify access to all resources
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        for rid in resource_ids:
            assert authz.check(("user", "alice"), "read", ("doc", rid))

    def test_bulk_grant_resources_with_subject_relation(self, authz):
        """bulk_grant_resources supports subject_relation parameter."""
        resource_ids = ["secret-1", "secret-2", "secret-3"]
        count = authz.bulk_grant_resources(
            "admin",
            resource_type="doc",
            resource_ids=resource_ids,
            subject=("team", "security"),
            subject_relation="admin",
        )
        assert count == 3

        # Member of team should NOT have access (grant is to team#admin)
        authz.grant("member", resource=("team", "security"), subject=("user", "bob"))
        for rid in resource_ids:
            assert not authz.check(("user", "bob"), "admin", ("doc", rid))

        # Admin of team should have access
        authz.grant("admin", resource=("team", "security"), subject=("user", "carol"))
        for rid in resource_ids:
            assert authz.check(("user", "carol"), "admin", ("doc", rid))
