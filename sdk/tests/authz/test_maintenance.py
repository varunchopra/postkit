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
        assert authz.check("alice", "read", ("doc", "1"))

        # Run VACUUM
        conn = psycopg.connect(DATABASE_URL, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("VACUUM authz.tuples")
        cursor.execute("VACUUM authz.permission_hierarchy")
        conn.close()

        # Permissions should still work
        assert authz.check("alice", "read", ("doc", "1"))

    def test_vacuum_full_preserves_permissions(self, authz):
        """VACUUM FULL should not affect permissions."""
        # Setup permissions
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("write", resource=("doc", "2"), subject=("user", "bob"))

        # Verify initial state
        assert authz.check("alice", "read", ("doc", "1"))
        assert authz.check("bob", "write", ("doc", "2"))

        # Run VACUUM FULL (requires exclusive lock)
        conn = psycopg.connect(DATABASE_URL, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("VACUUM FULL authz.tuples")
        conn.close()

        # Permissions should still work
        assert authz.check("alice", "read", ("doc", "1"))
        assert authz.check("bob", "write", ("doc", "2"))


class TestVerifyRepair:
    """Test verify operations."""

    def test_verify_clean_state(self, authz):
        """verify() on clean state returns no issues."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        authz.grant("write", resource=("doc", "2"), subject=("team", "eng"))

        issues = authz.verify()
        assert len(issues) == 0


class TestBulkOperations:
    """Bulk import functionality."""

    def test_bulk_grant_many_users(self, authz):
        """bulk_grant handles many users efficiently."""
        users = [f"user-{i}" for i in range(100)]
        authz.bulk_grant("read", resource=("doc", "1"), subject_ids=users)

        for user in users:
            assert authz.check(user, "read", ("doc", "1"))

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
            assert authz.check("alice", "read", ("doc", rid))

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
            assert not authz.check("bob", "admin", ("doc", rid))

        # Admin of team should have access
        authz.grant("admin", resource=("team", "security"), subject=("user", "carol"))
        for rid in resource_ids:
            assert authz.check("carol", "admin", ("doc", rid))
