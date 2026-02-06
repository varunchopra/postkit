"""
Consistency and statistics tests for postkit/authz.

These tests verify data integrity checks and statistics functions.
"""


class TestStatistics:
    """Test the stats monitoring function."""

    def test_empty_namespace_returns_zeros(self, authz):
        """Empty namespace returns all zeros."""
        stats = authz.get_stats()
        assert stats["tuple_count"] == 0
        assert stats["hierarchy_rule_count"] == 0
        assert stats["unique_users"] == 0
        assert stats["unique_resources"] == 0

    def test_stats_reflect_tuples(self, authz):
        """Stats accurately reflect tuple counts."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "2"), subject=("user", "bob"))

        stats = authz.get_stats()
        assert stats["tuple_count"] == 2
        assert stats["hierarchy_rule_count"] == 0
        assert stats["unique_users"] == 2
        assert stats["unique_resources"] == 2

    def test_stats_with_hierarchy(self, authz):
        """Stats track hierarchy rules."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        stats = authz.get_stats()
        assert stats["tuple_count"] == 1
        assert stats["hierarchy_rule_count"] == 2  # admin->write, write->read
        assert stats["unique_users"] == 1
        assert stats["unique_resources"] == 1

    def test_stats_with_groups(self, authz):
        """Stats reflect group membership counts."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        stats = authz.get_stats()
        assert stats["tuple_count"] == 3
        assert stats["hierarchy_rule_count"] == 0
        assert stats["unique_users"] == 2
        assert stats["unique_resources"] == 2  # team:eng and doc:1


class TestVerifyIntegrity:
    """Verify function checks for data integrity issues like cycles."""

    def test_verify_with_hierarchy_and_groups(self, authz):
        """verify() handles combined hierarchy + group expansion without false positives."""
        authz.set_hierarchy("doc", "admin", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        assert authz.verify() == []

    def test_verify_detects_audit_partition_issues(self, authz, db_connection):
        """verify() detects audit events stuck in default partition."""
        cursor = db_connection.cursor()
        # Insert with event_time far outside any partition range.
        cursor.execute(
            """
            INSERT INTO authz.audit_events
                (namespace, resource_type, resource_id, relation,
                 subject_type, subject_id, event_type, event_time)
            VALUES (%s, 'doc', 'test', 'read', 'user', 'alice',
                    'tuple_created', '2099-01-15T00:00:00Z')
            """,
            (authz.namespace,),
        )

        issues = authz.verify()

        # verify_integrity checks audit_events_default globally (not per-namespace).
        partition_issues = [i for i in issues if i["resource_id"] == "audit_partitions"]
        assert len(partition_issues) == 1
        assert partition_issues[0]["status"] == "error"
        assert "default partition" in partition_issues[0]["details"]


class TestGraphResolution:
    """Test that complex graph topologies resolve correctly."""

    def test_diamond_hierarchy_works(self, authz):
        """Diamond hierarchy pattern produces correct results."""
        # admin -> write -> view
        # admin -> read -> view
        authz.set_hierarchy("doc", "admin", "write")
        authz.add_hierarchy_rule("doc", "admin", "read")
        authz.add_hierarchy_rule("doc", "write", "view")
        authz.add_hierarchy_rule("doc", "read", "view")

        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # view is implied by both write and read
        assert authz.check(("user", "alice"), "view", ("doc", "1"))
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
