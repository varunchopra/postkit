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
        assert stats["unique_users"] == 2
        assert stats["unique_resources"] == 2

    def test_stats_with_hierarchy(self, authz):
        """Stats track hierarchy rules."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        stats = authz.get_stats()
        assert stats["tuple_count"] == 1
        assert stats["hierarchy_rule_count"] == 2  # admin->write, write->read

    def test_stats_with_groups(self, authz):
        """Stats reflect group membership counts."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        stats = authz.get_stats()
        assert stats["tuple_count"] == 3
        assert stats["unique_users"] == 2
        assert stats["unique_resources"] == 2  # team:eng and doc:1


class TestVerifyIntegrity:
    """Verify function checks for data integrity issues like cycles."""

    def test_verify_clean_state_returns_empty(self, authz):
        """verify() returns nothing when data is correct."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        assert authz.verify() == []

    def test_verify_with_hierarchy(self, authz):
        """verify() correctly handles hierarchy-expanded permissions."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))
        assert authz.verify() == []

    def test_verify_with_groups(self, authz):
        """verify() correctly handles group-expanded permissions."""
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        assert authz.verify() == []

    def test_verify_with_hierarchy_and_groups(self, authz):
        """verify() handles combined hierarchy + group expansion."""
        authz.set_hierarchy("doc", "admin", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        assert authz.verify() == []


class TestLazyEvaluationCorrectness:
    """Test that lazy evaluation produces correct results."""

    def test_user_in_many_groups_works(self, authz):
        """User in multiple groups gets permissions from all."""
        for team in ["team-a", "team-b", "team-c"]:
            authz.grant("read", resource=("doc", "1"), subject=("team", team))
            authz.grant("member", resource=("team", team), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_direct_and_group_both_work(self, authz):
        """User with direct grant and group membership has access."""
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

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
