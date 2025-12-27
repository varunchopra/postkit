"""
Permission hierarchy tests for postkit/authz.

Tests for:
- Adding/removing hierarchy rules
- Hierarchy chains (admin -> write -> read)
- Dynamic hierarchy modifications with existing data
- Hierarchy rule cleanup
- Cycle detection
- Explain functionality
"""

import pytest
from authz_sdk import AuthzError


class TestHierarchyModification:
    """Test hierarchy changes with existing data."""

    def test_adding_hierarchy_expands_existing_permissions(self, authz):
        """Adding hierarchy rule retroactively expands permissions."""
        # Grant admin WITHOUT hierarchy
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # No read access yet
        assert not authz.check("alice", "read", ("doc", "1"))

        # Add hierarchy rule
        authz.add_hierarchy_rule("doc", "admin", "read")

        # Now alice should have read (hierarchy trigger handles this)
        assert authz.check("alice", "read", ("doc", "1"))

    def test_removing_hierarchy_contracts_permissions(self, authz):
        """Removing hierarchy rule retroactively removes implied permissions."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check("alice", "read", ("doc", "1"))

        # Remove the write->read implication
        authz.remove_hierarchy_rule("doc", "write", "read")

        # alice still has admin and write, but not read
        assert authz.check("alice", "admin", ("doc", "1"))
        assert authz.check("alice", "write", ("doc", "1"))
        assert not authz.check("alice", "read", ("doc", "1"))

    def test_hierarchy_change_affects_multiple_resources(self, authz):
        """Hierarchy change recomputes all affected resources."""
        # Setup: 20 docs, all with admin grants
        for i in range(20):
            authz.grant("admin", resource=("doc", str(i)), subject=("user", "alice"))

        # Verify no read access yet
        for i in range(20):
            assert not authz.check("alice", "read", ("doc", str(i)))

        # Add hierarchy
        authz.add_hierarchy_rule("doc", "admin", "read")

        # All 20 should now have read
        for i in range(20):
            assert authz.check("alice", "read", ("doc", str(i)))

    def test_hierarchy_chain_modification(self, authz):
        """Modifying middle of hierarchy chain updates correctly."""
        # admin -> write -> read
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # alice has all three
        assert authz.check("alice", "admin", ("doc", "1"))
        assert authz.check("alice", "write", ("doc", "1"))
        assert authz.check("alice", "read", ("doc", "1"))

        # Remove admin->write (breaks the chain)
        authz.remove_hierarchy_rule("doc", "admin", "write")

        # Now alice has admin but NOT write or read
        assert authz.check("alice", "admin", ("doc", "1"))
        assert not authz.check("alice", "write", ("doc", "1"))
        assert not authz.check("alice", "read", ("doc", "1"))

    def test_clear_hierarchy_removes_all_rules(self, authz):
        """clear_hierarchy removes all rules for a resource type."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check("alice", "read", ("doc", "1"))

        authz.clear_hierarchy("doc")

        # Only admin remains, implied permissions gone
        assert authz.check("alice", "admin", ("doc", "1"))
        assert not authz.check("alice", "write", ("doc", "1"))
        assert not authz.check("alice", "read", ("doc", "1"))


class TestHierarchyCycle:
    """Hierarchy cycle prevention."""

    def test_direct_cycle_rejected(self, authz):
        """admin -> admin should be rejected."""
        with pytest.raises(AuthzError, match="cycle"):
            authz.add_hierarchy_rule("doc", "admin", "admin")

    def test_indirect_cycle_rejected(self, authz):
        """admin -> write -> admin should be rejected."""
        authz.set_hierarchy("doc", "admin", "write")
        with pytest.raises(AuthzError, match="cycle"):
            authz.add_hierarchy_rule("doc", "write", "admin")

    def test_branching_cycle_rejected(self, authz):
        """admin -> write, admin -> read, read -> admin should be rejected."""
        authz.add_hierarchy_rule("doc", "admin", "write")
        authz.add_hierarchy_rule("doc", "admin", "read")
        with pytest.raises(AuthzError, match="cycle"):
            authz.add_hierarchy_rule("doc", "read", "admin")


class TestHierarchyEdgeCases:
    """Edge cases in permission hierarchies."""

    def test_deep_hierarchy_chain(self, authz):
        """Long hierarchy chain works correctly."""
        levels = [f"level{i}" for i in range(1, 11)]
        for i in range(len(levels) - 1):
            authz.add_hierarchy_rule("doc", levels[i], levels[i + 1])

        authz.grant(levels[0], resource=("doc", "1"), subject=("user", "alice"))

        for level in levels:
            assert authz.check("alice", level, ("doc", "1"))

    def test_wide_hierarchy_branches(self, authz):
        """Permission implying many others."""
        implied = ["read", "write", "delete", "share", "comment"]
        for perm in implied:
            authz.add_hierarchy_rule("doc", "admin", perm)

        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        for perm in ["admin"] + implied:
            assert authz.check("alice", perm, ("doc", "1"))


class TestExplainEdgeCases:
    """Edge cases in explain functionality."""

    def test_explain_multiple_paths(self, authz):
        """explain() returns all paths when multiple exist."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        explanations = authz.explain("alice", "read", ("doc", "1"))

        assert len(explanations) == 2
        assert any("DIRECT" in e for e in explanations)
        assert any("GROUP" in e for e in explanations)

    def test_explain_deep_hierarchy(self, authz):
        """explain() shows full hierarchy chain."""
        authz.set_hierarchy("doc", "owner", "admin", "write", "read")
        authz.grant("owner", resource=("doc", "1"), subject=("user", "alice"))

        explanations = authz.explain("alice", "read", ("doc", "1"))

        assert any("owner -> admin -> write -> read" in e for e in explanations)
