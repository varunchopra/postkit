"""
Stress tests for postkit/authz.

Tests performance and correctness under high load:
- Large groups (1000+ users)
- Many resources
- Deep hierarchy chains
- High concurrency

Note: These tests use moderate sizes that complete in reasonable time.
For true stress testing, increase the numbers and run separately.
"""

import os
import pytest
import time

from authz_sdk import AuthzClient


class TestLargeGroups:
    """Test performance with large group memberships."""

    def test_large_team_membership(self, authz):
        """Team with 1000 members should work correctly."""
        num_users = 1000

        # Add all users to team
        start = time.time()
        for i in range(num_users):
            authz.grant(
                "member", resource=("team", "large"), subject=("user", f"user-{i}")
            )
        membership_time = time.time() - start

        # Grant team access to a resource
        start = time.time()
        authz.grant("read", resource=("doc", "shared"), subject=("team", "large"))
        grant_time = time.time() - start

        # All users should have access
        for i in range(0, num_users, 100):  # Sample every 100th user
            assert authz.check(f"user-{i}", "read", ("doc", "shared"))

        # Check stats
        stats = authz.stats()
        assert stats["tuple_count"] == num_users + 1

        # Performance assertions (adjust thresholds for your environment)
        assert (
            membership_time < 30
        ), f"Adding {num_users} members took {membership_time:.2f}s"
        assert grant_time < 5, f"Granting to large team took {grant_time:.2f}s"

    def test_user_in_many_teams(self, authz):
        """User in 100 teams should work correctly."""
        num_teams = 100

        # Add user to many teams
        for i in range(num_teams):
            authz.grant(
                "member", resource=("team", f"team-{i}"), subject=("user", "alice")
            )
            authz.grant(
                "read", resource=("doc", f"doc-{i}"), subject=("team", f"team-{i}")
            )

        # User should have access to all resources
        for i in range(num_teams):
            assert authz.check("alice", "read", ("doc", f"doc-{i}"))

        # List operations should work
        resources = authz.list_resources("alice", "doc", "read")
        assert len(resources) == num_teams


class TestManyResources:
    """Test performance with many resources."""

    def test_many_direct_grants(self, authz):
        """User with 1000 direct grants should work correctly."""
        num_resources = 1000

        start = time.time()
        for i in range(num_resources):
            authz.grant("read", resource=("doc", f"doc-{i}"), subject=("user", "alice"))
        grant_time = time.time() - start

        # Spot check permissions
        assert authz.check("alice", "read", ("doc", "doc-0"))
        assert authz.check("alice", "read", ("doc", "doc-999"))
        assert not authz.check("alice", "read", ("doc", "doc-1000"))

        # Filter should work efficiently
        start = time.time()
        all_ids = [f"doc-{i}" for i in range(num_resources)]
        result = authz.filter_authorized("alice", "doc", "read", all_ids)
        filter_time = time.time() - start

        assert len(result) == num_resources
        assert (
            filter_time < 1
        ), f"Filtering {num_resources} resources took {filter_time:.2f}s"


class TestDeepHierarchy:
    """Test performance with deep permission hierarchies."""

    def test_hierarchy_depth_100(self, authz):
        """Hierarchy chain of 100 levels should work correctly."""
        depth = 100
        levels = [f"level-{i}" for i in range(depth)]

        # Create hierarchy chain: level-0 -> level-1 -> ... -> level-99
        for i in range(depth - 1):
            authz.add_hierarchy_rule("doc", levels[i], levels[i + 1])

        # Grant top-level permission
        authz.grant(levels[0], resource=("doc", "1"), subject=("user", "alice"))

        # User should have all implied permissions
        start = time.time()
        for level in levels:
            assert authz.check("alice", level, ("doc", "1"))
        check_time = time.time() - start

        # Checks should be fast (O(1) each)
        avg_check_ms = (check_time / depth) * 1000
        assert avg_check_ms < 5, f"Average check time {avg_check_ms:.2f}ms too slow"


class TestAmplification:
    """Test write amplification scenarios.

    With lazy evaluation, there's no precomputed table and thus no
    write amplification. These tests verify that lazy evaluation
    handles scenarios that would have caused amplification correctly.
    """

    def test_large_team_with_hierarchy(self, authz):
        """Large team with hierarchy works correctly via lazy evaluation."""
        # Create a scenario that would have significant amplification with precomputation:
        # - 1 team with 100 members
        # - Team has admin on 10 resources
        # - Hierarchy: admin -> write -> read (3 levels)

        authz.set_hierarchy("doc", "admin", "write", "read")

        for i in range(100):
            authz.grant(
                "member", resource=("team", "eng"), subject=("user", f"user-{i}")
            )

        for i in range(10):
            authz.grant("admin", resource=("doc", f"doc-{i}"), subject=("team", "eng"))

        stats = authz.stats()

        # Tuples: 100 memberships + 10 team grants = 110
        # With lazy evaluation, no computed table exists
        assert stats["tuple_count"] == 110

        # Verify permissions work correctly via lazy evaluation
        assert authz.check("user-0", "admin", ("doc", "doc-0"))
        assert authz.check("user-0", "write", ("doc", "doc-0"))
        assert authz.check("user-0", "read", ("doc", "doc-0"))
        assert authz.check("user-99", "admin", ("doc", "doc-9"))
        assert not authz.check("user-0", "admin", ("doc", "doc-999"))  # Non-existent


class TestEdgeCases:
    """Test edge cases at scale."""

    def test_max_hierarchy_depth(self, authz):
        """Verify deep hierarchy depth works correctly."""
        # With lazy evaluation using recursive CTEs, we need to stay
        # within PostgreSQL's max recursion depth (default: 100)
        depth = 50  # Safe margin below 100

        levels = [f"perm-{i}" for i in range(depth)]
        for i in range(depth - 1):
            authz.add_hierarchy_rule("doc", levels[i], levels[i + 1])

        authz.grant(levels[0], resource=("doc", "1"), subject=("user", "alice"))

        # Should complete without hitting iteration limit
        assert authz.check("alice", levels[depth - 1], ("doc", "1"))

    def test_many_permissions_same_resource(self, authz):
        """Many users with different permissions on same resource."""
        num_users = 500
        permissions = ["read", "write", "admin", "delete", "share"]

        for i in range(num_users):
            perm = permissions[i % len(permissions)]
            authz.grant(
                perm, resource=("doc", "contested"), subject=("user", f"user-{i}")
            )

        # Verify correct permissions
        for i in range(0, num_users, 50):
            expected_perm = permissions[i % len(permissions)]
            assert authz.check(f"user-{i}", expected_perm, ("doc", "contested"))

        # list_users should work
        users = authz.list_users("read", ("doc", "contested"))
        expected_read_users = num_users // len(permissions)
        assert len(users) == expected_read_users
