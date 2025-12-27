"""
Listing and filtering tests for postkit/authz.

Tests for:
- filter_authorized: batch filtering of resources
- Pagination: cursor-based pagination for list operations
- list_users / list_resources: listing operations
"""

import pytest
from authz_sdk import AuthzClient


class TestFilterAuthorized:
    """Test the filter_authorized function for batch filtering."""

    def test_filter_returns_only_authorized(self, authz):
        """filter_authorized returns subset user can access."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "3"), subject=("user", "alice"))

        result = authz.filter_authorized("alice", "doc", "read", ["1", "2", "3", "4"])

        assert set(result) == {"1", "3"}

    def test_filter_empty_input_returns_empty(self, authz):
        """Empty input list returns empty result."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        result = authz.filter_authorized("alice", "doc", "read", [])

        assert result == []

    def test_filter_no_access_returns_empty(self, authz):
        """User with no access gets empty result."""
        result = authz.filter_authorized("alice", "doc", "read", ["1", "2", "3"])

        assert result == []

    def test_filter_respects_hierarchy(self, authz):
        """filter_authorized respects permission hierarchy."""
        authz.set_hierarchy("doc", "admin", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "2"), subject=("user", "alice"))

        result = authz.filter_authorized("alice", "doc", "read", ["1", "2", "3"])

        assert set(result) == {"1", "2"}

    def test_filter_respects_group_membership(self, authz):
        """filter_authorized respects group-based access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("read", resource=("doc", "2"), subject=("team", "eng"))

        result = authz.filter_authorized("alice", "doc", "read", ["1", "2", "3"])

        assert set(result) == {"1", "2"}

    def test_filter_large_batch(self, authz):
        """filter_authorized handles large input efficiently."""
        # Grant access to even-numbered docs
        for i in range(0, 100, 2):
            authz.grant("read", resource=("doc", str(i)), subject=("user", "alice"))

        all_docs = [str(i) for i in range(100)]
        result = authz.filter_authorized("alice", "doc", "read", all_docs)

        expected = {str(i) for i in range(0, 100, 2)}
        assert set(result) == expected

    def test_filter_returns_consistent_results(self, authz):
        """filter_authorized returns results consistently."""
        authz.grant("read", resource=("doc", "z"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "a"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "m"), subject=("user", "alice"))

        result = authz.filter_authorized(
            "alice", "doc", "read", ["z", "a", "m", "x"]  # x not authorized
        )

        # Should return authorized ones (order may vary, but set should match)
        assert set(result) == {"z", "a", "m"}


class TestPagination:
    """Test cursor-based pagination for list operations."""

    def test_list_resources_pagination(self, authz):
        """list_resources supports cursor-based pagination."""
        # Create 25 resources with predictable IDs
        for i in range(25):
            authz.grant(
                "read", resource=("doc", f"doc-{i:02d}"), subject=("user", "alice")
            )

        # First page
        page1 = authz.list_resources("alice", "doc", "read", limit=10)
        assert len(page1) == 10

        # Second page using cursor
        page2 = authz.list_resources("alice", "doc", "read", limit=10, cursor=page1[-1])
        assert len(page2) == 10
        assert page2[0] > page1[-1]  # Cursor works

        # Third page (partial)
        page3 = authz.list_resources("alice", "doc", "read", limit=10, cursor=page2[-1])
        assert len(page3) == 5

        # All resources accounted for
        all_docs = set(page1 + page2 + page3)
        assert len(all_docs) == 25

    def test_list_users_pagination(self, authz):
        """list_users supports cursor-based pagination."""
        # Grant to 15 users
        for i in range(15):
            authz.grant(
                "read", resource=("doc", "shared"), subject=("user", f"user-{i:02d}")
            )

        page1 = authz.list_users("read", ("doc", "shared"), limit=10)
        page2 = authz.list_users("read", ("doc", "shared"), limit=10, cursor=page1[-1])

        assert len(page1) == 10
        assert len(page2) == 5
        assert set(page1).isdisjoint(set(page2))

    def test_pagination_with_no_results(self, authz):
        """Pagination with no results returns empty list."""
        result = authz.list_resources("nobody", "doc", "read", limit=10)
        assert result == []

    def test_pagination_cursor_past_end(self, authz):
        """Cursor past all results returns empty list."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        result = authz.list_resources("alice", "doc", "read", limit=10, cursor="zzz")
        assert result == []
