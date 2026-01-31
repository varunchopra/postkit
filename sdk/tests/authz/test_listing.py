"""
Listing and filtering tests for postkit/authz.

Tests for:
- filter_authorized: batch filtering of resources
- Pagination: cursor-based pagination for list operations
- list_subjects / list_resources: listing operations
"""


class TestFilterAuthorized:
    """Test the filter_authorized function for batch filtering."""

    def test_filter_returns_only_authorized(self, authz):
        """filter_authorized returns subset user can access."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "3"), subject=("user", "alice"))

        result = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3", "4"]
        )

        assert set(result) == {"1", "3"}

    def test_filter_empty_input_returns_empty(self, authz):
        """Empty input list returns empty result."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        result = authz.filter_authorized(("user", "alice"), "doc", "read", [])

        assert result == []

    def test_filter_no_access_returns_empty(self, authz):
        """User with no access gets empty result."""
        result = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3"]
        )

        assert result == []

    def test_filter_respects_hierarchy(self, authz):
        """filter_authorized respects permission hierarchy."""
        authz.set_hierarchy("doc", "admin", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "2"), subject=("user", "alice"))

        result = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3"]
        )

        assert set(result) == {"1", "2"}

    def test_filter_respects_group_membership(self, authz):
        """filter_authorized respects group-based access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("read", resource=("doc", "2"), subject=("team", "eng"))

        result = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3"]
        )

        assert set(result) == {"1", "2"}

    def test_filter_large_batch(self, authz):
        """filter_authorized handles large input efficiently."""
        # Grant access to even-numbered docs
        for i in range(0, 100, 2):
            authz.grant("read", resource=("doc", str(i)), subject=("user", "alice"))

        all_docs = [str(i) for i in range(100)]
        result = authz.filter_authorized(("user", "alice"), "doc", "read", all_docs)

        expected = {str(i) for i in range(0, 100, 2)}
        assert len(result) == 50  # No duplicates in result
        assert set(result) == expected


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
        page1 = authz.list_resources(("user", "alice"), "doc", "read", limit=10)
        assert len(page1) == 10

        # Second page using cursor
        page2 = authz.list_resources(
            ("user", "alice"), "doc", "read", limit=10, cursor=page1[-1]
        )
        assert len(page2) == 10
        assert page2[0] > page1[-1]  # Cursor works

        # Third page (partial)
        page3 = authz.list_resources(
            ("user", "alice"), "doc", "read", limit=10, cursor=page2[-1]
        )
        assert len(page3) == 5

        # All resources accounted for
        all_docs = set(page1 + page2 + page3)
        assert len(all_docs) == 25

    def test_list_subjects_pagination(self, authz):
        """list_subjects supports cursor-based pagination."""
        # Grant to 15 users
        for i in range(15):
            authz.grant(
                "read", resource=("doc", "shared"), subject=("user", f"user-{i:02d}")
            )

        page1 = authz.list_subjects("read", ("doc", "shared"), limit=10)
        # Cursor is the full (type, id) tuple from the last result
        page2 = authz.list_subjects(
            "read", ("doc", "shared"), limit=10, cursor=page1[-1]
        )

        assert len(page1) == 10
        assert len(page2) == 5
        assert set(page1).isdisjoint(set(page2))

    def test_pagination_with_no_results(self, authz):
        """Pagination with no results returns empty list."""
        result = authz.list_resources(("user", "nobody"), "doc", "read", limit=10)
        assert result == []

    def test_pagination_cursor_past_end(self, authz):
        """Cursor past all results returns empty list."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        result = authz.list_resources(
            ("user", "alice"), "doc", "read", limit=10, cursor="zzz"
        )
        assert result == []

    def test_list_subjects_pagination_mixed_types(self, authz):
        """list_subjects pagination works correctly with mixed subject types.

        Regression test: pagination must use composite cursor (type, id) not just id,
        otherwise subjects are skipped when paginating across different types.
        """
        # IDs designed to expose the bug: "bbb" < "zzz" alphabetically
        authz.grant("read", resource=("doc", "shared"), subject=("api_key", "aaa"))
        authz.grant("read", resource=("doc", "shared"), subject=("api_key", "zzz"))
        authz.grant("read", resource=("doc", "shared"), subject=("user", "bbb"))

        all_subjects = set(authz.list_subjects("read", ("doc", "shared")))
        assert len(all_subjects) == 3

        page1 = authz.list_subjects("read", ("doc", "shared"), limit=2)
        assert page1 == [("api_key", "aaa"), ("api_key", "zzz")]

        # Old bug: WHERE subject_id > "zzz" skips ("user", "bbb") since "bbb" < "zzz"
        # Fixed: WHERE (type, id) > ("api_key", "zzz") includes ("user", "bbb")
        page2 = authz.list_subjects(
            "read", ("doc", "shared"), limit=2, cursor=page1[-1]
        )
        assert ("user", "bbb") in page2

        combined = set(page1) | set(page2)
        assert combined == all_subjects

    def test_list_subjects_pagination_same_id_different_types(self, authz):
        """Pagination handles same ID across different subject types."""
        authz.grant("read", resource=("doc", "shared"), subject=("api_key", "alice"))
        authz.grant("read", resource=("doc", "shared"), subject=("user", "alice"))

        page1 = authz.list_subjects("read", ("doc", "shared"), limit=1)
        assert page1 == [("api_key", "alice")]

        page2 = authz.list_subjects(
            "read", ("doc", "shared"), limit=1, cursor=page1[-1]
        )
        assert page2 == [("user", "alice")]

    def test_list_subjects_partial_cursor_fails_safe(self, authz):
        """Partial cursor returns empty result (fail-safe), not all rows.

        Defense in depth: SQL function should handle invalid input gracefully
        even though the SDK prevents this scenario via type constraints.
        """
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("user", "bob"))

        # Direct SQL call with partial cursor (cursor_type set, cursor_id NULL)
        # Parameters: resource_type, resource_id, permission, namespace, limit, subject_type, cursor_type, cursor_id
        authz.cursor.execute(
            """SELECT * FROM authz.list_subjects(%s, %s, %s, %s, %s, %s, %s, %s)""",
            ("doc", "1", "read", authz.namespace, 100, None, "user", None),
        )

        # Should return empty (fail-safe), not all rows
        result = authz.cursor.fetchall()
        assert result == []
