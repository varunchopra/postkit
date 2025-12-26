"""
Resource hierarchy tests for pg-authz.

Tests for resource containment (e.g., folder contains doc, org contains project).
Access to a parent resource grants access to child resources.
"""

import pytest


class TestBasicResourceHierarchy:
    """Tests for basic parent-child resource relationships."""

    def test_access_to_folder_grants_access_to_doc(self, authz):
        """User with read on folder can read docs in that folder."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice can read the folder
        authz.grant("read", resource=("folder", "docs"), subject=("user", "alice"))

        # Alice should be able to read the doc inside
        assert authz.check("alice", "read", ("doc", "readme"))

    def test_no_folder_access_no_doc_access(self, authz):
        """User without folder access cannot access docs in folder."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice has no access to the folder
        # Alice should not be able to read the doc
        assert not authz.check("alice", "read", ("doc", "readme"))

    def test_direct_doc_access_without_folder(self, authz):
        """Direct grant on doc works without folder access."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice gets direct access to the doc
        authz.grant("read", resource=("doc", "readme"), subject=("user", "alice"))

        # Alice can read the doc directly
        assert authz.check("alice", "read", ("doc", "readme"))
        # But not the folder
        assert not authz.check("alice", "read", ("folder", "docs"))


class TestNestedResourceHierarchy:
    """Tests for deeply nested resource hierarchies."""

    def test_three_level_hierarchy(self, authz):
        """Access propagates through multiple levels: org -> project -> doc."""
        # doc:spec is in project:api, which is in org:acme
        authz.grant("parent", resource=("doc", "spec"), subject=("project", "api"))
        authz.grant("parent", resource=("project", "api"), subject=("org", "acme"))

        # Alice can read the org
        authz.grant("read", resource=("org", "acme"), subject=("user", "alice"))

        # Alice should be able to read the doc
        assert authz.check("alice", "read", ("doc", "spec"))

    def test_middle_level_access(self, authz):
        """Access at middle level grants access to children only."""
        # doc:spec is in project:api, which is in org:acme
        authz.grant("parent", resource=("doc", "spec"), subject=("project", "api"))
        authz.grant("parent", resource=("project", "api"), subject=("org", "acme"))

        # Alice can read the project (middle level)
        authz.grant("read", resource=("project", "api"), subject=("user", "alice"))

        # Alice can read the doc (child)
        assert authz.check("alice", "read", ("doc", "spec"))
        # But not the org (parent)
        assert not authz.check("alice", "read", ("org", "acme"))


class TestResourceHierarchyWithPermissionHierarchy:
    """Tests combining resource hierarchy with permission hierarchy."""

    def test_admin_on_folder_gives_read_on_doc(self, authz):
        """Admin on folder grants read on docs via permission hierarchy."""
        # Set up permission hierarchy
        authz.add_hierarchy_rule("folder", "admin", "read")
        authz.add_hierarchy_rule("doc", "admin", "read")

        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice is admin of the folder
        authz.grant("admin", resource=("folder", "docs"), subject=("user", "alice"))

        # Alice should be able to read the doc
        assert authz.check("alice", "read", ("doc", "readme"))

    def test_write_on_folder_gives_write_on_doc(self, authz):
        """Write permission propagates to child resources."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice can write to the folder
        authz.grant("write", resource=("folder", "docs"), subject=("user", "alice"))

        # Alice should be able to write to the doc
        assert authz.check("alice", "write", ("doc", "readme"))


class TestResourceHierarchyWithGroups:
    """Tests combining resource hierarchy with group membership."""

    def test_team_access_to_folder_propagates_to_docs(self, authz):
        """Team with folder access grants members access to docs."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Engineering team can read the folder
        authz.grant(
            "read", resource=("folder", "docs"), subject=("team", "engineering")
        )

        # Alice is on the engineering team
        authz.grant(
            "member", resource=("team", "engineering"), subject=("user", "alice")
        )

        # Alice should be able to read the doc
        assert authz.check("alice", "read", ("doc", "readme"))

    def test_nested_team_with_resource_hierarchy(self, authz):
        """Nested teams work with resource hierarchies."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Platform team can read the folder
        authz.grant("read", resource=("folder", "docs"), subject=("team", "platform"))

        # Infrastructure team is part of platform team
        authz.grant(
            "member", resource=("team", "platform"), subject=("team", "infrastructure")
        )

        # Alice is on the infrastructure team
        authz.grant(
            "member", resource=("team", "infrastructure"), subject=("user", "alice")
        )

        # Alice should be able to read the doc
        assert authz.check("alice", "read", ("doc", "readme"))


class TestResourceHierarchyCycleDetection:
    """Tests that cycles in resource hierarchy are prevented."""

    def test_direct_cycle_rejected(self, authz):
        """Resource cannot be its own parent."""
        with pytest.raises(Exception):
            authz.grant(
                "parent", resource=("folder", "docs"), subject=("folder", "docs")
            )

    def test_indirect_cycle_rejected(self, authz):
        """Indirect cycles are detected and rejected."""
        # folder:a contains folder:b
        authz.grant("parent", resource=("folder", "b"), subject=("folder", "a"))

        # folder:b cannot contain folder:a (would create cycle)
        with pytest.raises(Exception):
            authz.grant("parent", resource=("folder", "a"), subject=("folder", "b"))

    def test_long_cycle_rejected(self, authz):
        """Long cycles are detected and rejected."""
        # a contains b, b contains c, c contains d
        authz.grant("parent", resource=("folder", "b"), subject=("folder", "a"))
        authz.grant("parent", resource=("folder", "c"), subject=("folder", "b"))
        authz.grant("parent", resource=("folder", "d"), subject=("folder", "c"))

        # d cannot contain a (would create cycle)
        with pytest.raises(Exception):
            authz.grant("parent", resource=("folder", "a"), subject=("folder", "d"))


class TestListingWithResourceHierarchy:
    """Tests for list operations with resource hierarchies."""

    def test_list_users_includes_parent_access(self, authz):
        """list_users on doc includes users with folder access."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice has direct access to doc
        authz.grant("read", resource=("doc", "readme"), subject=("user", "alice"))

        # Bob has access via folder
        authz.grant("read", resource=("folder", "docs"), subject=("user", "bob"))

        users = authz.list_users("read", ("doc", "readme"))

        assert "alice" in users
        assert "bob" in users

    def test_list_resources_includes_child_resources(self, authz):
        """list_resources includes resources accessible via parent."""
        # doc:readme and doc:changelog are in folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))
        authz.grant("parent", resource=("doc", "changelog"), subject=("folder", "docs"))

        # Alice can read the folder
        authz.grant("read", resource=("folder", "docs"), subject=("user", "alice"))

        # Alice also has direct access to another doc
        authz.grant("read", resource=("doc", "other"), subject=("user", "alice"))

        resources = authz.list_resources("alice", "doc", "read")

        assert "readme" in resources
        assert "changelog" in resources
        assert "other" in resources

    def test_filter_authorized_with_resource_hierarchy(self, authz):
        """filter_authorized respects resource hierarchy."""
        # doc:readme is in folder:docs, doc:secret is not
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice can read the folder
        authz.grant("read", resource=("folder", "docs"), subject=("user", "alice"))

        authorized = authz.filter_authorized(
            "alice", "doc", "read", ["readme", "secret", "other"]
        )

        assert authorized == ["readme"]


class TestExplainWithResourceHierarchy:
    """Tests for explain with resource hierarchies."""

    def test_explain_shows_parent_path(self, authz):
        """Explain shows access via parent resource."""
        # doc:readme is inside folder:docs
        authz.grant("parent", resource=("doc", "readme"), subject=("folder", "docs"))

        # Alice can read the folder
        authz.grant("read", resource=("folder", "docs"), subject=("user", "alice"))

        explanation = authz.explain("alice", "read", ("doc", "readme"))

        # Should have at least one explanation showing access
        assert len(explanation) > 0
        # Should mention folder or resource in the explanation
        explanation_text = " ".join(explanation)
        assert (
            "folder" in explanation_text.lower()
            or "resource" in explanation_text.lower()
        )
