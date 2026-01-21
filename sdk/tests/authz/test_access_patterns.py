"""
Tests for permission resolution patterns in postkit/authz.

These tests verify correct behavior for complex access patterns:

1. Multi-level hierarchy with alternate paths
2. subject_relation filtering
3. Cascade handling when users join/leave groups
4. Multiple alternate paths to the same permission

With lazy evaluation, permissions are computed at query time via recursive
CTEs. These tests ensure the resolution logic handles edge cases correctly.
"""


class TestMultiLevelHierarchyAlternatePath:
    """
    Hierarchy check must walk full permission chain.

    When a user loses one path to a permission, alternate paths through
    multi-level hierarchies (admin -> write -> read) must still work.
    """

    def test_alternate_path_via_higher_permission_two_levels(self, authz):
        """
        User retains 'read' when alternate path has 'admin' (admin->write->read).

        Setup:
        - alice is member of team:eng AND team:platform
        - team:eng has 'read' on repo:api
        - team:platform has 'admin' on repo:api
        - Hierarchy: admin -> write -> read

        When alice is removed from team:eng, she should still have read
        via team:platform's admin (which implies write, which implies read).
        """
        authz.set_hierarchy("repo", "admin", "write", "read")

        # alice is in both teams
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("user", "alice"))

        # eng has read, platform has admin
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))
        authz.grant("admin", resource=("repo", "api"), subject=("team", "platform"))

        # alice should have admin, write, and read
        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

        # Remove alice from team:eng
        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should STILL have all permissions via team:platform's admin
        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_alternate_path_via_middle_permission(self, authz):
        """
        User retains 'read' when alternate path has 'write' (write->read).

        This tests the hierarchy at one level deep, which should work
        even without the recursive CTE fix.
        """
        authz.set_hierarchy("repo", "admin", "write", "read")

        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("user", "alice"))

        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))
        authz.grant("write", resource=("repo", "api"), subject=("team", "platform"))

        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should still have write and read via team:platform
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))
        assert not authz.check(("user", "alice"), "admin", ("repo", "api"))

    def test_no_alternate_path_removes_permission(self, authz):
        """Verify removal works when there is no alternate path."""
        authz.set_hierarchy("repo", "admin", "write", "read")

        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))

        assert authz.check(("user", "alice"), "read", ("repo", "api"))

        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should lose all access
        assert not authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_multiple_relations_on_same_group(self, authz):
        """
        User with multiple relations on same group retains access when one is removed.

        This tests that we only exclude the specific group#relation being removed,
        not ALL relations on that group.

        Scenario:
        - Alice is BOTH member AND admin of team:eng
        - team:eng#member has read on doc:1
        - team:eng#admin has write on doc:1 (and write->read hierarchy)
        - Removing Alice's member should NOT remove her read (she has it via admin)
        """
        authz.set_hierarchy("doc", "write", "read")

        # Alice has both member and admin relations on team:eng
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))

        # Grant via different relations
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            subject_relation="member",
        )
        authz.grant(
            "write",
            resource=("doc", "1"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # Alice should have both read and write
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))

        # Remove Alice's member relation
        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # Alice should STILL have read via admin->write->read
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))

        # Remove Alice's admin relation too
        authz.revoke("admin", resource=("team", "eng"), subject=("user", "alice"))

        # Now Alice should lose all access
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))
        assert not authz.check(("user", "alice"), "write", ("doc", "1"))

    def test_direct_grant_as_alternate_path(self, authz):
        """Direct grant serves as alternate path to retain permission."""
        authz.set_hierarchy("repo", "admin", "write", "read")

        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))

        # alice also has direct admin grant
        authz.grant("admin", resource=("repo", "api"), subject=("user", "alice"))

        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should still have all permissions via direct admin grant
        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))


class TestSubjectRelationFiltering:
    """
    subject_relation must be respected in permission grants.

    When a tuple specifies subject_relation (e.g., team#admin instead of
    team#member), only users with that specific relation should get access.
    """

    def test_member_does_not_get_admin_only_permission(self, authz):
        """
        User with 'member' relation doesn't get permission granted to 'admin'.

        This tests that incremental_add_user_to_group filters by subject_relation.
        """
        # alice is an admin of the team
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))

        # bob is just a member
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Grant repo access only to team admins, not members
        authz.grant(
            "read",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # alice (admin) should have access
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

        # bob (member) should NOT have access
        assert not authz.check(("user", "bob"), "read", ("repo", "api"))

    def test_adding_member_after_admin_only_grant(self, authz):
        """
        Adding a new member after admin-only grant doesn't give them access.

        This specifically tests the incremental path: the grant exists,
        then we add a member - they shouldn't get access.
        """
        # Grant repo access only to team admins
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # Now add charlie as a member (not admin)
        authz.grant("member", resource=("team", "eng"), subject=("user", "charlie"))

        # charlie should NOT have access (member != admin)
        assert not authz.check(("user", "charlie"), "write", ("repo", "api"))

        # But if we make charlie an admin...
        authz.grant("admin", resource=("team", "eng"), subject=("user", "charlie"))

        # Now charlie should have access
        assert authz.check(("user", "charlie"), "write", ("repo", "api"))

    def test_member_gets_default_member_grant(self, authz):
        """Member gets access from grants that use default member relation."""
        # Grant with default member relation (no subject_relation specified)
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))

        # Add alice as member
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should have access via default member relation
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_mixed_relations_on_same_resource(self, authz):
        """Different relations grant different permissions on same resource."""
        # Members get read, admins get write
        authz.grant(
            "read",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="member",
        )
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # alice is member, bob is admin
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("admin", resource=("team", "eng"), subject=("user", "bob"))

        # alice: read yes, write no
        assert authz.check(("user", "alice"), "read", ("repo", "api"))
        assert not authz.check(("user", "alice"), "write", ("repo", "api"))

        # bob: write yes (and read via hierarchy if set, but not set here)
        assert authz.check(("user", "bob"), "write", ("repo", "api"))
        assert not authz.check(("user", "bob"), "read", ("repo", "api"))


class TestCascadeHandling:
    """
    Group membership changes cascade to all affected resources.

    When a user joins or leaves a group, their effective permissions
    on all resources where that group has access must update.
    """

    def test_joining_group_grants_access_to_all_group_resources(self, authz):
        """User joining group gets access to all resources the group has."""
        # Team has access to multiple resources
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))
        authz.grant("write", resource=("repo", "frontend"), subject=("team", "eng"))
        authz.grant("admin", resource=("doc", "design"), subject=("team", "eng"))

        # alice joins the team
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should have access to ALL resources
        assert authz.check(("user", "alice"), "read", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "frontend"))
        assert authz.check(("user", "alice"), "admin", ("doc", "design"))

    def test_leaving_group_removes_access_to_all_group_resources(self, authz):
        """User leaving group loses access to all group resources."""
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))
        authz.grant("write", resource=("repo", "frontend"), subject=("team", "eng"))
        authz.grant("admin", resource=("doc", "design"), subject=("team", "eng"))

        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # Verify alice has access
        assert authz.check(("user", "alice"), "read", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "frontend"))

        # alice leaves the team
        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should lose ALL access
        assert not authz.check(("user", "alice"), "read", ("repo", "api"))
        assert not authz.check(("user", "alice"), "write", ("repo", "frontend"))
        assert not authz.check(("user", "alice"), "admin", ("doc", "design"))

    def test_cascade_with_hierarchy_expansion(self, authz):
        """Cascade works together with hierarchy expansion."""
        authz.set_hierarchy("repo", "admin", "write", "read")

        # Team has admin on repo
        authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))

        # alice joins team
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # alice should have admin, write, and read (cascade + hierarchy)
        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))


class TestMultipleAlternatePaths:
    """
    Tests for complex scenarios with multiple alternate paths.

    These tests ensure that permission checks correctly handle cases
    where a user has access through multiple independent paths.
    """

    def test_three_groups_remove_one(self, authz):
        """User in three groups retains access when removed from one."""
        authz.grant("member", resource=("team", "a"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "b"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "c"), subject=("user", "alice"))

        authz.grant("read", resource=("doc", "1"), subject=("team", "a"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "b"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "c"))

        # Remove from team:a
        authz.revoke("member", resource=("team", "a"), subject=("user", "alice"))

        # Still has access via team:b and team:c
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove from team:b
        authz.revoke("member", resource=("team", "b"), subject=("user", "alice"))

        # Still has access via team:c
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove from team:c
        authz.revoke("member", resource=("team", "c"), subject=("user", "alice"))

        # Now access is gone
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_direct_and_group_combined(self, authz):
        """Direct grant + group grant are independent alternate paths."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))  # Direct

        # Remove from group
        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # Still has access via direct grant
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove direct grant
        authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))

        # Now access is gone
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_hierarchy_levels_as_alternate_paths(self, authz):
        """Different hierarchy levels count as having the permission."""
        authz.set_hierarchy("doc", "admin", "write", "read")

        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "ops"), subject=("user", "alice"))

        # eng has read directly, ops has write (implies read)
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("write", resource=("doc", "1"), subject=("team", "ops"))

        # Remove from eng (had direct read)
        authz.revoke("member", resource=("team", "eng"), subject=("user", "alice"))

        # Still has read via ops's write -> read
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))


class TestDirectGrants:
    """Tests for direct user grants."""

    def test_direct_grant_with_hierarchy(self, authz):
        """Direct grant to user expands hierarchy correctly."""
        authz.set_hierarchy("repo", "admin", "write", "read")

        authz.grant("admin", resource=("repo", "api"), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_direct_revoke_with_group_fallback(self, authz):
        """Revoking direct grant preserves group-based access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))  # Direct

        # Revoke direct grant
        authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))

        # alice still has access via team
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_direct_revoke_no_fallback(self, authz):
        """Revoking direct grant removes access when no fallback."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))

        assert not authz.check(("user", "alice"), "read", ("doc", "1"))


class TestGroupGrants:
    """Tests for grants to groups."""

    def test_grant_to_group_gives_all_members_access(self, authz):
        """Granting permission to group gives all members access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "charlie"))

        # Grant to group
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        # All members should have access
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "bob"), "read", ("doc", "1"))
        assert authz.check(("user", "charlie"), "read", ("doc", "1"))

    def test_revoke_from_group_with_alternate_paths(self, authz):
        """Revoking from group preserves access for members with alternates."""
        # alice is in two teams
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "ops"), subject=("user", "alice"))

        # bob is only in eng
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Both teams have read on doc:1
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "ops"))

        # Revoke from eng
        authz.revoke("read", resource=("doc", "1"), subject=("team", "eng"))

        # alice should still have access (via ops)
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # bob should lose access (only had it via eng)
        assert not authz.check(("user", "bob"), "read", ("doc", "1"))

    def test_revoke_group_grant_with_subject_relation(self, authz):
        """
        Revoking group#admin grant only affects users with admin relation.

        This tests that incremental_remove_group_grant correctly filters
        by subject_relation.
        """
        # charlie is team admin, alice is regular member
        authz.grant("admin", resource=("team", "eng"), subject=("user", "charlie"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # Grant write access only to team#admin (not regular members)
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # charlie has write, alice does not
        assert authz.check(("user", "charlie"), "write", ("repo", "api"))
        assert not authz.check(("user", "alice"), "write", ("repo", "api"))

        # Revoke the team#admin grant
        authz.revoke(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # charlie should lose access
        assert not authz.check(("user", "charlie"), "write", ("repo", "api"))

    def test_revoke_group_grant_preserves_other_relations(self, authz):
        """
        Revoking group#admin doesn't affect group#member grants.

        Members and admins can have separate permissions on same resource.
        """
        authz.grant("admin", resource=("team", "eng"), subject=("user", "charlie"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        # Admins get write, members get read
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )
        authz.grant(
            "read",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="member",
        )

        assert authz.check(("user", "charlie"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

        # Revoke only admin grant
        authz.revoke(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # charlie loses write
        assert not authz.check(("user", "charlie"), "write", ("repo", "api"))

        # alice keeps read
        assert authz.check(("user", "alice"), "read", ("repo", "api"))
