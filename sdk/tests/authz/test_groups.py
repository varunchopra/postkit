"""
Group membership tests for postkit/authz.

Tests for:
- Team/group permission inheritance
- Member addition/removal
- Cascade behavior when groups change
- Subject relations (userset references)
- Edge cases
"""


class TestGroupDeletion:
    """Test behavior when groups are modified."""

    def test_removing_team_permission_removes_member_access(self, authz):
        """When team loses permission, members lose access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove team's permission (not alice's membership)
        assert authz.revoke("read", resource=("doc", "1"), subject=("team", "eng"))

        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_removing_user_from_team_removes_access(self, authz):
        """Removing user from team removes their team-based access."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove alice from team
        assert authz.revoke(
            "member", resource=("team", "eng"), subject=("user", "alice")
        )

        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_deleting_all_team_members_clears_access(self, authz):
        """Removing all members from team removes their access."""
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Remove all members
        assert authz.revoke(
            "member", resource=("team", "eng"), subject=("user", "alice")
        )
        assert authz.revoke("member", resource=("team", "eng"), subject=("user", "bob"))

        # No one can access via team anymore
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))
        assert not authz.check(("user", "bob"), "read", ("doc", "1"))


class TestGroupMembership:
    """Test group membership inheritance."""

    def test_user_inherits_team_permissions(self, authz):
        """User gets permissions from team membership."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_multiple_users_in_team(self, authz):
        """Multiple users in same team all get permissions."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "bob"), "read", ("doc", "1"))

    def test_user_in_multiple_teams(self, authz):
        """User can be in multiple teams and get all permissions."""
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "ops"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("write", resource=("doc", "2"), subject=("team", "ops"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "2"))

    def test_team_permissions_combine_with_hierarchy(self, authz):
        """Team permissions work with hierarchy expansion."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("admin", resource=("doc", "1"), subject=("team", "eng"))

        # alice gets admin from team, plus write and read from hierarchy
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))
        assert authz.check(("user", "alice"), "read", ("doc", "1"))


class TestSubjectRelations:
    """Test non-default subject relations (userset references).

    The subject_relation field allows granting permissions to specific
    relations on a group, not just the default "member" relation.

    Example: team#admin vs team#member
    """

    def test_custom_subject_relation_grants_access(self, authz):
        """Permission granted via custom subject_relation works."""
        # alice has "admin" relation on team (not member)
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))

        # Grant repo access to team#admin (not default team#member)
        authz.grant(
            "read",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # alice should have access via team#admin
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_member_not_matching_admin_relation(self, authz):
        """User with 'member' doesn't get access via 'admin' subject_relation."""
        # bob has "member" relation on team
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Grant repo access to team#admin only
        authz.grant(
            "read",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # bob is member, not admin, so no access
        assert not authz.check(("user", "bob"), "read", ("repo", "api"))

    def test_both_member_and_admin_get_respective_access(self, authz):
        """Users get access based on their specific relation."""
        # alice is admin, bob is member
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Different resources for different relations
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

        # alice (admin) gets write
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        # bob (member) gets read only
        assert authz.check(("user", "bob"), "read", ("repo", "api"))
        assert not authz.check(("user", "bob"), "write", ("repo", "api"))
        # Security: admin relation must not grant access to member-only permission.
        assert not authz.check(("user", "alice"), "read", ("repo", "api"))


class TestGroupEdgeCases:
    """Edge cases in group membership."""

    def test_large_group(self, authz):
        """Group with many members."""
        authz.grant("read", resource=("doc", "1"), subject=("team", "big-team"))
        authz.bulk_grant(
            "member",
            resource=("team", "big-team"),
            subjects=[("user", f"user-{i}") for i in range(100)],
        )

        for i in range(100):
            assert authz.check(("user", f"user-{i}"), "read", ("doc", "1"))

    def test_empty_group(self, authz):
        """Group with no members grants no access."""
        authz.grant("read", resource=("doc", "1"), subject=("team", "empty-team"))

        # No one has access since the team has no members
        assert not authz.check(("user", "anyone"), "read", ("doc", "1"))
