"""Nested teams tests."""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authz import AuthzCycleError


class TestNestedTeamMembership:
    """Test nested team membership."""

    def test_simple_nesting(self, authz):
        """User in child team inherits parent team's permissions."""
        # alice is in infrastructure
        authz.grant(
            "member", resource=("team", "infrastructure"), subject=("user", "alice")
        )

        # infrastructure is in platform
        authz.grant(
            "member", resource=("team", "platform"), subject=("team", "infrastructure")
        )

        # platform has admin on repo
        authz.grant("admin", resource=("repo", "api"), subject=("team", "platform"))

        # alice should have admin via: alice in infra in platform -> repo
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True

    def test_deep_nesting(self, authz):
        """Permissions work through deep nesting (5 levels)."""
        # alice in team-a in team-b in team-c in team-d in team-e
        authz.grant("member", resource=("team", "a"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "b"))
        authz.grant("member", resource=("team", "d"), subject=("team", "c"))
        authz.grant("member", resource=("team", "e"), subject=("team", "d"))

        # team-e has read on doc
        authz.grant("read", resource=("doc", "secret"), subject=("team", "e"))

        assert authz.check(("user", "alice"), "read", ("doc", "secret")) is True

    def test_user_not_in_nested_chain_denied(self, authz):
        """User outside the nested chain has no access."""
        # alice is in infrastructure
        authz.grant(
            "member", resource=("team", "infrastructure"), subject=("user", "alice")
        )

        # infrastructure is in platform
        authz.grant(
            "member", resource=("team", "platform"), subject=("team", "infrastructure")
        )

        # security team (separate) has admin
        authz.grant("admin", resource=("repo", "api"), subject=("team", "security"))

        # alice is not in security, so no access
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is False

    def test_multiple_paths(self, authz):
        """User with multiple paths to permission (DAG structure)."""
        # alice is in both infra and security teams
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "security"), subject=("user", "alice"))

        # both teams are in engineering
        authz.grant(
            "member", resource=("team", "engineering"), subject=("team", "infra")
        )
        authz.grant(
            "member", resource=("team", "engineering"), subject=("team", "security")
        )

        # engineering has admin
        authz.grant("admin", resource=("repo", "api"), subject=("team", "engineering"))

        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True

    def test_diamond_structure(self, authz):
        """Diamond inheritance pattern works correctly."""
        #       engineering
        #       /         \
        #   platform    security
        #       \         /
        #        infrastructure
        #            |
        #          alice

        authz.grant(
            "member", resource=("team", "infrastructure"), subject=("user", "alice")
        )
        authz.grant(
            "member", resource=("team", "platform"), subject=("team", "infrastructure")
        )
        authz.grant(
            "member", resource=("team", "security"), subject=("team", "infrastructure")
        )
        authz.grant(
            "member", resource=("team", "engineering"), subject=("team", "platform")
        )
        authz.grant(
            "member", resource=("team", "engineering"), subject=("team", "security")
        )

        authz.grant("admin", resource=("repo", "api"), subject=("team", "engineering"))

        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True


class TestCycleDetection:
    """Test cycle detection in nested teams."""

    def test_self_membership_prevented(self, authz):
        """Cannot add a group as member of itself."""
        with pytest.raises(AuthzCycleError):
            authz.grant("member", resource=("team", "a"), subject=("team", "a"))

    def test_direct_cycle_prevented(self, authz):
        """Cannot create A in B in A cycle."""
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))

        with pytest.raises(AuthzCycleError):
            authz.grant("member", resource=("team", "a"), subject=("team", "b"))

    def test_indirect_cycle_prevented(self, authz):
        """Cannot create A in B in C in A cycle."""
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "b"))

        with pytest.raises(AuthzCycleError):
            authz.grant("member", resource=("team", "a"), subject=("team", "c"))

    def test_long_cycle_prevented(self, authz):
        """Cannot create cycle through long chain."""
        # a in b in c in d in e
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "b"))
        authz.grant("member", resource=("team", "d"), subject=("team", "c"))
        authz.grant("member", resource=("team", "e"), subject=("team", "d"))

        # Try to add e in a (would create cycle)
        with pytest.raises(AuthzCycleError):
            authz.grant("member", resource=("team", "a"), subject=("team", "e"))

    def test_valid_dag_allowed(self, authz):
        """Valid DAG structures (no cycles) are allowed."""
        # Diamond pattern is valid
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "a"))
        authz.grant("member", resource=("team", "d"), subject=("team", "b"))
        authz.grant("member", resource=("team", "d"), subject=("team", "c"))

        # This should succeed - no cycle
        authz.grant("member", resource=("team", "a"), subject=("user", "alice"))
        authz.grant("admin", resource=("repo", "api"), subject=("team", "d"))

        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True


class TestNestedTeamsWithHierarchy:
    """Test nested teams combined with permission hierarchy."""

    def test_hierarchy_applies_through_nesting(self, authz):
        """Permission hierarchy works with nested teams."""
        authz.set_hierarchy("repo", "admin", "write", "read")

        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("team", "infra"))
        authz.grant("admin", resource=("repo", "api"), subject=("team", "platform"))

        # alice should have all permissions via: infra in platform -> admin -> write -> read
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True
        assert authz.check(("user", "alice"), "write", ("repo", "api")) is True
        assert authz.check(("user", "alice"), "read", ("repo", "api")) is True

    def test_multiple_hierarchy_levels(self, authz):
        """Deep permission hierarchy with nested teams."""
        authz.set_hierarchy("repo", "owner", "admin", "write", "read")

        authz.grant("member", resource=("team", "a"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "b"))
        authz.grant("owner", resource=("repo", "api"), subject=("team", "c"))

        # alice has all permissions
        assert authz.check(("user", "alice"), "owner", ("repo", "api")) is True
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True
        assert authz.check(("user", "alice"), "write", ("repo", "api")) is True
        assert authz.check(("user", "alice"), "read", ("repo", "api")) is True


class TestNestedTeamsWithExpiration:
    """Test nested teams combined with expiration."""

    def test_expired_membership_in_chain_blocks_access(self, authz, db_connection):
        """Expired membership anywhere in chain blocks access."""
        cursor = db_connection.cursor()

        # alice in infra (not expired)
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))

        # infra in platform (expired) - bypass validation
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'team', 'platform', 'member', 'team', 'infra', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )

        # platform has admin
        authz.grant("admin", resource=("repo", "api"), subject=("team", "platform"))

        # alice should NOT have access (chain is broken)
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is False

    def test_unexpired_chain_works(self, authz):
        """Access works when entire chain is unexpired."""
        future = datetime.now(timezone.utc) + timedelta(days=7)

        authz.grant(
            "member",
            resource=("team", "infra"),
            subject=("user", "alice"),
            expires_at=future,
        )
        authz.grant(
            "member",
            resource=("team", "platform"),
            subject=("team", "infra"),
            expires_at=future,
        )
        authz.grant(
            "admin",
            resource=("repo", "api"),
            subject=("team", "platform"),
            expires_at=future,
        )

        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True

    def test_alternate_unexpired_path_works(self, authz, db_connection):
        """Access works if at least one path is fully unexpired."""
        cursor = db_connection.cursor()
        future = datetime.now(timezone.utc) + timedelta(days=7)

        # alice in infra and security
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "security"), subject=("user", "alice"))

        # infra -> platform (expired)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'team', 'platform', 'member', 'team', 'infra', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )

        # security -> platform (not expired)
        authz.grant(
            "member",
            resource=("team", "platform"),
            subject=("team", "security"),
            expires_at=future,
        )

        # platform has admin
        authz.grant("admin", resource=("repo", "api"), subject=("team", "platform"))

        # alice can access via security path
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True


class TestListWithNestedTeams:
    """Test list functions with nested teams."""

    def test_list_subjects_includes_nested_members(self, authz):
        """list_subjects returns subjects from all nested teams."""
        # alice in infra in platform
        # bob directly in platform
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("team", "infra"))
        authz.grant("member", resource=("team", "platform"), subject=("user", "bob"))

        authz.grant("read", resource=("doc", "1"), subject=("team", "platform"))

        subjects = authz.list_subjects("read", ("doc", "1"))

        assert ("user", "alice") in subjects
        assert ("user", "bob") in subjects

    def test_list_subjects_deep_nesting(self, authz):
        """list_subjects works with deeply nested teams."""
        # alice in a in b in c
        authz.grant("member", resource=("team", "a"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "b"), subject=("team", "a"))
        authz.grant("member", resource=("team", "c"), subject=("team", "b"))

        authz.grant("read", resource=("doc", "1"), subject=("team", "c"))

        subjects = authz.list_subjects("read", ("doc", "1"))
        assert ("user", "alice") in subjects

    def test_list_resources_via_nested_teams(self, authz):
        """list_resources returns resources accessible via nested teams."""
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("team", "infra"))

        # Direct grant to infra
        authz.grant("read", resource=("doc", "1"), subject=("team", "infra"))
        # Grant to platform (alice gets via nesting)
        authz.grant("read", resource=("doc", "2"), subject=("team", "platform"))

        resources = authz.list_resources(("user", "alice"), "doc", "read")

        assert "1" in resources
        assert "2" in resources

    def test_filter_authorized_with_nested_teams(self, authz):
        """filter_authorized works with nested team access."""
        authz.grant("member", resource=("team", "infra"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "platform"), subject=("team", "infra"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "platform"))
        authz.grant("read", resource=("doc", "3"), subject=("team", "infra"))

        authorized = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3", "4"]
        )

        assert "1" in authorized  # via platform
        assert "2" not in authorized  # no grant
        assert "3" in authorized  # direct to infra
        assert "4" not in authorized  # no grant


class TestSubjectRelationWithNestedTeams:
    """Test subject_relation handling with nested teams."""

    def test_subject_relation_respected(self, authz):
        """Grant to team#admin only applies to users with admin relation."""
        # alice is admin of team
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))
        # bob is member of team
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Grant to team#admin (only admins)
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        # alice (admin) can write
        assert authz.check(("user", "alice"), "write", ("repo", "api")) is True
        # bob (member) cannot write
        assert authz.check(("user", "bob"), "write", ("repo", "api")) is False

    def test_null_subject_relation_matches_all(self, authz):
        """Grant without subject_relation matches any relation."""
        authz.grant("admin", resource=("team", "eng"), subject=("user", "alice"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "bob"))

        # Grant without subject_relation
        authz.grant("read", resource=("repo", "api"), subject=("team", "eng"))

        # Both can read
        assert authz.check(("user", "alice"), "read", ("repo", "api")) is True
        assert authz.check(("user", "bob"), "read", ("repo", "api")) is True
