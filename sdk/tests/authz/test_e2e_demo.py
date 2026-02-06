"""
End-to-End Demo: Central Permissions Service for an Internal Developer Platform

This test demonstrates two things:

1. The postkit/authz SDK (AuthzClient) - the generic, tuple-based API
2. Domain-specific helpers (AcmeAuthz) - how customers layer their own abstractions

SCENARIO: Acme Corp
===================
Acme uses postkit/authz as their central authorization service across all internal
tools: repos, services, secrets, and incident management.

Rather than each tool managing its own permissions, they all ask one question:

    "Can user X do action Y on object Z?"

The answer comes from postkit/authz, which knows about team memberships, permission
hierarchies, and direct grants.
"""

from postkit.authz import AuthzClient

# Domain-specific helpers - how customers wrap the generic SDK with their
# own domain language. The SDK deals in tuples; this layer deals in teams,
# repos, and services.


class AcmeAuthz:
    """
    Acme's domain-specific authorization helpers.

    Built on top of AuthzClient, this provides Acme-specific conveniences
    like add_to_team() and team_owns(). Every company would build their
    own version of this.
    """

    def __init__(self, client: AuthzClient):
        self.client = client

    def add_to_team(self, user: str, team: str):
        """Add a user to a team."""
        self.client.grant("member", resource=("team", team), subject=("user", user))

    def team_owns(self, team: str, resource: tuple, permission: str = "admin"):
        """Grant a team ownership (or other permission) on a resource."""
        self.client.grant(permission, resource=resource, subject=("team", team))


class TestInternalDevPlatform:
    """
    Acme Corp's internal developer platform uses postkit/authz as a
    central permissions service.
    """

    def test_central_permissions_service(self, authz: AuthzClient):
        """
        Full workflow demonstrating postkit/authz as a central permissions service.

        Shows both the generic SDK (authz) and domain helpers (acme).
        """
        # Wrap the SDK with Acme's domain helpers
        acme = AcmeAuthz(authz)

        # 1. Setup: Permission hierarchy
        # Acme uses the same hierarchy across all resource types:
        # admin -> write -> read
        # If you have "admin", you automatically have "write" and "read".
        for resource_type in ["repo", "service", "secret", "incident"]:
            authz.set_hierarchy(resource_type, "admin", "write", "read")

        # 2. Team structure
        # The payments team owns their repo and service.
        # They can read (but not write) their secrets.

        acme.team_owns("payments-eng", ("repo", "payments-api"))
        acme.team_owns("payments-eng", ("service", "payments"))
        acme.team_owns("payments-eng", ("secret", "stripe-key"), permission="read")

        # Alice and Bob are on the payments team
        acme.add_to_team("alice", "payments-eng")
        acme.add_to_team("bob", "payments-eng")

        # 3. Team-based access
        # Alice and Bob automatically have access to everything their team owns.

        # Alice can write (team has admin -> admin implies write)
        assert authz.check(("user", "alice"), "write", ("repo", "payments-api"))

        # Alice can read (admin -> write -> read)
        assert authz.check(("user", "alice"), "read", ("repo", "payments-api"))

        # Alice can read the secret (team has read)
        assert authz.check(("user", "alice"), "read", ("secret", "stripe-key"))

        # Alice cannot write to secret (team only has read)
        assert not authz.check(("user", "alice"), "write", ("secret", "stripe-key"))

        # Charlie is not on the team - no access
        assert not authz.check(("user", "charlie"), "read", ("repo", "payments-api"))

        # 4. Explain: Why does alice have access?
        # Auditing and debugging: trace the permission path.
        explanations = authz.explain(
            ("user", "alice"), "write", ("repo", "payments-api")
        )

        assert len(explanations) == 1
        assert any("HIERARCHY" in exp for exp in explanations)

        # 5. Dynamic grant: On-call incident access
        # It's 3am. Incident! Alice is on-call and needs write access.
        # This is a direct grant, not via team.
        assert (
            authz.grant(
                "write", resource=("incident", "inc-123"), subject=("user", "alice")
            )
            > 0
        )

        assert authz.check(("user", "alice"), "write", ("incident", "inc-123"))
        assert not authz.check(("user", "bob"), "write", ("incident", "inc-123"))

        # 6. Contractor access
        # Charlie is a contractor who needs to review the code.
        # Direct grant, not team membership.
        assert (
            authz.grant(
                "read", resource=("repo", "payments-api"), subject=("user", "charlie")
            )
            > 0
        )

        assert authz.check(("user", "charlie"), "read", ("repo", "payments-api"))
        assert not authz.check(("user", "charlie"), "write", ("repo", "payments-api"))

        # 7. List operations
        # Security review: who has access? what can someone access?
        subjects = authz.list_subjects("read", ("repo", "payments-api"))
        assert len(subjects) == 3
        assert ("user", "alice") in subjects
        assert ("user", "bob") in subjects
        assert ("user", "charlie") in subjects

        repos = authz.list_resources(("user", "alice"), "repo", "read")
        assert len(repos) == 1
        assert "payments-api" in repos

        # 8. Revoke
        # Incident resolved. Contractor done. Clean up access.
        assert authz.revoke(
            "write", resource=("incident", "inc-123"), subject=("user", "alice")
        )
        assert not authz.check(("user", "alice"), "write", ("incident", "inc-123"))

        assert authz.revoke(
            "read", resource=("repo", "payments-api"), subject=("user", "charlie")
        )
        assert not authz.check(("user", "charlie"), "read", ("repo", "payments-api"))

        # Team access unchanged
        assert authz.check(("user", "alice"), "read", ("repo", "payments-api"))
        assert authz.check(("user", "bob"), "read", ("repo", "payments-api"))
