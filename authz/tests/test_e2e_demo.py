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

from authz_sdk import AuthzClient


# =============================================================================
# Layer 2: Domain-specific helpers (what customers build)
# =============================================================================
# This is how a company like Acme would wrap the generic SDK with their
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

    def remove_from_team(self, user: str, team: str):
        """Remove a user from a team."""
        self.client.revoke("member", resource=("team", team), subject=("user", user))

    def team_owns(self, team: str, resource: tuple, permission: str = "admin"):
        """Grant a team ownership (or other permission) on a resource."""
        self.client.grant(permission, resource=resource, subject=("team", team))


# =============================================================================
# The Test
# =============================================================================


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

        # =================================================================
        # 1. SETUP: Permission hierarchy
        # =================================================================
        # Acme uses the same hierarchy across all resource types:
        #   admin -> write -> read
        #
        # If you have "admin", you automatically have "write" and "read".

        for resource_type in ["repo", "service", "secret", "incident"]:
            authz.set_hierarchy(resource_type, "admin", "write", "read")

        # =================================================================
        # 2. TEAM STRUCTURE
        # =================================================================
        # The payments team owns their repo and service.
        # They can read (but not write) their secrets.

        acme.team_owns("payments-eng", ("repo", "payments-api"))
        acme.team_owns("payments-eng", ("service", "payments"))
        acme.team_owns("payments-eng", ("secret", "stripe-key"), permission="read")

        # Alice and Bob are on the payments team
        acme.add_to_team("alice", "payments-eng")
        acme.add_to_team("bob", "payments-eng")

        # =================================================================
        # 3. TEAM-BASED ACCESS
        # =================================================================
        # Alice and Bob automatically have access to everything their team owns.

        # Alice can write (team has admin -> admin implies write)
        assert authz.check("alice", "write", ("repo", "payments-api"))

        # Alice can read (admin -> write -> read)
        assert authz.check("alice", "read", ("repo", "payments-api"))

        # Alice can read the secret (team has read)
        assert authz.check("alice", "read", ("secret", "stripe-key"))

        # Alice cannot write to secret (team only has read)
        assert not authz.check("alice", "write", ("secret", "stripe-key"))

        # Charlie is not on the team - no access
        assert not authz.check("charlie", "read", ("repo", "payments-api"))

        # =================================================================
        # 4. EXPLAIN: Why does alice have access?
        # =================================================================
        # Auditing and debugging: trace the permission path.

        explanations = authz.explain("alice", "write", ("repo", "payments-api"))

        assert len(explanations) > 0
        assert any("HIERARCHY" in exp for exp in explanations)

        # =================================================================
        # 5. DYNAMIC GRANT: On-call incident access
        # =================================================================
        # It's 3am. Incident! Alice is on-call and needs write access.
        # This is a direct grant, not via team.

        authz.grant(
            "write", resource=("incident", "inc-123"), subject=("user", "alice")
        )

        assert authz.check("alice", "write", ("incident", "inc-123"))
        assert not authz.check("bob", "write", ("incident", "inc-123"))

        # =================================================================
        # 6. CONTRACTOR ACCESS
        # =================================================================
        # Charlie is a contractor who needs to review the code.
        # Direct grant, not team membership.

        authz.grant(
            "read", resource=("repo", "payments-api"), subject=("user", "charlie")
        )

        assert authz.check("charlie", "read", ("repo", "payments-api"))
        assert not authz.check("charlie", "write", ("repo", "payments-api"))

        # =================================================================
        # 7. LIST OPERATIONS
        # =================================================================
        # Security review: who has access? what can someone access?

        users = authz.list_users("read", ("repo", "payments-api"))
        assert "alice" in users
        assert "bob" in users
        assert "charlie" in users

        repos = authz.list_resources("alice", "repo", "read")
        assert "payments-api" in repos

        # =================================================================
        # 8. REVOKE
        # =================================================================
        # Incident resolved. Contractor done. Clean up access.

        authz.revoke(
            "write", resource=("incident", "inc-123"), subject=("user", "alice")
        )
        assert not authz.check("alice", "write", ("incident", "inc-123"))

        authz.revoke(
            "read", resource=("repo", "payments-api"), subject=("user", "charlie")
        )
        assert not authz.check("charlie", "read", ("repo", "payments-api"))

        # Team access unchanged
        assert authz.check("alice", "read", ("repo", "payments-api"))
        assert authz.check("bob", "read", ("repo", "payments-api"))
