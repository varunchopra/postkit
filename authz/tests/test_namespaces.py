"""
Namespace isolation tests for postkit/authz.

Verifies that namespaces provide complete multi-tenant isolation:
- Permissions in one namespace are not visible in another
- Hierarchy rules are namespace-scoped
- Group memberships are namespace-scoped
"""

import pytest
from authz_sdk import AuthzClient


class TestNamespaceIsolation:
    """Verify namespaces are completely isolated."""

    def test_permission_in_one_namespace_not_visible_in_another(
        self, authz, make_authz
    ):
        """Permission granted in namespace A must not be visible in namespace B."""
        # Grant in default namespace (authz fixture)
        authz.grant("read", resource=("doc", "secret"), subject=("user", "alice"))

        # Create client for different namespace
        other_ns = make_authz("other_tenant")

        # Must not have access in other namespace
        assert not other_ns.check("alice", "read", ("doc", "secret"))

    def test_same_resource_different_permissions_per_namespace(self, make_authz):
        """Same resource ID can have different permissions in different namespaces."""
        tenant_a = make_authz("tenant_a")
        tenant_b = make_authz("tenant_b")

        tenant_a.grant("admin", resource=("doc", "1"), subject=("user", "alice"))
        tenant_b.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        assert tenant_a.check("alice", "admin", ("doc", "1"))
        assert not tenant_b.check("alice", "admin", ("doc", "1"))
        assert tenant_b.check("alice", "read", ("doc", "1"))

    def test_hierarchy_rules_namespace_scoped(self, make_authz):
        """Hierarchy rules in one namespace don't affect another."""
        tenant_a = make_authz("tenant_a_hier")
        tenant_b = make_authz("tenant_b_hier")

        # Only tenant_a has hierarchy
        tenant_a.set_hierarchy("doc", "admin", "read")

        tenant_a.grant("admin", resource=("doc", "1"), subject=("user", "alice"))
        tenant_b.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # tenant_a: admin implies read
        assert tenant_a.check("alice", "read", ("doc", "1"))
        # tenant_b: no hierarchy, so admin does NOT imply read
        assert not tenant_b.check("alice", "read", ("doc", "1"))

    def test_group_membership_namespace_scoped(self, make_authz):
        """Group membership in one namespace doesn't grant access in another."""
        tenant_a = make_authz("tenant_a_grp")
        tenant_b = make_authz("tenant_b_grp")

        # Setup in tenant_a: alice in team, team has read on doc
        tenant_a.grant("member", resource=("team", "eng"), subject=("user", "alice"))
        tenant_a.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        # Setup in tenant_b: same team has read, but alice NOT a member in this namespace
        tenant_b.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        # tenant_a: alice can read via team membership
        assert tenant_a.check("alice", "read", ("doc", "1"))
        # tenant_b: alice cannot read (not a member in this namespace)
        assert not tenant_b.check("alice", "read", ("doc", "1"))
