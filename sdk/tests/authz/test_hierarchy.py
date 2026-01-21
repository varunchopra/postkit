"""
Permission hierarchy tests for postkit/authz.

Tests for:
- Adding/removing hierarchy rules
- Hierarchy chains (admin -> write -> read)
- Dynamic hierarchy modifications with existing data
- Hierarchy rule cleanup
- Cycle detection
- Explain functionality
"""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authz import AuthzCycleError


class TestHierarchyModification:
    """Test hierarchy changes with existing data."""

    def test_adding_hierarchy_expands_existing_permissions(self, authz):
        """Adding hierarchy rule retroactively expands permissions."""
        # Grant admin WITHOUT hierarchy
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # No read access yet
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

        # Add hierarchy rule
        authz.add_hierarchy_rule("doc", "admin", "read")

        # Now alice should have read (hierarchy trigger handles this)
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_removing_hierarchy_contracts_permissions(self, authz):
        """Removing hierarchy rule retroactively removes implied permissions."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove the write->read implication
        authz.remove_hierarchy_rule("doc", "write", "read")

        # alice still has admin and write, but not read
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_hierarchy_change_affects_multiple_resources(self, authz):
        """Hierarchy change recomputes all affected resources."""
        # Setup: 20 docs, all with admin grants
        for i in range(20):
            authz.grant("admin", resource=("doc", str(i)), subject=("user", "alice"))

        # Verify no read access yet
        for i in range(20):
            assert not authz.check(("user", "alice"), "read", ("doc", str(i)))

        # Add hierarchy
        authz.add_hierarchy_rule("doc", "admin", "read")

        # All 20 should now have read
        for i in range(20):
            assert authz.check(("user", "alice"), "read", ("doc", str(i)))

    def test_hierarchy_chain_modification(self, authz):
        """Modifying middle of hierarchy chain updates correctly."""
        # admin -> write -> read
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # alice has all three
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert authz.check(("user", "alice"), "write", ("doc", "1"))
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        # Remove admin->write (breaks the chain)
        authz.remove_hierarchy_rule("doc", "admin", "write")

        # Now alice has admin but NOT write or read
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert not authz.check(("user", "alice"), "write", ("doc", "1"))
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_clear_hierarchy_removes_all_rules(self, authz):
        """clear_hierarchy removes all rules for a resource type."""
        authz.set_hierarchy("doc", "admin", "write", "read")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "read", ("doc", "1"))

        authz.clear_hierarchy("doc")

        # Only admin remains, implied permissions gone
        assert authz.check(("user", "alice"), "admin", ("doc", "1"))
        assert not authz.check(("user", "alice"), "write", ("doc", "1"))
        assert not authz.check(("user", "alice"), "read", ("doc", "1"))


class TestHierarchyCycle:
    """Hierarchy cycle prevention."""

    def test_direct_cycle_rejected(self, authz):
        """admin -> admin should be rejected."""
        with pytest.raises(AuthzCycleError) as exc_info:
            authz.add_hierarchy_rule("doc", "admin", "admin")
        assert exc_info.value.error_code == "BIZ_CYCLE_SELF"

    def test_indirect_cycle_rejected(self, authz):
        """admin -> write -> admin should be rejected."""
        authz.set_hierarchy("doc", "admin", "write")
        with pytest.raises(AuthzCycleError) as exc_info:
            authz.add_hierarchy_rule("doc", "write", "admin")
        assert exc_info.value.error_code == "BIZ_CYCLE_HIERARCHY"

    def test_branching_cycle_rejected(self, authz):
        """admin -> write, admin -> read, read -> admin should be rejected."""
        authz.add_hierarchy_rule("doc", "admin", "write")
        authz.add_hierarchy_rule("doc", "admin", "read")
        with pytest.raises(AuthzCycleError) as exc_info:
            authz.add_hierarchy_rule("doc", "read", "admin")
        assert exc_info.value.error_code == "BIZ_CYCLE_HIERARCHY"

    def test_cross_namespace_cycle_rejected(self, make_authz):
        """Cycle via global hierarchy should be rejected.

        If global has admin -> write -> read, a tenant adding read -> admin
        should be rejected because it creates a cross-namespace cycle.
        """
        global_authz = make_authz("global")
        global_authz.set_hierarchy("doc", "admin", "write", "read")

        tenant = make_authz("cycle_test_tenant")
        with pytest.raises(AuthzCycleError) as exc_info:
            tenant.add_hierarchy_rule("doc", "read", "admin")
        assert exc_info.value.error_code == "BIZ_CYCLE_HIERARCHY"


class TestHierarchyEdgeCases:
    """Edge cases in permission hierarchies."""

    def test_deep_hierarchy_chain(self, authz):
        """Long hierarchy chain works correctly."""
        levels = [f"level{i}" for i in range(1, 11)]
        for i in range(len(levels) - 1):
            authz.add_hierarchy_rule("doc", levels[i], levels[i + 1])

        authz.grant(levels[0], resource=("doc", "1"), subject=("user", "alice"))

        for level in levels:
            assert authz.check(("user", "alice"), level, ("doc", "1"))

    def test_wide_hierarchy_branches(self, authz):
        """Permission implying many others."""
        implied = ["read", "write", "delete", "share", "comment"]
        for perm in implied:
            authz.add_hierarchy_rule("doc", "admin", perm)

        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        for perm in ["admin"] + implied:
            assert authz.check(("user", "alice"), perm, ("doc", "1"))


class TestExplainEdgeCases:
    """Edge cases in explain functionality."""

    def test_explain_multiple_paths(self, authz):
        """explain() returns all paths when multiple exist."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))
        authz.grant("member", resource=("team", "eng"), subject=("user", "alice"))

        explanations = authz.explain(("user", "alice"), "read", ("doc", "1"))

        assert len(explanations) == 2
        assert any("DIRECT" in e for e in explanations)
        assert any("GROUP" in e for e in explanations)

    def test_explain_deep_hierarchy(self, authz):
        """explain() shows full hierarchy chain."""
        authz.set_hierarchy("doc", "owner", "admin", "write", "read")
        authz.grant("owner", resource=("doc", "1"), subject=("user", "alice"))

        explanations = authz.explain(("user", "alice"), "read", ("doc", "1"))

        assert any("owner -> admin -> write -> read" in e for e in explanations)


class TestGlobalHierarchy:
    """Tests for global (cross-namespace) permission hierarchies."""

    def test_global_hierarchy_applies_across_namespaces(
        self, make_authz, db_connection
    ):
        """Hierarchy in 'global' namespace applies to all tenants."""
        # Set global hierarchy via SQL (schema belongs in migrations, not SDK)
        with db_connection.cursor() as cur:
            cur.execute("SELECT authz.add_hierarchy('doc', 'admin', 'view', 'global')")

        authz = make_authz("gh_tenant_a")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        assert authz.check(("user", "alice"), "view", ("doc", "1"))
        # Cleanup handled by cleanup_global_hierarchies fixture

    def test_tenant_hierarchy_is_isolated(self, make_authz, db_connection):
        """Tenant-specific hierarchies only apply to that tenant."""
        # Add hierarchy via SDK - goes to tenant namespace
        authz = make_authz("gh_tenant_b")
        authz.add_hierarchy_rule("doc", "admin", "edit")
        authz.add_hierarchy_rule("doc", "admin", "view")
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        # Implied permissions work for this tenant
        assert authz.check(("user", "alice"), "view", ("doc", "1"))
        assert authz.check(("user", "alice"), "edit", ("doc", "1"))

        # Different tenant does NOT see the tenant-specific hierarchy
        authz2 = make_authz("gh_tenant_c")
        authz2.grant("admin", resource=("doc", "2"), subject=("user", "bob"))
        # Bob has admin but NOT view (no hierarchy in this tenant)
        assert authz2.check(("user", "bob"), "admin", ("doc", "2"))
        assert not authz2.check(("user", "bob"), "view", ("doc", "2"))

    def test_global_hierarchy_via_global_namespace(self, make_authz, db_connection):
        """Hierarchies in 'global' namespace apply to all tenants."""
        # Add hierarchy to global namespace
        global_authz = make_authz("global")
        global_authz.add_hierarchy_rule("doc", "superadmin", "viewer")

        # Both tenants should see the global hierarchy
        authz1 = make_authz("gh_tenant_d")
        authz1.grant("superadmin", resource=("doc", "1"), subject=("user", "alice"))
        assert authz1.check(("user", "alice"), "viewer", ("doc", "1"))

        authz2 = make_authz("gh_tenant_e")
        authz2.grant("superadmin", resource=("doc", "2"), subject=("user", "bob"))
        assert authz2.check(("user", "bob"), "viewer", ("doc", "2"))

    def test_global_hierarchy_in_list_resources(self, make_authz):
        """list_resources finds resources via global hierarchy."""
        make_authz("global").set_hierarchy("note", "owner", "edit", "view")

        acme = make_authz("acme")
        acme.grant("owner", resource=("note", "n1"), subject=("user", "alice"))

        # owner→edit→view means alice can list notes she can 'view'
        assert "n1" in acme.list_resources(("user", "alice"), "note", "view")

    def test_global_hierarchy_in_list_subjects(self, make_authz):
        """list_subjects finds subjects via global hierarchy."""
        make_authz("global").set_hierarchy("note", "owner", "edit", "view")

        acme = make_authz("acme")
        acme.grant("owner", resource=("note", "n1"), subject=("user", "alice"))

        # owner→edit→view means alice appears when listing 'view' subjects
        assert ("user", "alice") in acme.list_subjects("view", ("note", "n1"))

    def test_global_hierarchy_in_filter_authorized(self, make_authz):
        """filter_authorized respects global hierarchy."""
        make_authz("global").set_hierarchy("note", "owner", "edit", "view")

        acme = make_authz("acme")
        acme.grant("owner", resource=("note", "n1"), subject=("user", "alice"))

        # owner→edit→view means n1 passes 'view' filter
        result = acme.filter_authorized(
            ("user", "alice"), "note", "view", ["n1", "n2", "n3"]
        )
        assert result == ["n1"]

    def test_global_hierarchy_in_explain(self, make_authz):
        """explain traces paths through global hierarchy."""
        make_authz("global").set_hierarchy("note", "owner", "edit", "view")

        acme = make_authz("acme")
        acme.grant("owner", resource=("note", "n1"), subject=("user", "alice"))

        paths = acme.explain(("user", "alice"), "view", ("note", "n1"))
        assert any("owner" in p and "view" in p for p in paths)


class TestExternalResources:
    """Tests for cross-namespace sharing."""

    def test_returns_grants_from_other_namespaces(self, make_authz):
        authz_a = make_authz("swm_org_a")
        authz_a.grant("view", resource=("note", "1"), subject=("user", "alice"))

        authz_b = make_authz("swm_org_b")
        shared = authz_b.list_external_resources(("user", "alice"), "note", "view")

        assert len(shared) == 1
        assert shared[0]["namespace"] == "swm_org_a"
        assert shared[0]["resource_id"] == "1"

    def test_excludes_current_namespace(self, make_authz):
        authz = make_authz("swm_org_c")
        authz.grant("view", resource=("note", "1"), subject=("user", "alice"))

        shared = authz.list_external_resources(("user", "alice"), "note", "view")
        assert shared == []

    def test_applies_global_hierarchy(self, make_authz, db_connection):
        with db_connection.cursor() as cur:
            cur.execute("SELECT authz.add_hierarchy('note', 'edit', 'view', 'global')")

        authz_a = make_authz("swm_org_d")
        authz_a.grant("edit", resource=("note", "1"), subject=("user", "alice"))

        authz_b = make_authz("swm_org_e")
        shared = authz_b.list_external_resources(("user", "alice"), "note", "view")

        assert len(shared) == 1
        assert shared[0]["relation"] == "edit"
        # Cleanup handled by cleanup_global_hierarchies fixture

    def test_filters_expired(self, make_authz, db_connection):
        cursor = db_connection.cursor()

        # Insert expired tuple directly (bypass SDK validation)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES ('swm_org_f', 'note', 'expired', 'view', 'user', 'alice', now() - interval '1 hour')
        """
        )

        # Grant valid permission via SDK
        authz_a = make_authz("swm_org_f")
        future = datetime.now(timezone.utc) + timedelta(days=1)
        authz_a.grant(
            "view",
            resource=("note", "valid"),
            subject=("user", "alice"),
            expires_at=future,
        )

        authz_b = make_authz("swm_org_g")
        shared = authz_b.list_external_resources(("user", "alice"), "note", "view")

        assert len(shared) == 1
        assert shared[0]["resource_id"] == "valid"
