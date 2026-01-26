"""Tests for multi-tenancy isolation."""


class TestNamespaceIsolation:
    """Tests for namespace/tenant isolation."""

    def test_different_namespaces_isolated(self, make_config):
        """Config entries in different namespaces are isolated."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        # Each tenant sets same key
        tenant_a.set("prompts/bot", {"owner": "a"})
        tenant_b.set("prompts/bot", {"owner": "b"})

        # Each sees only their own
        assert tenant_a.get_value("prompts/bot")["owner"] == "a"
        assert tenant_b.get_value("prompts/bot")["owner"] == "b"

    def test_list_only_shows_own_namespace(self, make_config):
        """list_entries() only returns entries from own namespace."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        tenant_a.set("prompts/a1", {"v": 1})
        tenant_a.set("prompts/a2", {"v": 2})
        tenant_b.set("prompts/b1", {"v": 1})

        a_keys = [e["key"] for e in tenant_a.list_entries()]
        b_keys = [e["key"] for e in tenant_b.list_entries()]

        assert "prompts/a1" in a_keys
        assert "prompts/a2" in a_keys
        assert "prompts/b1" not in a_keys

        assert "prompts/b1" in b_keys
        assert "prompts/a1" not in b_keys

    def test_delete_only_affects_own_namespace(self, make_config):
        """delete() only affects entries in own namespace."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        tenant_a.set("prompts/shared", {"owner": "a"})
        tenant_b.set("prompts/shared", {"owner": "b"})

        # Delete from tenant_a
        tenant_a.delete("prompts/shared")

        # tenant_b still has their copy
        assert tenant_b.get_value("prompts/shared")["owner"] == "b"

    def test_stats_scoped_to_namespace(self, make_config):
        """get_stats() is scoped to namespace."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        tenant_a.set("prompts/a1", {"v": 1})
        tenant_a.set("prompts/a2", {"v": 2})
        tenant_b.set("prompts/b1", {"v": 1})

        a_stats = tenant_a.get_stats()
        b_stats = tenant_b.get_stats()

        assert a_stats["total_keys"] == 2
        assert b_stats["total_keys"] == 1

    def test_history_scoped_to_namespace(self, make_config):
        """history() only shows versions from own namespace."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        tenant_a.set("prompts/shared", {"owner": "a", "v": 1})
        tenant_a.set("prompts/shared", {"owner": "a", "v": 2})
        tenant_b.set("prompts/shared", {"owner": "b"})

        a_history = tenant_a.history("prompts/shared")
        b_history = tenant_b.history("prompts/shared")

        assert len(a_history) == 2
        assert len(b_history) == 1
