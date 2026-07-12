"""Namespace isolation across every read surface."""

import pytest
from postkit.memory import MemoryError, MemoryErrorCode

from tests.helpers import assert_global_row_delete_protected


def _seed_graph(client, ep_content, fact_content, entity_content):
    """Record an episode, consolidate a fact linked to an entity, return ids."""
    ep = client.record("s1", "user", ep_content, keywords=ep_content.split())
    result = client.consolidate(
        [
            {"content": fact_content},
            {"content": entity_content, "kind": "entity"},
        ],
        [{"from": "n0", "to": "n1", "relation": "entity"}],
        source_episodes=[ep],
    )
    return ep, result["node_ids"]


class TestNamespaceIsolation:
    def test_recall_is_isolated(self, make_memory):
        a = make_memory("tenant_a")
        b = make_memory("tenant_b")
        a.record("s1", "user", "alice likes hiking", keywords=["hiking"])

        assert a.recall(keywords=["hiking"])
        assert b.recall(keywords=["hiking"]) == []

    def test_stats_and_lists_are_isolated(self, make_memory):
        a = make_memory("tenant_a")
        b = make_memory("tenant_b")
        _seed_graph(a, "bob has a dog named Rex", "Bob owns a dog", "Rex")

        a_stats = a.get_stats()
        assert a_stats["total_episodes"] == 1
        assert a_stats["total_nodes"] == 2
        assert a_stats["total_edges"] == 1

        b_stats = b.get_stats()
        assert b_stats["total_episodes"] == 0
        assert b_stats["total_nodes"] == 0
        assert b_stats["total_edges"] == 0
        assert b.list_episodes() == []
        assert b.list_nodes() == []

    def test_recall_expansion_never_crosses_namespaces(self, make_memory):
        a = make_memory("tenant_a")
        b = make_memory("tenant_b")
        _seed_graph(a, "carol plays chess", "Carol plays chess", "Chess")
        _seed_graph(b, "dave plays chess", "Dave plays chess", "Chess")

        a_hits = {
            (h["source"], h["content"]) for h in a.recall(keywords=["chess"], hops=2)
        }
        assert ("node", "Carol plays chess") in a_hits
        assert all("Dave" not in content for _, content in a_hits)

    def test_neighbors_isolated_by_missing_node(self, make_memory):
        a = make_memory("tenant_a")
        b = make_memory("tenant_b")
        _, node_ids = _seed_graph(a, "erin sings", "Erin sings", "Song")

        assert a.neighbors(node_ids[0])
        with pytest.raises(MemoryError) as exc_info:
            b.neighbors(node_ids[0])
        assert exc_info.value.error_code == MemoryErrorCode.DATA_NODE_NOT_FOUND


class TestGlobalConfigRow:
    """The shared 'global' config defaults row is protected like the siblings'."""

    def test_global_config_row_delete_protected(self, db_connection):
        assert_global_row_delete_protected(db_connection, "memory", "memory.config")
