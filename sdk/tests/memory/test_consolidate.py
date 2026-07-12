"""consolidate() and consolidation_due(): distillation, dedup, replay (M3)."""

import pytest
from postkit.memory import MemoryError, MemoryErrorCode


class TestConsolidate:
    def test_facts_inserted_with_default_evidence(self, memory):
        e1 = memory.record("s1", "user", "one")
        e2 = memory.record("s1", "user", "two")
        result = memory.consolidate(
            [{"content": "a distilled fact"}], [], source_episodes=[e1, e2]
        )
        node_id = result["node_ids"][0]
        node = memory.get_node(node_id)
        assert sorted(node["evidence"]) == sorted([e1, e2])

    def test_explicit_evidence_overrides_default(self, memory):
        e1 = memory.record("s1", "user", "one")
        e2 = memory.record("s1", "user", "two")
        result = memory.consolidate(
            [{"content": "fact", "evidence": [e1]}], [], source_episodes=[e1, e2]
        )
        assert memory.get_node(result["node_ids"][0])["evidence"] == [e1]

    def test_n_ref_edges_resolve(self, memory):
        e1 = memory.record("s1", "user", "one")
        result = memory.consolidate(
            [{"content": "person"}, {"content": "hobby"}],
            [{"from": "n0", "to": "n1", "relation": "assoc"}],
            source_episodes=[e1],
        )
        a, b = result["node_ids"]
        neighbors = memory.neighbors(a)
        assert any(n["node_id"] == b and n["direction"] == "out" for n in neighbors)

    def test_existing_id_edge_refs_resolve(self, memory):
        e1 = memory.record("s1", "user", "one")
        first = memory.consolidate([{"content": "existing"}], [], source_episodes=[e1])
        existing_id = first["node_ids"][0]
        e2 = memory.record("s1", "user", "two")
        second = memory.consolidate(
            [{"content": "new"}],
            [{"from": "n0", "to": existing_id, "relation": "causal"}],
            source_episodes=[e2],
        )
        new_id = second["node_ids"][0]
        assert any(n["node_id"] == existing_id for n in memory.neighbors(new_id))

    def test_entity_dedup_reuses_id(self, memory):
        e1 = memory.record("s1", "user", "one")
        first = memory.consolidate(
            [{"content": "Narendra Modi", "kind": "entity"}], [], source_episodes=[e1]
        )
        e2 = memory.record("s1", "user", "two")
        second = memory.consolidate(
            [{"content": "Narendra Modi", "kind": "entity"}], [], source_episodes=[e2]
        )
        assert first["node_ids"][0] == second["node_ids"][0]
        entities = memory.list_nodes(kind="entity")
        assert len([n for n in entities if n["content"] == "Narendra Modi"]) == 1

    def test_episodes_marked_consolidated(self, memory):
        e1 = memory.record("s1", "user", "one")
        e2 = memory.record("s1", "user", "two")
        assert {r["id"] for r in memory.consolidation_due()} == {e1, e2}
        memory.consolidate([{"content": "fact"}], [], source_episodes=[e1, e2])
        assert memory.consolidation_due() == []

    def test_unknown_source_episode_rejected(self, memory):
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate([{"content": "fact"}], [], source_episodes=[999999])
        assert exc_info.value.error_code == MemoryErrorCode.DATA_EPISODE_NOT_FOUND

    def test_malformed_fact_rejected(self, memory):
        e1 = memory.record("s1", "user", "one")
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate([{"kind": "fact"}], [], source_episodes=[e1])
        assert exc_info.value.error_code == MemoryErrorCode.VAL_FACT_MALFORMED

    def test_out_of_range_fact_index_rejected(self, memory):
        e1 = memory.record("s1", "user", "one")
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate(
                [{"content": "only one fact"}],
                [{"from": "n0", "to": "n9", "relation": "assoc"}],  # n9 out of range
                source_episodes=[e1],
            )
        assert exc_info.value.error_code == MemoryErrorCode.VAL_EDGE_MALFORMED

    def test_edge_to_unknown_node_id_rejected(self, memory):
        e1 = memory.record("s1", "user", "one")
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate(
                [{"content": "a fact"}],
                [{"from": "n0", "to": 999999, "relation": "assoc"}],
                source_episodes=[e1],
            )
        assert exc_info.value.error_code == MemoryErrorCode.DATA_NODE_NOT_FOUND

    def test_fractional_edge_endpoint_rejected(self, memory):
        e1 = memory.record("s1", "user", "one")
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate(
                [{"content": "a fact"}],
                [{"from": 12.5, "to": "n0", "relation": "assoc"}],
                source_episodes=[e1],
            )
        assert exc_info.value.error_code == MemoryErrorCode.VAL_EDGE_MALFORMED

    def test_overflowing_fact_index_rejected(self, memory):
        e1 = memory.record("s1", "user", "one")
        with pytest.raises(MemoryError) as exc_info:
            memory.consolidate(
                [{"content": "a fact"}],
                [{"from": "n99999999999", "to": "n0", "relation": "assoc"}],
                source_episodes=[e1],
            )
        assert exc_info.value.error_code == MemoryErrorCode.VAL_EDGE_MALFORMED


class TestM3Idempotency:
    def test_replay_same_key_is_skipped(self, memory):
        e1 = memory.record("s1", "user", "one")
        first = memory.consolidate(
            [{"content": "fact"}],
            [],
            source_episodes=[e1],
            idempotency_key="job-1",
        )
        assert first["skipped"] is False

        before = memory.get_stats()
        second = memory.consolidate(
            [{"content": "should not be inserted"}],
            [],
            source_episodes=[e1],
            idempotency_key="job-1",
        )
        assert second["skipped"] is True
        assert second["node_ids"] == []
        after = memory.get_stats()
        assert before["total_nodes"] == after["total_nodes"]
