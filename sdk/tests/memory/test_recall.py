"""recall(): fusion, recency, graph expansion, and visibility."""

from datetime import datetime, timedelta, timezone

import pytest

EMBED = "test-model"


class TestVectorRecall:
    def test_nearest_by_cosine_ranks_first(self, memory):
        memory.record(
            "s1", "user", "about apples", embedding=[1, 0, 0, 0], embed_model=EMBED
        )
        memory.record(
            "s1", "user", "about oranges", embedding=[0, 1, 0, 0], embed_model=EMBED
        )

        hits = memory.recall(query_embedding=[0.9, 0.1, 0, 0])
        assert hits[0]["content"] == "about apples"


class TestLexicalRecall:
    def test_keyword_recall_finds_match(self, memory):
        memory.record("s1", "user", "my apartment has hard water", keywords=["water"])
        memory.record("s1", "user", "the weather is cold", keywords=["weather"])

        hits = memory.recall(keywords=["water"])
        contents = [h["content"] for h in hits]
        assert "my apartment has hard water" in contents
        assert "the weather is cold" not in contents

    def test_ts_rank_beats_unrelated(self, memory):
        memory.record("s1", "user", "the monsoon arrived early this year", keywords=[])
        memory.record("s1", "user", "a report about quarterly revenue", keywords=[])

        hits = memory.recall(keywords=["monsoon"])
        assert hits[0]["content"] == "the monsoon arrived early this year"


class TestRecencyDecay:
    def test_newer_ranks_first_at_equal_similarity(self, memory):
        # occurred_at is immutable (M1), so it is set at record time. Two
        # episodes with identical embeddings differ only in age.
        long_ago = datetime.now(timezone.utc) - timedelta(days=120)
        memory.record(
            "s1",
            "user",
            "old note",
            embedding=[1, 0, 0, 0],
            embed_model=EMBED,
            occurred_at=long_ago,
        )
        memory.record(
            "s1", "user", "new note", embedding=[1, 0, 0, 0], embed_model=EMBED
        )

        hits = memory.recall(query_embedding=[1, 0, 0, 0])
        assert hits[0]["content"] == "new note"

    def test_score_halves_at_one_halflife(self, memory):
        """Two records with identical content and keywords differ only in age,
        so their score ratio isolates recency decay: 0.5 at the 30-day default."""
        halflife_ago = datetime.now(timezone.utc) - timedelta(days=30)
        fresh = memory.record("s1", "user", "team offsite plan", keywords=["offsite"])
        aged = memory.record(
            "s1",
            "user",
            "team offsite plan",
            keywords=["offsite"],
            occurred_at=halflife_ago,
        )

        scores = {h["id"]: h["score"] for h in memory.recall(keywords=["offsite"])}
        assert scores[aged] / scores[fresh] == pytest.approx(0.5, rel=0.02)


class TestGraphExpansion:
    def _chain(self, memory):
        """n0 (has embedding) -> n1 -> n2, so n2 is two hops from the entry."""
        ep = memory.record(
            "s1", "user", "seed", embedding=[1, 0, 0, 0], embed_model=EMBED
        )
        result = memory.consolidate(
            [
                {
                    "content": "root fact",
                    "embedding": [1, 0, 0, 0],
                    "embed_model": EMBED,
                },
                {"content": "one hop away"},
                {"content": "two hops away"},
            ],
            [
                {"from": "n0", "to": "n1", "relation": "assoc"},
                {"from": "n1", "to": "n2", "relation": "assoc"},
            ],
            source_episodes=[ep],
        )
        return result["node_ids"]

    def test_hops_zero_returns_entry_only(self, memory):
        self._chain(memory)
        hits = memory.recall(query_embedding=[1, 0, 0, 0], hops=0)
        node_contents = {h["content"] for h in hits if h["source"] == "node"}
        assert node_contents == {"root fact"}

    def test_hops_one_reaches_one_edge(self, memory):
        self._chain(memory)
        hits = memory.recall(query_embedding=[1, 0, 0, 0], hops=1)
        node_contents = {h["content"] for h in hits if h["source"] == "node"}
        assert "one hop away" in node_contents
        assert "two hops away" not in node_contents

    def test_hops_two_reaches_two_edges(self, memory):
        self._chain(memory)
        hits = memory.recall(query_embedding=[1, 0, 0, 0], hops=2)
        node_contents = {h["content"] for h in hits if h["source"] == "node"}
        assert "two hops away" in node_contents

    def test_recall_max_nodes_cap_honored(self, memory, test_helpers):
        test_helpers.set_config(recall_max_nodes=2)
        ep = memory.record(
            "s1", "user", "seed", embedding=[1, 0, 0, 0], embed_model=EMBED
        )
        memory.consolidate(
            [
                {"content": "hub", "embedding": [1, 0, 0, 0], "embed_model": EMBED},
                {"content": "leaf a"},
                {"content": "leaf b"},
                {"content": "leaf c"},
                {"content": "leaf d"},
            ],
            [
                {"from": "n0", "to": "n1", "relation": "assoc"},
                {"from": "n0", "to": "n2", "relation": "assoc"},
                {"from": "n0", "to": "n3", "relation": "assoc"},
                {"from": "n0", "to": "n4", "relation": "assoc"},
            ],
            source_episodes=[ep],
        )
        hits = memory.recall(query_embedding=[1, 0, 0, 0], hops=1, k=50)
        node_hits = [h for h in hits if h["source"] == "node"]
        assert len(node_hits) <= 2


class TestVisibility:
    def test_superseded_node_not_returned(self, memory):
        ep = memory.record(
            "s1", "user", "seed", embedding=[1, 0, 0, 0], embed_model=EMBED
        )
        ids = memory.consolidate(
            [
                {
                    "content": "stale fact",
                    "embedding": [1, 0, 0, 0],
                    "embed_model": EMBED,
                },
                {
                    "content": "fresh fact",
                    "embedding": [1, 0, 0, 0],
                    "embed_model": EMBED,
                },
            ],
            [],
            source_episodes=[ep],
        )["node_ids"]
        memory.supersede(ids[0], ids[1])

        contents = {h["content"] for h in memory.recall(query_embedding=[1, 0, 0, 0])}
        assert "stale fact" not in contents
        assert "fresh fact" in contents

    def test_expired_valid_until_not_returned(self, memory):
        ep = memory.record(
            "s1", "user", "seed", embedding=[1, 0, 0, 0], embed_model=EMBED
        )
        memory.consolidate(
            [
                {
                    "content": "expired fact",
                    "embedding": [1, 0, 0, 0],
                    "embed_model": EMBED,
                    "valid_until": "2000-01-01T00:00:00+00:00",
                },
                {
                    "content": "current fact",
                    "embedding": [1, 0, 0, 0],
                    "embed_model": EMBED,
                },
            ],
            [],
            source_episodes=[ep],
        )
        contents = {h["content"] for h in memory.recall(query_embedding=[1, 0, 0, 0])}
        assert "expired fact" not in contents
        assert "current fact" in contents
