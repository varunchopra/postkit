"""get_stats and the paginated list_* accessors."""


class TestStats:
    def test_counts(self, memory):
        e1 = memory.record("s1", "user", "one")
        memory.record("s1", "user", "two")
        memory.consolidate(
            [{"content": "fact"}, {"content": "Entity", "kind": "entity"}],
            [{"from": "n0", "to": "n1", "relation": "entity"}],
            source_episodes=[e1],
        )
        stats = memory.get_stats()
        assert stats["total_episodes"] == 2
        assert stats["unconsolidated_episodes"] == 1
        assert stats["total_nodes"] == 2
        assert stats["live_nodes"] == 2
        assert stats["total_edges"] == 1
        assert stats["embedding_dim"] == 4


class TestListEpisodes:
    def test_pagination_no_overlap(self, memory):
        for i in range(5):
            memory.record("s1", "user", f"episode {i}")

        page1 = memory.list_episodes(limit=2)
        assert len(page1) == 2
        page2 = memory.list_episodes(limit=2, before=page1[-1]["cursor"])
        assert len(page2) == 2

        ids1 = {r["id"] for r in page1}
        ids2 = {r["id"] for r in page2}
        assert ids1.isdisjoint(ids2)
        assert min(r["id"] for r in page1) > max(r["id"] for r in page2)

    def test_session_filter(self, memory):
        memory.record("sa", "user", "in a")
        memory.record("sb", "user", "in b")
        rows = memory.list_episodes(session="sa")
        assert [r["content"] for r in rows] == ["in a"]


class TestListNodes:
    def test_pagination_no_overlap(self, memory):
        ep = memory.record("s1", "user", "seed")
        memory.consolidate(
            [{"content": f"fact {i}"} for i in range(5)],
            [],
            source_episodes=[ep],
        )
        page1 = memory.list_nodes(limit=2)
        assert len(page1) == 2
        page2 = memory.list_nodes(limit=2, before=page1[-1]["cursor"])
        assert len(page2) == 2
        assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})

    def test_include_superseded_toggle(self, memory):
        ep = memory.record("s1", "user", "seed")
        old, new = memory.consolidate(
            [{"content": "old"}, {"content": "new"}], [], source_episodes=[ep]
        )["node_ids"]
        memory.supersede(old, new)

        live = {r["id"] for r in memory.list_nodes()}
        assert old not in live and new in live

        everything = {r["id"] for r in memory.list_nodes(include_superseded=True)}
        assert old in everything and new in everything

    def test_kind_filter(self, memory):
        ep = memory.record("s1", "user", "seed")
        memory.consolidate(
            [{"content": "a fact"}, {"content": "AnEntity", "kind": "entity"}],
            [],
            source_episodes=[ep],
        )
        entities = memory.list_nodes(kind="entity")
        assert [n["content"] for n in entities] == ["AnEntity"]
