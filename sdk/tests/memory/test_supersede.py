"""supersede(): bi-temporal retirement and the M4 single-step guarantee."""

import threading

import pytest
from postkit.memory import MemoryError, MemoryErrorCode

JOIN_TIMEOUT = 15


def _two_nodes(memory):
    ep = memory.record("s1", "user", "seed")
    return memory.consolidate(
        [{"content": "old belief"}, {"content": "new belief"}],
        [],
        source_episodes=[ep],
    )["node_ids"]


class TestSupersede:
    def test_sets_supersession_fields(self, memory):
        old, new = _two_nodes(memory)
        memory.supersede(old, new)
        node = memory.get_node(old)
        assert node["superseded_by"] == new
        assert node["invalidated_at"] is not None
        assert node["valid_until"] is not None

    def test_self_supersede_rejected(self, memory):
        old, _ = _two_nodes(memory)
        with pytest.raises(MemoryError) as exc_info:
            memory.supersede(old, old)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_SUPERSEDE_SELF

    def test_already_superseded_rejected(self, memory):
        old, new = _two_nodes(memory)
        memory.supersede(old, new)
        with pytest.raises(MemoryError) as exc_info:
            memory.supersede(old, new)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_ALREADY_SUPERSEDED

    def test_missing_node_rejected(self, memory):
        _, new = _two_nodes(memory)
        with pytest.raises(MemoryError) as exc_info:
            memory.supersede(999999, new)
        assert exc_info.value.error_code == MemoryErrorCode.DATA_NODE_NOT_FOUND

    def test_invalidated_replacement_rejected(self, memory):
        old, new = _two_nodes(memory)
        memory.supersede(old, new)
        with pytest.raises(MemoryError) as exc_info:
            memory.supersede(new, old)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_REPLACEMENT_INVALIDATED
        assert memory.get_node(new)["invalidated_at"] is None


class TestM4Race:
    """Two concurrent supersessions of one node: exactly one wins."""

    def test_concurrent_supersede_one_winner(self, memory, connect):
        old, new = _two_nodes(memory)
        ns = memory.namespace
        results: list = []

        def contender():
            conn = connect()
            try:
                cur = conn.cursor()
                cur.execute("SELECT memory.set_tenant(%s)", (ns,))
                cur.execute("SELECT memory.supersede(%s, %s, %s)", (ns, old, new))
                conn.commit()
                results.append("ok")
            except Exception as e:  # noqa: BLE001
                conn.rollback()
                results.append(e)

        threads = [threading.Thread(target=contender) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=JOIN_TIMEOUT)
            assert not t.is_alive(), "supersede race deadlocked or hung"

        oks = [r for r in results if r == "ok"]
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(oks) == 1
        assert len(errors) == 1
        hint = errors[0].diag.message_hint
        assert hint == "postkit:memory:BIZ_ALREADY_SUPERSEDED"
