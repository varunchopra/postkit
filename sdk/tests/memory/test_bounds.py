import pytest
from postkit.memory import MemoryValidationError


def test_every_bounded_memory_api_rejects_max_plus_one(memory):
    calls = (
        (lambda: memory.consolidation_due(batch_size=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: memory.consolidate([{}] * 1001, [], []), "VAL_BATCH_TOO_LARGE"),
        (lambda: memory.consolidate([], [{}] * 1001, []), "VAL_BATCH_TOO_LARGE"),
        (lambda: memory.consolidate([], [], [0] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: memory.list_episodes(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: memory.list_nodes(limit=1001), "VAL_LIMIT_TOO_LARGE"),
    )
    for call, code in calls:
        with pytest.raises(MemoryValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_memory_boundaries_accept_max_and_reject_nonpositive(memory):
    episode = memory.record("bounds", "user", "seed")
    result = memory.consolidate(
        [{"content": f"fact-{i}"} for i in range(1000)],
        [],
        [episode],
    )
    assert len(result["node_ids"]) == 1000
    for bad in (None, 0, -1):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.list_nodes(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"


def test_rejected_memory_batch_has_no_partial_effects(memory):
    before = memory.get_stats()["total_nodes"]
    with pytest.raises(MemoryValidationError):
        memory.consolidate([{"content": str(i)} for i in range(1001)], [], [])
    assert memory.get_stats()["total_nodes"] == before
