"""record(): the append path and the M1 immutability guarantee."""

from datetime import datetime, timezone

import psycopg
import pytest
from postkit.memory import MemoryError, MemoryErrorCode


class TestRecord:
    def test_round_trips_via_list(self, memory):
        memory.record("s1", "user", "the cat sat", keywords=["cat", "sat"])
        rows = memory.list_episodes()
        assert len(rows) == 1
        assert rows[0]["content"] == "the cat sat"
        assert rows[0]["role"] == "user"
        assert rows[0]["session_id"] == "s1"
        assert set(rows[0]["keywords"]) == {"cat", "sat"}

    def test_keywords_default_empty(self, memory):
        memory.record("s1", "user", "no keywords here")
        assert memory.list_episodes()[0]["keywords"] == []

    def test_embedding_without_model_rejected(self, memory):
        with pytest.raises(MemoryError) as exc_info:
            memory.record("s1", "user", "hi", embedding=[1, 0, 0, 0])
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_EMBED_MODEL_REQUIRED

    def test_model_without_embedding_rejected(self, memory):
        with pytest.raises(MemoryError) as exc_info:
            memory.record("s1", "user", "hi", embed_model="m")
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_EMBED_MODEL_REQUIRED

    def test_occurred_at_override_respected(self, memory):
        when = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        memory.record("s1", "user", "backdated", occurred_at=when)
        assert memory.list_episodes()[0]["occurred_at"] == when

    def test_embedding_stored(self, memory):
        memory.record(
            "s1", "user", "vec", embedding=[0.1, 0.2, 0.3, 0.4], embed_model="test"
        )
        row = memory.list_episodes()[0]
        assert row["embed_model"] == "test"


class TestM1Immutability:
    """Episode content is immutable; only consolidated_at may be set, once, from NULL."""

    def test_content_update_rejected(self, memory, test_helpers):
        eid = memory.record("s1", "user", "original")
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState) as exc_info:
            test_helpers.update_episode_content(eid, "tampered")
        assert (
            exc_info.value.diag.message_hint == "postkit:memory:DATA_EPISODE_IMMUTABLE"
        )

    def test_consolidated_at_can_be_set_once(self, memory, test_helpers):
        eid = memory.record("s1", "user", "original")
        test_helpers.mark_consolidated(eid)
        assert test_helpers.get_episode(eid)["consolidated_at"] is not None

    def test_second_consolidated_at_update_rejected(self, memory, test_helpers):
        eid = memory.record("s1", "user", "original")
        test_helpers.mark_consolidated(eid)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState) as exc_info:
            test_helpers.mark_consolidated(eid)
        assert (
            exc_info.value.diag.message_hint == "postkit:memory:DATA_EPISODE_IMMUTABLE"
        )

    def test_delete_allowed(self, memory, test_helpers):
        eid = memory.record("s1", "user", "disposable")
        test_helpers.delete_episode(eid)
        assert test_helpers.get_episode(eid) is None
