"""Trim, stats, and history reads."""

from datetime import timedelta

import pytest
from postkit.presence import PresenceErrorCode, PresenceValidationError


class TestTrim:
    def test_retention_required_and_positive(self, presence):
        with pytest.raises(TypeError):
            presence.trim()  # older_than is a required argument

        with pytest.raises(PresenceValidationError) as exc_info:
            presence.trim(timedelta(seconds=-1))
        assert (
            exc_info.value.error_code
            == PresenceErrorCode.VAL_TRIM_INTERVAL_NOT_POSITIVE
        )

    def test_trims_only_old_transitions(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.age_transitions("40 days")
        presence.register("w2")
        presence.heartbeat("w2")

        result = presence.trim(timedelta(days=30))
        assert result == [{"namespace": test_helpers.namespace, "deleted": 1}]
        remaining = test_helpers.get_transitions()
        assert [t["entity_id"] for t in remaining] == ["w2"]

    def test_limit_batches_deletes(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()
        presence.heartbeat("w1")  # 3 transitions total
        test_helpers.age_transitions("40 days")

        assert presence.trim(timedelta(days=30), limit=2)[0]["deleted"] == 2
        assert presence.trim(timedelta(days=30), limit=2)[0]["deleted"] == 1
        assert presence.trim(timedelta(days=30), limit=2) == []


class TestStats:
    def test_counts(self, presence, test_helpers):
        presence.register("u1")
        presence.register("a1")
        presence.heartbeat("a1")
        presence.register("d1")
        presence.heartbeat("d1")
        test_helpers.set_last_seen("d1", "-10 minutes")
        presence.sweep()
        presence.register("o1")
        presence.heartbeat("o1")
        test_helpers.set_last_seen("o1", "-10 minutes")  # overdue, not swept

        stats = presence.get_stats()
        assert stats["total_entities"] == 4
        assert stats["unknown"] == 1
        assert stats["alive"] == 2
        assert stats["dead"] == 1
        assert stats["overdue"] == 1
        # first contacts (a1, d1, o1) + d1's death
        assert stats["total_transitions"] == 4


class TestReads:
    def test_get_transitions_filters_and_orders(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        presence.register("w2")
        presence.heartbeat("w2")

        all_transitions = presence.get_transitions()
        assert {t["entity_id"] for t in all_transitions} == {"w1", "w2"}

        only_w1 = presence.get_transitions("w1")
        assert [t["entity_id"] for t in only_w1] == ["w1"]

        limited = presence.get_transitions(limit=1)
        assert len(limited) == 1

    def test_list_filters(self, presence, test_helpers):
        presence.register("a1", kind="sensor")
        presence.heartbeat("a1")
        presence.register("d1")
        presence.heartbeat("d1")
        test_helpers.set_last_seen("d1", "-10 minutes")
        presence.sweep()

        assert {e["entity_id"] for e in presence.list_entities()} == {"a1", "d1"}
        assert [e["entity_id"] for e in presence.list_entities(kind="sensor")] == ["a1"]
        assert [e["entity_id"] for e in presence.list_entities(status="dead")] == ["d1"]

    def test_status_absent_entity(self, presence):
        assert presence.status("ghost") is None
