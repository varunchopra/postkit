"""P2 and P4: the transition state machine and the departed/died split."""

from datetime import timedelta

import pytest
from postkit.presence import PresenceError, PresenceErrorCode

from tests.presence.test_invariants import heartbeat, register, sweep


class TestEdges:
    def test_first_contact_is_unknown_to_alive(self, presence, test_helpers):
        presence.register("w1")
        assert test_helpers.get_entity_row("w1")["status"] == "unknown"

        assert presence.heartbeat("w1") == "alive"
        transitions = test_helpers.get_transitions("w1")
        assert [(t["from_status"], t["to_status"]) for t in transitions] == [
            ("unknown", "alive")
        ]

    def test_death_only_via_sweep(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")

        # Reads never mutate: status() sees overdue but the entity stays alive
        assert presence.status("w1")["overdue"] is True
        assert test_helpers.get_entity_row("w1")["status"] == "alive"

        deaths = presence.sweep()
        assert [d["entity_id"] for d in deaths] == ["w1"]
        assert test_helpers.get_entity_row("w1")["status"] == "dead"

    def test_revival_via_heartbeat_not_sweep(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()

        assert presence.heartbeat("w1") == "alive"
        row = test_helpers.get_entity_row("w1")
        assert row["status"] == "alive"
        assert row["dead_since"] is None
        last = test_helpers.get_transitions("w1")[-1]
        assert (last["from_status"], last["to_status"]) == ("dead", "alive")

    def test_unknown_entities_never_swept(self, presence, test_helpers):
        """Nothing can die before first contact."""
        presence.register("w1")
        assert presence.sweep() == []
        assert test_helpers.get_entity_row("w1")["status"] == "unknown"

    def test_death_carries_silent_for(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")

        death = presence.sweep()[0]
        assert death["silent_for"] is not None
        assert death["silent_for"].total_seconds() > 9 * 60


class TestDeregister:
    def test_departed_from_each_status(self, presence, test_helpers):
        # unknown
        presence.register("u1")
        assert presence.deregister("u1") is True
        # alive
        presence.register("a1")
        presence.heartbeat("a1")
        assert presence.deregister("a1") is True
        # dead
        presence.register("d1")
        presence.heartbeat("d1")
        test_helpers.set_last_seen("d1", "-10 minutes")
        presence.sweep()
        assert presence.deregister("d1") is True

        for entity, from_status in (("u1", "unknown"), ("a1", "alive"), ("d1", "dead")):
            assert test_helpers.get_entity_row(entity) is None
            last = test_helpers.get_transitions(entity)[-1]
            assert (last["from_status"], last["to_status"]) == (from_status, "departed")

    def test_deregister_absent_is_idempotent(self, presence):
        assert presence.deregister("ghost") is False

    def test_reregister_lands_at_unknown(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        presence.deregister("w1")

        presence.register("w1")
        row = test_helpers.get_entity_row("w1")
        assert row["status"] == "unknown"
        assert row["last_seen"] is None


class TestRegister:
    def test_none_preserves_attributes(self, presence, test_helpers):
        """A deploy re-running register with default args must not wipe
        anything (the lease metadata-fix pattern, applied from birth)."""
        presence.register(
            "w1", kind="sensor", timeout=timedelta(hours=1), metadata={"rack": 7}
        )
        presence.register("w1")

        row = test_helpers.get_entity_row("w1")
        assert row["kind"] == "sensor"
        assert row["timeout_override"] == timedelta(hours=1)
        assert row["metadata"] == {"rack": 7}

    def test_register_is_not_a_heartbeat(self, presence, test_helpers):
        presence.register("w1")
        presence.heartbeat("w1")
        seen_before = test_helpers.get_entity_row("w1")["last_seen"]

        presence.register("w1", metadata={"v": 2})
        row = test_helpers.get_entity_row("w1")
        assert row["last_seen"] == seen_before
        assert row["status"] == "alive"
        assert row["metadata"] == {"v": 2}

    def test_heartbeat_unregistered_raises(self, presence):
        with pytest.raises(PresenceError) as exc_info:
            presence.heartbeat("ghost")
        assert exc_info.value.error_code == PresenceErrorCode.ENTITY_UNKNOWN


class TestTimeoutOverride:
    def test_override_replaces_kind_default(self, presence, test_helpers, connect):
        """The exclusive-disjunct regression: an entity with an override
        LONGER than the kind's dead_after, silent past the kind cutoff but
        within its override, must survive sweep and read overdue = false.
        The OR-shaped predicate would falsely kill exactly this entity."""
        presence.register("slow", timeout=timedelta(hours=1))
        presence.register("fast")
        presence.heartbeat("slow")
        presence.heartbeat("fast")
        test_helpers.set_last_seen("slow", "-10 minutes")
        test_helpers.set_last_seen("fast", "-10 minutes")

        deaths = presence.sweep()
        assert [d["entity_id"] for d in deaths] == ["fast"]
        assert test_helpers.get_entity_row("slow")["status"] == "alive"
        assert presence.status("slow")["overdue"] is False

    def test_shorter_override_dies_before_kind_default(self, presence, test_helpers):
        presence.register("quick", timeout=timedelta(seconds=30))
        presence.heartbeat("quick")
        test_helpers.set_last_seen("quick", "-1 minute")  # within 90s default

        deaths = presence.sweep()
        assert [d["entity_id"] for d in deaths] == ["quick"]


class TestRawSurface:
    def test_raw_lifecycle_matches_sdk(self, test_helpers):
        """The SQL surface is the contract: the same lifecycle through raw
        SQL produces the same edge stream."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        register(cur, ns, "w1")
        heartbeat(cur, ns, "w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        assert len(sweep(cur, ns)) == 1
        heartbeat(cur, ns, "w1")

        edges = [
            (t["from_status"], t["to_status"])
            for t in test_helpers.get_transitions("w1")
        ]
        assert edges == [
            ("unknown", "alive"),
            ("alive", "dead"),
            ("dead", "alive"),
        ]
