"""P5: flap damping records but suppresses; suppression defers terminal
alerts, never drops them."""

import hashlib
import json
import time


def force_edges(presence, test_helpers, entity: str, edges: int) -> None:
    """Cycle an entity through death/revival edges without sleeping."""
    for _ in range(edges // 2 + edges % 2):
        test_helpers.set_last_seen(entity, "-10 minutes")
        presence.sweep()
        presence.heartbeat(entity)


class TestFlapDamping:
    def test_transitions_recorded_past_threshold_marked_flapping(
        self, presence, test_helpers
    ):
        """Truth is kept: every edge lands in transitions; edges past the
        threshold inside the window carry flapping = true."""
        test_helpers.set_config(flap_threshold=3)
        presence.register("w1")
        presence.heartbeat("w1")

        force_edges(presence, test_helpers, "w1", 6)

        transitions = test_helpers.get_transitions("w1")
        # first contact + 6 forced edges (3 deaths, 3 revivals)
        assert len(transitions) == 7
        flap_flags = [t["flapping"] for t in transitions]
        # All edges land in one window; the 4th and later exceed threshold 3
        assert flap_flags == [False, False, False, True, True, True, True]

    def test_window_expiry_resets_the_counter(self, presence, test_helpers):
        test_helpers.set_config(flap_threshold=2)
        presence.register("w1")
        presence.heartbeat("w1")
        force_edges(presence, test_helpers, "w1", 4)
        assert test_helpers.get_transitions("w1")[-1]["flapping"] is True

        # The window expires; the next edge starts a fresh count
        test_helpers.set_flap_window_started("w1", "-1 hour")
        test_helpers.set_last_seen("w1", "-10 minutes")
        death = presence.sweep()[0]
        assert death["flapping"] is False
        assert test_helpers.get_entity_row("w1")["flap_count"] == 1

    def test_departed_never_counts_or_flaps(self, presence, test_helpers):
        test_helpers.set_config(flap_threshold=1)
        presence.register("w1")
        presence.heartbeat("w1")
        force_edges(presence, test_helpers, "w1", 3)

        count_before = test_helpers.get_entity_row("w1")["flap_count"]
        presence.deregister("w1")
        departed = test_helpers.get_transitions("w1")[-1]
        assert departed["to_status"] == "departed"
        assert departed["flapping"] is False
        assert count_before > 1  # the real edges did count


class TestHookSuppressedFlag:
    """The deferred-terminal-alert bookkeeping that needs no queue: the flag
    is set only when a flapping death had a hook configured to suppress,
    and revival clears it (a flap storm ending alive owes nobody an alert).
    The deferred FIRE itself composes with queue and lives in the
    integration suite."""

    def test_flapping_death_with_hook_sets_flag(self, presence, test_helpers):
        test_helpers.set_config(flap_threshold=1, on_death_queue="alerts")
        presence.register("w1")
        presence.heartbeat("w1")  # count 1: not flapping, no death hook fires
        test_helpers.set_last_seen("w1", "-10 minutes")
        death = presence.sweep()[0]  # count 2 > 1: flapping, hook suppressed

        assert death["flapping"] is True
        assert test_helpers.get_entity_row("w1")["hook_suppressed"] is True

    def test_revival_clears_the_flag(self, presence, test_helpers):
        test_helpers.set_config(flap_threshold=1, on_death_queue="alerts")
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()
        assert test_helpers.get_entity_row("w1")["hook_suppressed"] is True

        presence.heartbeat("w1")
        assert test_helpers.get_entity_row("w1")["hook_suppressed"] is False

    def test_no_flag_without_configured_hook(self, presence, test_helpers):
        test_helpers.set_config(flap_threshold=1)
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        death = presence.sweep()[0]

        assert death["flapping"] is True
        # Nothing was suppressed because nothing was configured: no alert
        # is owed and no catch-up fire will happen
        assert test_helpers.get_entity_row("w1")["hook_suppressed"] is False


class TestNotifySuppression:
    def _listen(self, connect, namespace: str, kind: str = "default"):
        conn = connect()
        conn.autocommit = True
        channel = "presence_" + hashlib.md5(f"{namespace}/{kind}".encode()).hexdigest()
        conn.execute(f'LISTEN "{channel}"')
        return conn

    def _drain(self, conn, timeout: float) -> list[dict]:
        got = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for n in conn.notifies(timeout=0.05, stop_after=1):
                got.append(json.loads(n.payload))
            if got:
                break
        return got

    def test_normal_edge_notifies_flapping_edge_does_not(
        self, presence, test_helpers, connect
    ):
        """One drain per edge: pre-threshold edges each deliver exactly one
        notify; edges past the threshold deliver none."""
        ns = test_helpers.namespace
        test_helpers.set_config(flap_threshold=2)
        presence.register("w1")
        listener = self._listen(connect, ns)

        presence.heartbeat("w1")  # first contact: count 1, below threshold
        assert [g["to"] for g in self._drain(listener, timeout=5.0)] == ["alive"]

        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()  # death: count 2, still below threshold
        assert [g["to"] for g in self._drain(listener, timeout=5.0)] == ["dead"]

        presence.heartbeat("w1")  # revival: count 3 > threshold, flapping
        assert test_helpers.get_transitions("w1")[-1]["flapping"] is True
        assert self._drain(listener, timeout=1.0) == []

        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()  # flapping death: suppressed too
        assert self._drain(listener, timeout=1.0) == []
