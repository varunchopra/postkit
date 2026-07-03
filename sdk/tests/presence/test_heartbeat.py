"""Heartbeat mechanics: coalescing and batch semantics."""

import threading

JOIN_TIMEOUT = 15


class TestCoalesce:
    def test_fresh_heartbeat_skips_the_write(self, presence, test_helpers):
        """The user-presence write-rate valve: a heartbeat fresher than the
        coalesce interval returns without touching the row."""
        test_helpers.set_config(heartbeat_coalesce="1 hour")
        presence.register("w1")
        assert presence.heartbeat("w1") == "alive"
        row_before = test_helpers.get_entity_row("w1")

        assert presence.heartbeat("w1") == "alive"
        row_after = test_helpers.get_entity_row("w1")
        assert row_after["last_seen"] == row_before["last_seen"]
        assert row_after["updated_at"] == row_before["updated_at"]

    def test_stale_heartbeat_writes_despite_coalesce(self, presence, test_helpers):
        test_helpers.set_config(heartbeat_coalesce="1 second")
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-1 minute")

        presence.heartbeat("w1")
        row = test_helpers.get_entity_row("w1")
        assert row["last_seen"] > row["created_at"]

    def test_coalesce_never_swallows_a_revival(self, presence, test_helpers):
        """Coalescing applies only to already-alive entities: a dead entity
        heartbeating must revive however fresh the config window is."""
        test_helpers.set_config(heartbeat_coalesce="1 hour")
        presence.register("w1")
        presence.heartbeat("w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        presence.sweep()

        assert presence.heartbeat("w1") == "alive"
        assert test_helpers.get_entity_row("w1")["status"] == "alive"


class TestBatch:
    def test_batch_matches_single_semantics(self, presence, test_helpers):
        presence.register("w1")
        presence.register("w2")
        presence.heartbeat("w2")
        test_helpers.set_last_seen("w2", "-10 minutes")
        presence.sweep()  # w2 dead

        got = {
            r["entity_id"]: r["status"] for r in presence.heartbeat_many(["w1", "w2"])
        }
        assert got == {"w1": "alive", "w2": "alive"}

        # w1's first contact and w2's revival both emitted
        assert test_helpers.get_transitions("w1")[-1]["to_status"] == "alive"
        assert test_helpers.get_transitions("w2")[-1]["from_status"] == "dead"

    def test_unknown_entities_reported_not_raised(self, presence, test_helpers):
        """One typo must not abort a fleet batch: unregistered entities come
        back as 'unknown' and no row is created."""
        presence.register("w1")
        got = {
            r["entity_id"]: r["status"] for r in presence.heartbeat_many(["w1", "typo"])
        }
        assert got == {"w1": "alive", "typo": "unknown"}
        assert test_helpers.get_entity_row("typo") is None

    def test_duplicates_collapse(self, presence):
        got = presence.heartbeat_many(["x", "x", "x"])
        assert got == [{"entity_id": "x", "status": "unknown"}]

    def test_overlapping_batches_do_not_deadlock(self, test_helpers, connect):
        """Rows are locked in entity_id order, so two batches over the same
        entities in opposite argument order cannot deadlock."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        entities = [f"w{i}" for i in range(10)]
        for e in entities:
            cur.execute("SELECT presence.register(%s, %s)", (ns, e))
            cur.fetchone()

        def batch(order):
            conn = connect()
            c = conn.cursor()
            for _ in range(10):
                c.execute("SELECT * FROM presence.heartbeat_many(%s, %s)", (ns, order))
                c.fetchall()
                conn.commit()

        threads = [
            threading.Thread(target=batch, args=(entities,)),
            threading.Thread(target=batch, args=(entities[::-1],)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=JOIN_TIMEOUT)
            assert not t.is_alive(), "overlapping batches deadlocked or hung"
