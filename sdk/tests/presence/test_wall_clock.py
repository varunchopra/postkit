"""P3: liveness math on the wall clock, never the transaction start."""

import threading

from tests.presence.test_invariants import heartbeat, register, sweep


class TestWallClock:
    def test_heartbeat_in_idle_transaction_stamps_the_present(
        self, test_helpers, connect
    ):
        """A heartbeat riding a transaction that has been idling must
        record its real send time: with now() it would stamp the pinned
        transaction start, understating freshness and inviting a spurious
        death."""
        ns = test_helpers.namespace
        register(test_helpers.cursor, ns, "w1")

        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT 1")  # pins this transaction's now()

        checks = 0
        while True:
            cur.execute("SELECT clock_timestamp() - now() > interval '0.25 seconds'")
            if cur.fetchone()[0]:
                break
            checks += 1
            assert checks < 500, "wall clock never advanced past the pinned now()"
            threading.Event().wait(0.02)

        heartbeat(cur, ns, "w1")
        cur.execute(
            "SELECT last_seen - now() > interval '0.2 seconds' "
            "FROM presence.entities WHERE namespace = %s AND entity_id = %s",
            (ns, "w1"),
        )
        assert cur.fetchone()[0] is True
        conn.commit()

    def test_sweep_judges_on_wall_clock(self, test_helpers, connect):
        """A sweep riding an idled transaction must judge overdue-ness on
        the real present: an entity whose heartbeat is fresher than the
        pinned transaction start but stale on the wall clock still dies."""
        ns = test_helpers.namespace
        cur_main = test_helpers.cursor
        register(cur_main, ns, "w1")
        heartbeat(cur_main, ns, "w1")
        test_helpers.set_last_seen("w1", "-10 minutes")

        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT 1")  # pin now(); sweep must not use it
        result = sweep(cur, ns)
        conn.commit()
        assert len(result) == 1
