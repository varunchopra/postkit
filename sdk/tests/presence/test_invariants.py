"""P1, the module's core guarantee: each logical edge produces exactly one
transitions row, under concurrent sweeps and heartbeats.

The mechanism under test is the entity row lock: heartbeat's UPDATE and
sweep's FOR UPDATE SKIP LOCKED serialize on it, and status checks happen
under the lock. The adversarial case models the realistic composition -
a heartbeat riding a caller's transaction that wrote business rows first
and commits late.
"""

import threading

JOIN_TIMEOUT = 15  # seconds; generous but bounded so CI never hangs


def register(cursor, namespace, entity):
    cursor.execute("SELECT presence.register(%s, %s)", (namespace, entity))
    cursor.fetchone()


def heartbeat(cursor, namespace, entity):
    cursor.execute("SELECT presence.heartbeat(%s, %s)", (namespace, entity))
    return cursor.fetchone()[0]


def sweep(cursor, namespace):
    cursor.execute("SELECT * FROM presence.sweep(%s)", (namespace,))
    return cursor.fetchall()


class TestP1HeartbeatInLongTransaction:
    def test_sweep_skips_row_locked_by_inflight_revival(self, test_helpers, connect):
        """THE adversarial case. A dead entity's heartbeat rides a caller
        transaction that wrote something else first and stays open. A sweep
        running meanwhile must SKIP the locked row - no death, no second
        revival - and after the commit exactly one dead->alive transition
        exists."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        register(cur, ns, "w1")
        heartbeat(cur, ns, "w1")
        test_helpers.set_last_seen("w1", "-10 minutes")
        assert len(sweep(cur, ns)) == 1  # w1 is now dead

        conn_a = connect()
        cur_a = conn_a.cursor()
        cur_a.execute("SELECT pg_current_xact_id()")  # the business write
        heartbeat(cur_a, ns, "w1")  # revival in flight, row locked

        # Sweep while the revival is uncommitted: the row is locked, so
        # SKIP LOCKED must pass over it silently
        assert sweep(cur, ns) == []

        conn_a.commit()

        row = test_helpers.get_entity_row("w1")
        assert row["status"] == "alive"
        revivals = [
            t
            for t in test_helpers.get_transitions("w1")
            if t["from_status"] == "dead" and t["to_status"] == "alive"
        ]
        assert len(revivals) == 1

    def test_sweep_skips_row_locked_by_inflight_plain_heartbeat(
        self, test_helpers, connect
    ):
        """An overdue-but-alive entity whose fresh heartbeat is in flight
        must not be swept dead: the row lock protects the edge until the
        heartbeat commits, and after commit the entity is current again."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        register(cur, ns, "w1")
        heartbeat(cur, ns, "w1")
        test_helpers.set_last_seen("w1", "-10 minutes")  # overdue

        conn_a = connect()
        cur_a = conn_a.cursor()
        cur_a.execute("SELECT pg_current_xact_id()")
        heartbeat(cur_a, ns, "w1")  # fresh heartbeat in flight, row locked

        assert sweep(cur, ns) == []
        conn_a.commit()

        row = test_helpers.get_entity_row("w1")
        assert row["status"] == "alive"
        deaths = [
            t for t in test_helpers.get_transitions("w1") if t["to_status"] == "dead"
        ]
        assert deaths == []


class TestP1ConcurrentSweeps:
    def test_each_death_emitted_exactly_once(self, test_helpers, connect):
        """Two sweeps over the same overdue population partition it via
        SKIP LOCKED: every entity dies exactly once, across both."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        entities = [f"w{i}" for i in range(20)]
        for e in entities:
            register(cur, ns, e)
            heartbeat(cur, ns, e)
            test_helpers.set_last_seen(e, "-10 minutes")

        results: list[list] = [[], []]
        started = threading.Barrier(2)

        def sweeper(slot):
            conn = connect()
            c = conn.cursor()
            started.wait(timeout=JOIN_TIMEOUT)
            c.execute("SELECT entity_id FROM presence.sweep(%s)", (ns,))
            results[slot] = [r[0] for r in c.fetchall()]
            conn.commit()

        threads = [threading.Thread(target=sweeper, args=(i,)) for i in (0, 1)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=JOIN_TIMEOUT)
            assert not t.is_alive(), "sweep deadlocked or hung"

        swept = results[0] + results[1]
        assert sorted(swept) == sorted(entities)
        assert len(set(swept)) == len(swept)  # no entity died twice

        for e in entities:
            deaths = [
                t for t in test_helpers.get_transitions(e) if t["to_status"] == "dead"
            ]
            assert len(deaths) == 1


class TestP1PhotoFinish:
    def test_sweep_vs_heartbeat_never_double_emits(self, test_helpers, connect):
        """Sweep and heartbeat race on one overdue entity, repeatedly.
        Legal outcomes per round: the heartbeat wins (no death) or the
        sweep wins (one death, then the next heartbeat revives). Never two
        deaths for one silence, never a revival without a preceding
        death."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        register(cur, ns, "w1")
        heartbeat(cur, ns, "w1")

        for _ in range(5):
            test_helpers.set_last_seen("w1", "-10 minutes")
            barrier = threading.Barrier(2)

            def run_sweep(round_barrier):
                conn = connect()
                c = conn.cursor()
                round_barrier.wait(timeout=JOIN_TIMEOUT)
                sweep(c, ns)
                conn.commit()

            def run_heartbeat(round_barrier):
                conn = connect()
                c = conn.cursor()
                round_barrier.wait(timeout=JOIN_TIMEOUT)
                heartbeat(c, ns, "w1")
                conn.commit()

            threads = [
                threading.Thread(target=run_sweep, args=(barrier,)),
                threading.Thread(target=run_heartbeat, args=(barrier,)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=JOIN_TIMEOUT)
                assert not t.is_alive(), "race round deadlocked or hung"

            # Leave the entity alive for the next round
            heartbeat(cur, ns, "w1")

        transitions = test_helpers.get_transitions("w1")
        # Strict alternation: the edge stream is valid regardless of who
        # won each round
        expected_from = {"unknown": "alive", "alive": "dead", "dead": "alive"}
        state = None
        for t in transitions:
            if state is not None:
                assert t["from_status"] == state, (
                    f"edge {t['from_status']}->{t['to_status']} does not "
                    f"chain from {state}: {transitions}"
                )
            assert t["to_status"] == expected_from[t["from_status"]]
            state = t["to_status"]
