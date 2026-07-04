"""O1, the module's core guarantee: no event ever becomes visible at or
behind a consumer's cursor.

Cursors are (xid, id) pairs because xid is assigned at a transaction's
FIRST write while id is assigned at emit. A transaction that does business
writes before emitting (the documented usage) carries an older xid with a
higher id than a fresh transaction that emits immediately, so id order and
commit-visibility order disagree; only xid order is frozen below the
horizon. Tests here put a business write before the emit where that
divergence is the point - an emit-first test cannot tell the two orders
apart and proves nothing about the gate.
"""


def emit(cursor, namespace, topic, payload="{}"):
    cursor.execute(
        "SELECT outbox.emit(%s, %s, 'test.event', %s)", (namespace, topic, payload)
    )
    return cursor.fetchone()[0]


def subscribe(cursor, namespace, topic, consumer, from_):
    cursor.execute(
        "SELECT position_xid::text, position_id FROM outbox.subscribe(%s, %s, %s, %s)",
        (namespace, topic, consumer, from_),
    )
    row = cursor.fetchone()
    return (int(row[0]), row[1])


def poll_ids(cursor, namespace, topic, consumer):
    cursor.execute(
        "SELECT id FROM outbox.poll(%s, %s, %s)", (namespace, topic, consumer)
    )
    return [r[0] for r in cursor.fetchall()]


def ack(cursor, namespace, topic, consumer, xid, event_id):
    cursor.execute(
        "SELECT outbox.ack(%s, %s, %s, %s::xid8, %s)",
        (namespace, topic, consumer, str(xid), event_id),
    )
    return cursor.fetchone()[0]


def ack_event(cursor, test_helpers, topic, consumer, event_id):
    """Ack by event id, looking up its stored pair - what a real consumer
    does with the xid and id columns of the row it just polled."""
    xid, _ = test_helpers.event_position(topic, event_id)
    return ack(cursor, test_helpers.namespace, topic, consumer, xid, event_id)


class TestXidIdCursors:
    def test_emit_after_business_write_is_not_lost(self, test_helpers, connect):
        """THE case the pair cursor exists for. A's transaction writes
        business state first (old xid), then emits AFTER B's fresh
        transaction has emitted (so A's id is higher, B's lower). A commits
        and is consumed while B is still open. When B finally commits, its
        event carries a lower id but a HIGHER xid than the cursor - a plain
        id cursor would have acked past it forever."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        conn_a = connect()
        cur_a = conn_a.cursor()
        cur_a.execute(
            "SELECT pg_current_xact_id()"
        )  # A's business write: xid assigned here

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')  # newer xid, lower id

        id_a = emit(cur_a, ns, "orders", '{"src": "a"}')  # older xid, higher id
        conn_a.commit()
        assert id_a > id_b

        test_helpers.wait_readable("orders", id_a)
        assert poll_ids(cur, ns, "orders", "billing") == [id_a]
        assert ack_event(cur, test_helpers, "orders", "billing", id_a) is True

        conn_b.commit()
        test_helpers.wait_readable("orders", id_b)
        assert poll_ids(cur, ns, "orders", "billing") == [id_b]

    def test_delivery_follows_xid_order_not_id_order(self, test_helpers, connect):
        """The two orders genuinely differ here, and delivery must follow
        (xid, id): the older-xid, higher-id event sorts FIRST."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        conn_a = connect()
        cur_a = conn_a.cursor()
        cur_a.execute("SELECT pg_current_xact_id()")

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')

        id_a = emit(cur_a, ns, "orders", '{"src": "a"}')
        conn_a.commit()
        conn_b.commit()

        test_helpers.wait_readable("orders", id_b)
        assert poll_ids(cur, ns, "orders", "billing") == [id_a, id_b]


class TestHorizonGate:
    def test_committed_event_held_back_by_older_open_transaction(
        self, test_helpers, connect
    ):
        """While A's older transaction is open, even B's COMMITTED event is
        invisible; the naive ungated read would have returned it (and lost
        A's event). After A commits, both arrive in delivery order."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        conn_a = connect()
        cur_a = conn_a.cursor()
        id_a = emit(cur_a, ns, "orders", '{"src": "a"}')  # open, uncommitted

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')
        conn_b.commit()
        assert id_b > id_a

        # Gated read: nothing, because A's older transaction pins the horizon
        assert poll_ids(cur, ns, "orders", "billing") == []

        # Negative control, the bug this module exists to prevent: the
        # ungated read already shows B's id, and a consumer trusting it
        # would advance past A's smaller id
        assert test_helpers.ungated_ids_after("orders", 0) == [id_b]

        conn_a.commit()
        test_helpers.wait_readable("orders", id_b)
        assert poll_ids(cur, ns, "orders", "billing") == [id_a, id_b]

    def test_aborted_transaction_leaves_safe_gap(self, test_helpers, connect):
        """A rolls back: only B's event exists, and the gap below the
        horizon is legal to ack across."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        conn_a = connect()
        emit(conn_a.cursor(), ns, "orders", '{"src": "a"}')

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')
        conn_b.commit()

        conn_a.rollback()
        test_helpers.wait_readable("orders", id_b)

        got = poll_ids(cur, ns, "orders", "billing")
        assert got == [id_b]
        assert ack_event(cur, test_helpers, "orders", "billing", id_b) is True
        assert poll_ids(cur, ns, "orders", "billing") == []

    def test_subscribe_head_is_horizon_gated(self, test_helpers, connect):
        """'head' while an uncommitted event is in flight must exclude it:
        a raw-max cursor would strand that event once it commits."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor

        # Committed baseline event so the topic has a raw max
        baseline = emit(cur, ns, "orders", '{"n": 0}')
        test_helpers.wait_readable("orders", baseline)

        conn_a = connect()
        id_a = emit(conn_a.cursor(), ns, "orders", '{"src": "a"}')  # in flight

        head = subscribe(cur, ns, "orders", "late-joiner", "head")
        assert head == test_helpers.event_position("orders", baseline)

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')
        conn_b.commit()
        assert id_b > id_a

        conn_a.commit()
        test_helpers.wait_readable("orders", id_b)
        got = poll_ids(cur, ns, "orders", "late-joiner")
        assert id_a in got and id_b in got
        assert baseline not in got

    def test_delivery_order_has_no_gaps_below_horizon(self, test_helpers, connect):
        """O4: interleaved committed emits arrive complete and in delivery
        order in one poll."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        ids = []
        for i in range(5):
            conn = connect()
            ids.append(emit(conn.cursor(), ns, "orders", f'{{"n": {i}}}'))
            conn.commit()

        test_helpers.wait_readable("orders", ids[-1])
        assert poll_ids(cur, ns, "orders", "billing") == ids


class TestHorizonBlockers:
    """horizon_blockers surfaces the backends pinning the horizon."""

    def test_open_write_transaction_appears_and_clears(self, outbox, connect):
        """An uncommitted emit's backend is listed; after commit it is gone.

        The horizon is database-global and other test workers may hold
        older write transactions, so the is_horizon marker is asserted
        only when this backend's xid actually is the horizon.
        """
        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT pg_backend_pid()")
        blocker_pid = cur.fetchone()[0]
        cur.execute(
            "SELECT outbox.emit(%s, 'orders', 'test.event', '{}')",
            (outbox.namespace,),
        )
        cur.execute("SELECT pg_current_xact_id()::text")
        blocker_xid = int(cur.fetchone()[0])

        rows = {r["pid"]: r for r in outbox.horizon_blockers()}
        assert blocker_pid in rows
        row = rows[blocker_pid]
        assert row["xact_age"] is not None

        cur.execute("SELECT mod(outbox._horizon()::text::numeric, 4294967296)")
        horizon_low = int(cur.fetchone()[0])
        if blocker_xid % 4294967296 == horizon_low:
            assert row["is_horizon"] is True

        conn.commit()
        conn.close()

        pids = [r["pid"] for r in outbox.horizon_blockers()]
        assert blocker_pid not in pids
