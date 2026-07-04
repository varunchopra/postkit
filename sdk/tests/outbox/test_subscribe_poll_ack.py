"""O3 (independent fan-out) and O4 (ordered delivery), plus the cursor API
contracts around them."""

import psycopg
import pytest

from tests.outbox.test_horizon import ack, ack_event, emit, poll_ids, subscribe


class TestSubscribe:
    def test_subscribe_before_first_emit(self, test_helpers):
        """Deploying the consumer before the producer must work."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        assert subscribe(cur, ns, "orders", "billing", "start") == (0, 0)
        event_id = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", event_id)
        assert poll_ids(cur, ns, "orders", "billing") == [event_id]

    def test_from_is_required(self, test_helpers):
        ns = test_helpers.namespace
        for bad in (None, "beginning", ""):
            with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
                test_helpers.cursor.execute(
                    "SELECT * FROM outbox.subscribe(%s, 'orders', 'billing', %s)",
                    (ns, bad),
                )
            assert (
                exc_info.value.diag.message_hint
                == "postkit:outbox:VAL_SUBSCRIBE_FROM_REQUIRED"
            )

    def test_resubscribe_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        with pytest.raises(psycopg.errors.UniqueViolation) as exc_info:
            subscribe(cur, ns, "orders", "billing", "head")
        assert exc_info.value.diag.message_hint == "postkit:outbox:BIZ_CONSUMER_EXISTS"

    def test_head_skips_existing_events(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        old_id = emit(cur, ns, "orders", '{"old": true}')
        test_helpers.wait_readable("orders", old_id)
        subscribe(cur, ns, "orders", "late", "head")
        assert poll_ids(cur, ns, "orders", "late") == []
        new_id = emit(cur, ns, "orders", '{"new": true}')
        test_helpers.wait_readable("orders", new_id)
        assert poll_ids(cur, ns, "orders", "late") == [new_id]


class TestFanOutAndOrdering:
    def test_consumers_advance_independently(self, test_helpers):
        """O3: acking one consumer never affects another."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        subscribe(cur, ns, "orders", "email", "start")

        ids = [emit(cur, ns, "orders", f'{{"n": {i}}}') for i in range(3)]
        test_helpers.wait_readable("orders", ids[-1])

        assert poll_ids(cur, ns, "orders", "billing") == ids
        assert ack_event(cur, test_helpers, "orders", "billing", ids[-1]) is True

        assert poll_ids(cur, ns, "orders", "billing") == []
        assert poll_ids(cur, ns, "orders", "email") == ids

    def test_at_least_once_without_ack(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        ids = [emit(cur, ns, "orders") for _ in range(2)]
        test_helpers.wait_readable("orders", ids[-1])

        assert poll_ids(cur, ns, "orders", "billing") == ids
        assert poll_ids(cur, ns, "orders", "billing") == ids

    def test_partial_ack_resumes_midstream(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        ids = [emit(cur, ns, "orders") for _ in range(3)]
        test_helpers.wait_readable("orders", ids[-1])

        ack_event(cur, test_helpers, "orders", "billing", ids[0])
        assert poll_ids(cur, ns, "orders", "billing") == ids[1:]

    def test_poll_limit(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        ids = [emit(cur, ns, "orders") for _ in range(5)]
        test_helpers.wait_readable("orders", ids[-1])

        cur.execute(
            "SELECT id FROM outbox.poll(%s, 'orders', 'billing', p_limit := 2)", (ns,)
        )
        assert [r[0] for r in cur.fetchall()] == ids[:2]


class TestAckGuards:
    def test_ack_backwards_is_noop(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        ids = [emit(cur, ns, "orders") for _ in range(2)]
        test_helpers.wait_readable("orders", ids[-1])

        assert ack_event(cur, test_helpers, "orders", "billing", ids[1]) is True
        assert ack_event(cur, test_helpers, "orders", "billing", ids[0]) is False
        assert test_helpers.get_cursor("orders", "billing") == (
            test_helpers.event_position("orders", ids[1])
        )

    def test_ack_beyond_readable_head_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        event_id = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", event_id)

        future_xid, _ = test_helpers.event_position("orders", event_id)
        with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
            ack(cur, ns, "orders", "billing", future_xid + 1000, event_id + 1000)
        assert (
            exc_info.value.diag.message_hint
            == "postkit:outbox:BIZ_POSITION_BEYOND_HEAD"
        )

    def test_unknown_consumer_raises_everywhere(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        emit(cur, ns, "orders")

        for call, params in (
            ("SELECT * FROM outbox.poll(%s, 'orders', 'ghost')", (ns,)),
            ("SELECT outbox.has_pending(%s, 'orders', 'ghost')", (ns,)),
            ("SELECT outbox.ack(%s, 'orders', 'ghost', '0', 1)", (ns,)),
            ("SELECT outbox.replay(%s, 'orders', 'ghost', '0', 0)", (ns,)),
        ):
            with pytest.raises(psycopg.errors.NoDataFound) as exc_info:
                cur.execute(call, params)
            assert (
                exc_info.value.diag.message_hint
                == "postkit:outbox:BIZ_CONSUMER_UNKNOWN"
            )


class TestReplay:
    def test_replay_redelivers(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        ids = [emit(cur, ns, "orders") for _ in range(2)]
        test_helpers.wait_readable("orders", ids[-1])
        ack_event(cur, test_helpers, "orders", "billing", ids[-1])

        cur.execute("SELECT outbox.replay(%s, 'orders', 'billing', '0', 0)", (ns,))
        assert poll_ids(cur, ns, "orders", "billing") == ids

    def test_replay_beyond_head_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        event_id = emit(cur, ns, "orders")
        xid, _ = test_helpers.event_position("orders", event_id)

        with pytest.raises(psycopg.errors.InvalidParameterValue):
            cur.execute(
                "SELECT outbox.replay(%s, 'orders', 'billing', %s::xid8, %s)",
                (ns, str(xid + 1000), event_id + 1000),
            )
