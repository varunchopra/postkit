"""O5: a cursor below the retained range fails loudly, never skips silently."""

import psycopg
import pytest

from tests.outbox.test_horizon import ack_event, emit, poll_ids, subscribe

CURSOR_LOST = "postkit:outbox:BIZ_CURSOR_LOST"


def trim(cursor, namespace, older_than, topic=None):
    cursor.execute(
        "SELECT * FROM outbox.trim(%s, %s, %s)", (older_than, namespace, topic)
    )
    return cursor.fetchall()


class TestCursorLost:
    def test_trim_past_slow_consumer_then_poll_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        subscribe(cur, ns, "orders", "slow", "start")
        ids = [emit(cur, ns, "orders") for _ in range(3)]
        test_helpers.wait_readable("orders", ids[-1])
        last_pair = test_helpers.event_position("orders", ids[-1])
        test_helpers.age_events("40 days")

        assert trim(cur, ns, "30 days") == [(ns, "orders", 3)]
        assert test_helpers.get_trimmed_through("orders") == last_pair

        with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
            poll_ids(cur, ns, "orders", "slow")
        assert exc_info.value.diag.message_hint == CURSOR_LOST
        # The message carries the oldest available position for recovery
        assert f"({last_pair[0]}, {last_pair[1]})" in str(exc_info.value)

    def test_replay_to_oldest_available_recovers(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        subscribe(cur, ns, "orders", "slow", "start")
        last = 0
        for _ in range(3):
            last = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", last)
        test_helpers.age_events("40 days")
        trim(cur, ns, "30 days")

        oldest_xid, oldest_id = test_helpers.get_trimmed_through("orders")
        cur.execute(
            "SELECT outbox.replay(%s, 'orders', 'slow', %s::xid8, %s)",
            (ns, str(oldest_xid), oldest_id),
        )
        fresh = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", fresh)
        assert poll_ids(cur, ns, "orders", "slow") == [fresh]

    def test_protect_cursors_stops_trim_at_slowest_consumer(self, test_helpers):
        """Default config: the slowest cursor is a hard floor, so a consumer
        can be arbitrarily behind and never lose events."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor

        subscribe(cur, ns, "orders", "slow", "start")
        subscribe(cur, ns, "orders", "fast", "start")
        ids = [emit(cur, ns, "orders") for _ in range(4)]
        test_helpers.wait_readable("orders", ids[-1])
        test_helpers.age_events("40 days")

        ack_event(cur, test_helpers, "orders", "fast", ids[-1])
        ack_event(cur, test_helpers, "orders", "slow", ids[1])

        result = trim(cur, ns, "30 days")
        assert result == [(ns, "orders", 2)]  # only up to slow's cursor
        assert poll_ids(cur, ns, "orders", "slow") == ids[2:]

    def test_read_from_below_trimmed_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        last = 0
        for _ in range(2):
            last = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", last)
        test_helpers.age_events("40 days")
        trim(cur, ns, "30 days")

        with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
            cur.execute("SELECT * FROM outbox.read_from(%s, 'orders', '0', 0)", (ns,))
        assert exc_info.value.diag.message_hint == CURSOR_LOST

    def test_replay_below_trimmed_raises(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        subscribe(cur, ns, "orders", "slow", "start")
        last = 0
        for _ in range(2):
            last = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", last)
        test_helpers.age_events("40 days")
        trim(cur, ns, "30 days")

        with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
            cur.execute("SELECT outbox.replay(%s, 'orders', 'slow', '0', 0)", (ns,))
        assert exc_info.value.diag.message_hint == CURSOR_LOST
