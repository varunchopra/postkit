"""has_pending agrees with poll about whether events are waiting, without
taking poll's cursor-row lock."""

import psycopg
import pytest
from postkit.outbox import OutboxClient

from tests.outbox.test_horizon import ack_event, emit, poll_ids, subscribe
from tests.outbox.test_lost_cursor import trim


def has_pending(cursor, namespace, topic, consumer):
    cursor.execute(
        "SELECT outbox.has_pending(%s, %s, %s)", (namespace, topic, consumer)
    )
    return cursor.fetchone()[0]


class TestHasPending:
    def test_tracks_the_consumer_lifecycle(self, test_helpers):
        """False on a fresh subscription, true while readable events remain
        past the cursor, false again once everything is acked."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        client = OutboxClient(cur, ns)
        subscribe(cur, ns, "orders", "billing", "start")
        assert has_pending(cur, ns, "orders", "billing") is False

        first = emit(cur, ns, "orders")
        last = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", last)
        assert has_pending(cur, ns, "orders", "billing") is True
        assert client.has_pending("orders", "billing") is True

        ack_event(cur, test_helpers, "orders", "billing", first)
        assert has_pending(cur, ns, "orders", "billing") is True

        ack_event(cur, test_helpers, "orders", "billing", last)
        assert has_pending(cur, ns, "orders", "billing") is False
        assert client.has_pending("orders", "billing") is False

    def test_horizon_gated_events_are_not_pending(self, test_helpers, connect):
        """An uncommitted transaction's event is not pending: poll returns
        nothing here and has_pending must agree."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")

        conn_a = connect()
        id_a = emit(conn_a.cursor(), ns, "orders")  # open, uncommitted

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders")
        conn_b.commit()

        assert poll_ids(cur, ns, "orders", "billing") == []
        assert has_pending(cur, ns, "orders", "billing") is False

        conn_a.commit()
        test_helpers.wait_readable("orders", id_b)
        assert has_pending(cur, ns, "orders", "billing") is True
        assert poll_ids(cur, ns, "orders", "billing") == [id_a, id_b]

    def test_trimmed_past_cursor_reports_pending(self, test_helpers):
        """A cursor below the retained range is behind even when trim left
        nothing to read: pending here, CURSOR_LOST on the next poll, caught
        up again after replay to the recovery position."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        subscribe(cur, ns, "orders", "slow", "start")
        ids = [emit(cur, ns, "orders") for _ in range(3)]
        test_helpers.wait_readable("orders", ids[-1])
        test_helpers.age_events("40 days")
        trim(cur, ns, "30 days")

        assert has_pending(cur, ns, "orders", "slow") is True
        with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
            poll_ids(cur, ns, "orders", "slow")
        assert exc_info.value.diag.message_hint == "postkit:outbox:BIZ_CURSOR_LOST"

        oldest_xid, oldest_id = test_helpers.get_trimmed_through("orders")
        cur.execute(
            "SELECT outbox.replay(%s, 'orders', 'slow', %s::xid8, %s)",
            (ns, str(oldest_xid), oldest_id),
        )
        assert has_pending(cur, ns, "orders", "slow") is False

    def test_answers_while_a_poll_holds_the_cursor_row(self, test_helpers, connect):
        """poll serializes concurrent pollers on the cursor row; has_pending
        must answer anyway. The timing-out control poll proves the row is
        really locked."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        eid = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", eid)

        holder = connect()
        assert poll_ids(holder.cursor(), ns, "orders", "billing") == [eid]

        probe = connect()
        probe.execute("SET lock_timeout = '100ms'")
        probe.commit()
        probe_cur = probe.cursor()
        assert has_pending(probe_cur, ns, "orders", "billing") is True
        probe.rollback()

        with pytest.raises(psycopg.errors.LockNotAvailable):
            poll_ids(probe_cur, ns, "orders", "billing")
