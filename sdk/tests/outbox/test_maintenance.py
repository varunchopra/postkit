"""Trim boundary rules, stats, and lag; the sparse-id and prefix cases."""

import psycopg
import pytest

from tests.outbox.test_horizon import ack_event, emit, subscribe
from tests.outbox.test_lost_cursor import trim


class TestTrimRules:
    def test_retention_required_and_positive(self, test_helpers):
        for bad in (None, "-1 day", "0 seconds"):
            with pytest.raises(psycopg.errors.InvalidParameterValue) as exc_info:
                test_helpers.cursor.execute(
                    "SELECT * FROM outbox.trim(%s, %s)",
                    (bad, test_helpers.namespace),
                )
            assert (
                exc_info.value.diag.message_hint
                == "postkit:outbox:VAL_TRIM_INTERVAL_NOT_POSITIVE"
            )

    def test_no_consumers_with_protect_skips_topic(self, test_helpers):
        """A topic nobody consumes yet must not be silently emptied."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        for _ in range(2):
            emit(cur, ns, "orders")
        test_helpers.age_events("40 days")

        assert trim(cur, ns, "30 days") == []
        assert test_helpers.count_events("orders") == 2

    def test_retain_min_rows_is_positional(self, test_helpers):
        """The retain floor must survive interleaved traffic on OTHER topics:
        ids within one topic are sparse, so 'head minus N' would retain
        anywhere from zero to all rows depending on unrelated inserts."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False, retain_min_rows=2)

        quiet_ids = []
        for i in range(4):
            quiet_ids.append(emit(cur, ns, "quiet"))
            for _ in range(10):
                emit(cur, ns, "busy")  # widens the id gaps on 'quiet'
        test_helpers.wait_readable("quiet", quiet_ids[-1])
        test_helpers.age_events("40 days", topic="quiet")

        result = [r for r in trim(cur, ns, "30 days", topic="quiet")]
        assert result == [(ns, "quiet", 2)]
        assert test_helpers.event_ids("quiet") == quiet_ids[2:]  # exactly N newest

    def test_trim_never_deletes_above_readable_head(self, test_helpers, connect):
        """A committed row above the horizon (long transaction still open)
        must survive age-based trim: deleting it before any poll could see
        it would be silent permanent loss."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        old_id = emit(cur, ns, "orders")
        # The horizon only moves forward: once old_id is readable it stays
        # readable, whatever transactions open later
        test_helpers.wait_readable("orders", old_id)

        conn_a = connect()  # open transaction pins the horizon from here on
        emit(conn_a.cursor(), ns, "orders")

        conn_b = connect()
        cur_b = conn_b.cursor()
        newer_id = emit(cur_b, ns, "orders")
        conn_b.commit()

        test_helpers.age_events("40 days")  # ALL rows now look ancient

        result = trim(cur, ns, "30 days")
        assert result == [(ns, "orders", 1)]  # only the row below the horizon
        surviving = test_helpers.event_ids("orders")
        assert old_id not in surviving
        assert newer_id in surviving
        conn_a.rollback()

    def test_prefix_stranding_regression(self, test_helpers, connect):
        """The interleave that breaks per-row age deletion: a long
        transaction's event has an OLD created_at (transaction start) while
        quick emits in between are young. Whatever trim deletes, no
        surviving row may sort at or below the trimmed pair - that row
        would be unreachable and poll would raise CURSOR_LOST for data that
        still exists."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        conn_long = connect()
        cur_long = conn_long.cursor()
        cur_long.execute("SELECT 1")  # pin the transaction start time

        young_low = emit(cur, ns, "orders", '{"who": "young-low-id"}')
        old_high = emit(cur_long, ns, "orders", '{"who": "old-high-id"}')
        conn_long.commit()
        test_helpers.wait_readable("orders", old_high)

        # Only the long transaction's row is older than the cutoff
        cur.execute(
            "UPDATE outbox.events SET created_at = now() - interval '40 days' "
            "WHERE namespace = %s AND id = %s",
            (ns, old_high),
        )

        trim(cur, ns, "30 days")

        trimmed = test_helpers.get_trimmed_through("orders")
        surviving = [
            test_helpers.event_position("orders", i)
            for i in test_helpers.event_ids("orders")
        ]
        assert all(pair > trimmed for pair in surviving), (
            f"rows {surviving} stranded at or below trimmed pair {trimmed}"
        )
        assert young_low or True  # ids referenced above; assertion is the invariant

    def test_trim_does_not_strand_inflight_business_write_emit(
        self, test_helpers, connect
    ):
        """The trim face of the (xid, id) bug: while a business-write-first
        transaction's emit is in flight, its pair (old xid, high id) sorts
        BELOW a later transaction's committed event. Trim running in that
        window must not move the trimmed pair past it - the in-flight event
        must still be deliverable after it commits."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        conn_a = connect()
        cur_a = conn_a.cursor()
        cur_a.execute("SELECT pg_current_xact_id()")  # A's business write

        conn_b = connect()
        cur_b = conn_b.cursor()
        id_b = emit(cur_b, ns, "orders", '{"src": "b"}')
        conn_b.commit()

        id_a = emit(cur_a, ns, "orders", '{"src": "a"}')  # older xid, higher id

        test_helpers.age_events("40 days")
        trim(cur, ns, "30 days")  # runs while A is open

        conn_a.commit()
        test_helpers.wait_readable("orders", id_b)

        subscribe(cur, ns, "orders", "audit", "start")
        cur.execute("SELECT id FROM outbox.poll(%s, 'orders', 'audit')", (ns,))
        delivered = [r[0] for r in cur.fetchall()]
        assert id_a in delivered and id_b in delivered

        trimmed = test_helpers.get_trimmed_through("orders")
        for event_id in test_helpers.event_ids("orders"):
            assert test_helpers.event_position("orders", event_id) > trimmed

    def test_batch_limit_preserves_prefix(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        test_helpers.set_config(protect_cursors=False)

        ids = [emit(cur, ns, "orders") for _ in range(5)]
        test_helpers.wait_readable("orders", ids[-1])
        test_helpers.age_events("40 days")

        pair_of_second = test_helpers.event_position("orders", ids[1])
        cur.execute("SELECT * FROM outbox.trim('30 days', %s, NULL, 2)", (ns,))
        assert cur.fetchall() == [(ns, "orders", 2)]
        assert test_helpers.get_trimmed_through("orders") == pair_of_second
        assert test_helpers.event_ids("orders") == ids[2:]

        # The next call continues the prefix
        cur.execute("SELECT * FROM outbox.trim('30 days', %s, NULL, 2)", (ns,))
        assert cur.fetchall() == [(ns, "orders", 2)]
        assert test_helpers.event_ids("orders") == ids[4:]


class TestLagAndStats:
    def test_lag_counts_backlog_not_id_distance(self, test_helpers):
        """One event behind on a quiet topic while another topic emits
        hundreds: the backlog is 1, whatever the id gap says."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "quiet", "watcher", "start")

        first = emit(cur, ns, "quiet")
        test_helpers.wait_readable("quiet", first)
        ack_event(cur, test_helpers, "quiet", "watcher", first)
        for _ in range(200):
            emit(cur, ns, "busy")
        pending = emit(cur, ns, "quiet")
        test_helpers.wait_readable("quiet", pending)

        cur.execute("SELECT lag_events FROM outbox.lag(%s, 'quiet')", (ns,))
        assert cur.fetchone()[0] == 1

    def test_lag_caught_up(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        event_id = emit(cur, ns, "orders")
        test_helpers.wait_readable("orders", event_id)
        ack_event(cur, test_helpers, "orders", "billing", event_id)

        cur.execute("SELECT lag_events, lag_time, horizon FROM outbox.lag(%s)", (ns,))
        lag_events, lag_time, horizon = cur.fetchone()
        assert lag_events == 0
        assert lag_time is None
        assert horizon is not None

    def test_get_stats_inherits_backlog_semantics(self, test_helpers):
        """max_lag_events must match lag()'s count, not an id subtraction;
        the busy-topic interleave from the sparse-id case proves which one
        is implemented."""
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "quiet", "watcher", "start")

        for _ in range(50):
            emit(cur, ns, "busy")
        pending = emit(cur, ns, "quiet")
        test_helpers.wait_readable("quiet", pending)

        cur.execute("SELECT * FROM outbox.get_stats(%s)", (ns,))
        total_events, total_topics, total_consumers, max_lag = cur.fetchone()
        assert total_events == 51
        assert total_topics == 2
        assert total_consumers == 1
        assert max_lag == 1

    def test_list_consumers(self, test_helpers):
        ns = test_helpers.namespace
        cur = test_helpers.cursor
        subscribe(cur, ns, "orders", "billing", "start")
        subscribe(cur, ns, "orders", "email", "start")

        cur.execute("SELECT consumer FROM outbox.list_consumers(%s, 'orders')", (ns,))
        assert [r[0] for r in cur.fetchall()] == ["billing", "email"]
