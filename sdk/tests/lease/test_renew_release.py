"""Tests for lease.renew and lease.release via the SDK client."""

import json
from datetime import timedelta

from tests.helpers import channel_name


class TestRenew:
    def test_happy_renew(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        renewed = lease.renew("job", "w1", got["fence_token"], ttl=timedelta(minutes=2))
        assert renewed["renewed"] is True
        assert renewed["expires_at"] is not None
        assert test_helpers.get_lease_row("job")["expires_at"] == renewed["expires_at"]

    def test_wrong_fence_returns_false(self, lease):
        got = lease.acquire("job", "w1")
        renewed = lease.renew("job", "w1", got["fence_token"] + 100)
        assert renewed["renewed"] is False
        assert renewed["expires_at"] is None

    def test_wrong_holder_returns_false(self, lease):
        got = lease.acquire("job", "w1")
        renewed = lease.renew("job", "w2", got["fence_token"])
        assert renewed["renewed"] is False

    def test_renew_does_not_touch_metadata(self, lease, test_helpers):
        got = lease.acquire("job", "w1", metadata={"v": 1})
        lease.renew("job", "w1", got["fence_token"])
        assert test_helpers.get_lease_row("job")["metadata"] == {"v": 1}


class TestRelease:
    def test_release_idempotent(self, lease):
        got = lease.acquire("job", "w1")
        assert lease.release("job", "w1", got["fence_token"]) is True
        assert lease.release("job", "w1", got["fence_token"]) is False

    def test_release_wrong_fence_returns_false(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        assert lease.release("job", "w1", got["fence_token"] + 100) is False
        assert test_helpers.get_lease_row("job") is not None

    def test_release_after_takeover_returns_false(self, lease, test_helpers):
        first = lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")
        second = lease.acquire("job", "w2")

        assert lease.release("job", "w1", first["fence_token"]) is False
        row = test_helpers.get_lease_row("job")
        assert row["holder_id"] == "w2"
        assert row["fence_token"] == second["fence_token"]

    def test_distinct_pairs_get_distinct_channels(self, connect):
        conn = connect()
        row = conn.execute(
            "SELECT lease.channel_name('acme', 'eu/jobs'),"
            "       lease.channel_name('acme/eu', 'jobs')"
        ).fetchone()
        assert row[0] != row[1]

    def test_notify_on_release(self, lease, test_helpers, connect):
        """LISTEN on the lease.channel_name channel; the release NOTIFY
        arrives after commit with the documented payload."""
        test_helpers.set_config(notify_on_release=True)
        got = lease.acquire("job", "w1")

        listener = connect()
        channel = channel_name(listener.cursor(), "lease", lease.namespace, "job")
        listener.execute(f'LISTEN "{channel}"')
        listener.commit()

        lease.release("job", "w1", got["fence_token"])

        notifies = []
        gen = listener.notifies(timeout=10, stop_after=1)
        for n in gen:
            notifies.append(n)
        assert len(notifies) == 1
        payload = json.loads(notifies[0].payload)
        assert payload == {"name": "job", "event": "released"}
