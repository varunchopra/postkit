"""Invariant tests I1, I2, I5 against the raw SQL surface.

These run before/without the SDK client on purpose: they validate the
locking design itself (the _lock_name counter mutex), not the wrapper.
"""

import threading

JOIN_TIMEOUT = 15  # seconds; generous but bounded so CI never hangs


def acquire(cursor, namespace, name, holder, ttl=None):
    cursor.execute(
        "SELECT * FROM lease.acquire(%s, %s, %s, %s)",
        (namespace, name, holder, ttl),
    )
    row = cursor.fetchone()
    return {
        "acquired": row[0],
        "fence_token": row[1],
        "expires_at": row[2],
        "current_holder": row[3],
    }


class TestI1SingleLiveHolder:
    """I1: at most one live holder per (namespace, name)."""

    def test_concurrent_first_acquire_one_winner(self, test_helpers, connect):
        """Two connections race acquire on a free name; exactly one wins.

        Both start with no lease row and no counter row – the case the
        _lock_name mutex exists to serialize.
        """
        ns = test_helpers.namespace
        results = []

        def contender(worker):
            conn = None
            try:
                conn = connect()
                cur = conn.cursor()
                results.append(acquire(cur, ns, "leader", worker))
                conn.commit()
            finally:
                if conn:
                    conn.close()

        threads = [threading.Thread(target=contender, args=(w,)) for w in ("w1", "w2")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=JOIN_TIMEOUT)
            assert not t.is_alive(), "acquire race deadlocked or hung"

        assert len(results) == 2
        winners = [r for r in results if r["acquired"]]
        losers = [r for r in results if not r["acquired"]]
        assert len(winners) == 1
        assert len(losers) == 1
        # Loser gets observability info about the winner
        assert losers[0]["fence_token"] is None
        assert losers[0]["current_holder"] == winners[0]["current_holder"]
        assert losers[0]["expires_at"] is not None

    def test_contended_acquire_returns_holder_info(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace
        first = acquire(cur, ns, "job", "w1")
        second = acquire(cur, ns, "job", "w2")
        assert first["acquired"] is True
        assert second["acquired"] is False
        assert second["current_holder"] == "w1"
        assert second["fence_token"] is None
        assert second["expires_at"] == first["expires_at"]


class TestI2FenceMonotonicity:
    """I2: fence tokens strictly increase across distinct acquisitions."""

    def test_fence_increases_across_acquisitions(self, test_helpers):
        """Fences are STRICTLY INCREASING – never assert consecutive:
        gaps are legal and must not be "fixed"."""
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        fences = []
        for holder in ("w1", "w2", "w3"):
            got = acquire(cur, ns, "job", holder)
            assert got["acquired"] is True
            fences.append(got["fence_token"])
            cur.execute(
                "SELECT lease.release(%s, %s, %s, %s)",
                (ns, "job", holder, got["fence_token"]),
            )
            assert cur.fetchone()[0] is True

        assert fences == sorted(fences)
        assert len(set(fences)) == len(fences)

    def test_renew_and_reacquire_keep_fence(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        got = acquire(cur, ns, "job", "w1")
        fence = got["fence_token"]

        cur.execute(
            "SELECT * FROM lease.renew(%s, %s, %s, %s)", (ns, "job", "w1", fence)
        )
        assert cur.fetchone()[0] is True
        assert test_helpers.get_lease_row("job")["fence_token"] == fence

        # Same-holder re-acquire of a LIVE lease: renew semantics, same fence
        again = acquire(cur, ns, "job", "w1")
        assert again["acquired"] is True
        assert again["fence_token"] == fence

    def test_fence_survives_release(self, test_helpers):
        """The counter registry outlives the lease row (config.version_counters
        pattern) – a fresh acquisition after release must not restart at 1."""
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        first = acquire(cur, ns, "job", "w1")
        cur.execute(
            "SELECT lease.release(%s, %s, %s, %s)",
            (ns, "job", "w1", first["fence_token"]),
        )
        assert test_helpers.get_lease_row("job") is None
        assert test_helpers.get_counter("job") == first["fence_token"]

        second = acquire(cur, ns, "job", "w2")
        assert second["fence_token"] > first["fence_token"]


class TestI5PerNameCounters:
    """I5: fence tokens are comparable only within one lease name."""

    def test_independent_counters_per_name(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        a = acquire(cur, ns, "name-a", "w1")
        b = acquire(cur, ns, "name-b", "w1")
        # Each name starts its own counter at 1 – a global sequence would
        # hand name-b a token > 1 here.
        assert a["fence_token"] == 1
        assert b["fence_token"] == 1
