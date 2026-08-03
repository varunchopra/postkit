"""Invariant tests I3, I4: the fencing rules, against the raw SQL surface.

I4 is THE test for this module: verify in transaction T and a takeover in
T' must serialize – no interleaving where both win.
"""

import threading
import time

import psycopg
import pytest
from postkit.lease import LeaseError, LeaseErrorCode, LeaseFencingError

from tests.lease.test_invariants import JOIN_TIMEOUT, acquire

FENCE_STALE_HINT = "postkit:lease:FENCE_STALE"


def verify(cursor, namespace, name, holder, fence):
    cursor.execute(
        "SELECT lease.verify(%s, %s, %s, %s)", (namespace, name, holder, fence)
    )


class TestI3ExpiredMeansLost:
    """I3: past expires_at the old holder can never renew or verify with the
    old token – even before anyone else acquires."""

    def test_renew_fails_after_expiry_before_takeover(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        got = acquire(cur, ns, "job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        cur.execute(
            "SELECT * FROM lease.renew(%s, %s, %s, %s)",
            (ns, "job", "w1", got["fence_token"]),
        )
        renewed, expires_at = cur.fetchone()
        assert renewed is False
        assert expires_at is None

    def test_verify_fails_after_expiry_before_takeover(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        got = acquire(cur, ns, "job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        with pytest.raises(psycopg.errors.SerializationFailure) as exc_info:
            verify(cur, ns, "job", "w1", got["fence_token"])
        assert exc_info.value.diag.message_hint == FENCE_STALE_HINT

    def test_own_expired_reacquire_gets_new_fence(self, test_helpers):
        cur = test_helpers.cursor
        ns = test_helpers.namespace

        first = acquire(cur, ns, "job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        again = acquire(cur, ns, "job", "w1")
        assert again["acquired"] is True
        assert again["fence_token"] > first["fence_token"]
        # Logged as a takeover, previous holder = itself
        events = test_helpers.get_events("job")
        assert events[-1]["event"] == "taken_over"
        assert events[-1]["previous_holder"] == "w1"


class TestI4VerifyTakeoverSerialization:
    """I4: verify in transaction T and a takeover in T' serialize."""

    def test_takeover_waits_for_open_verify_transaction(self, test_helpers, connect):
        """Conn A verifies inside an open transaction (FOR SHARE held); conn B
        tries to take over the expired lease and must BLOCK until A commits,
        then proceed with a new fence. A's next verify then fails.

        Expiry choreography: the lease is given a short future expiry BEFORE
        A verifies – an UPDATE after A's FOR SHARE would itself block. A
        verifies before the wall clock crosses the expiry, so it passes; we
        then wait for the crossing (the one place a real clock crossing is
        the semantics under test) so B's acquire takes the takeover branch.
        B must resolve before acquire's 2 second lock timeout turns its wait
        into a miss – A commits about a second in, well inside it.
        """
        ns = test_helpers.namespace
        got = acquire(test_helpers.cursor, ns, "job", "w1")
        fence = got["fence_token"]

        test_helpers.set_expires_at("job", "+1 second")

        conn_a = connect()
        cur_a = conn_a.cursor()
        # A's transaction timestamp is pinned here, before the expiry passes
        verify(cur_a, ns, "job", "w1", fence)  # transaction A now holds FOR SHARE

        # Wait (bounded) until the lease is expired from everyone else's view
        deadline_checks = 0
        while True:
            test_helpers.cursor.execute(
                "SELECT expires_at <= now() FROM lease.leases "
                "WHERE namespace = %s AND name = %s",
                (ns, "job"),
            )
            if test_helpers.cursor.fetchone()[0]:
                break
            deadline_checks += 1
            assert deadline_checks < 300, "lease never crossed its expiry"
            threading.Event().wait(0.02)

        b_result = {}
        b_started = threading.Event()

        def takeover():
            conn_b = connect()
            cur_b = conn_b.cursor()
            b_started.set()
            b_result.update(acquire(cur_b, ns, "job", "w2"))
            conn_b.commit()

        thread = threading.Thread(target=takeover)
        thread.start()
        b_started.wait(timeout=JOIN_TIMEOUT)

        # B must still be blocked while A's transaction is open
        thread.join(timeout=1.0)
        assert thread.is_alive(), "takeover did not block behind open verify"
        assert b_result == {}

        conn_a.commit()
        thread.join(timeout=JOIN_TIMEOUT)
        assert not thread.is_alive(), "takeover never unblocked after commit"

        assert b_result["acquired"] is True
        assert b_result["fence_token"] > fence

        # A's next transaction: the old fence is dead
        with pytest.raises(psycopg.errors.SerializationFailure):
            verify(cur_a, ns, "job", "w1", fence)
        conn_a.rollback()

    def test_verify_after_committed_takeover_raises(self, test_helpers, connect):
        """Variant: the takeover commits first; a later verify with the old
        fence raises FENCE_STALE inside the protected transaction."""
        ns = test_helpers.namespace
        got = acquire(test_helpers.cursor, ns, "job", "w1")
        old_fence = got["fence_token"]

        test_helpers.set_expires_at("job", "-1 second")
        taken = acquire(test_helpers.cursor, ns, "job", "w2")
        assert taken["acquired"] is True

        conn_a = connect()
        cur_a = conn_a.cursor()
        with pytest.raises(psycopg.errors.SerializationFailure) as exc_info:
            verify(cur_a, ns, "job", "w1", old_fence)
        assert exc_info.value.diag.message_hint == FENCE_STALE_HINT
        conn_a.rollback()


class TestAcquireNonBlocking:
    """Contended acquires must not queue: a live held lease is answered from
    an unlocked fast path, and the locked (grantable) paths give up after the
    function's 2 second lock timeout with a plain miss."""

    def test_contended_acquire_does_not_block_behind_open_verify(
        self, test_helpers, connect
    ):
        """A live lease held by someone else is a miss answered without
        taking locks – even while a verify transaction holds FOR SHARE on
        the row, which would block any locked read indefinitely."""
        ns = test_helpers.namespace
        got = acquire(test_helpers.cursor, ns, "job", "w1")

        conn_a = connect()
        verify(conn_a.cursor(), ns, "job", "w1", got["fence_token"])

        start = time.monotonic()
        miss = acquire(test_helpers.cursor, ns, "job", "w2")
        elapsed = time.monotonic() - start
        conn_a.rollback()

        assert miss["acquired"] is False
        assert miss["current_holder"] == "w1"
        assert miss["expires_at"] is not None
        assert elapsed < 0.5, f"fast path took {elapsed:.2f}s - it must not lock"

    def test_lock_timeout_surfaces_as_plain_miss(self, test_helpers, connect):
        """An EXPIRED lease share-locked by an open verify transaction sends
        acquire to the locked takeover path; when the holder never commits,
        the 2 second lock timeout returns (false, NULL, NULL, NULL) instead
        of raising or waiting forever."""
        ns = test_helpers.namespace
        got = acquire(test_helpers.cursor, ns, "job", "w1")
        test_helpers.set_expires_at("job", "+1 second")

        conn_a = connect()
        verify(conn_a.cursor(), ns, "job", "w1", got["fence_token"])

        checks = 0
        while True:
            test_helpers.cursor.execute(
                "SELECT expires_at <= now() FROM lease.leases "
                "WHERE namespace = %s AND name = %s",
                (ns, "job"),
            )
            if test_helpers.cursor.fetchone()[0]:
                break
            checks += 1
            assert checks < 300, "lease never crossed its expiry"
            threading.Event().wait(0.02)

        conn_b = connect(statement_timeout_ms=10000)
        start = time.monotonic()
        miss = acquire(conn_b.cursor(), ns, "job", "w2")
        elapsed = time.monotonic() - start
        conn_b.rollback()
        conn_a.rollback()

        assert miss == {
            "acquired": False,
            "fence_token": None,
            "expires_at": None,
            "current_holder": None,
        }
        assert elapsed >= 2.0, f"returned after {elapsed:.2f}s - before the timeout"


class Test40001Disambiguation:
    """SDK-level: 40001 maps to LeaseFencingError ONLY with our hint.

    40001 is a shared sqlstate – a genuine serialization failure from inside
    a lease call must NOT be mistyped as a fencing error (the recovery paths
    differ: plain retry vs re-acquire-then-redo).
    """

    def test_stale_fence_raises_fencing_error(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        with (
            pytest.raises(LeaseFencingError) as exc_info,
            lease.cursor.connection.transaction(),
        ):
            lease.verify("job", "w1", got["fence_token"])
        assert exc_info.value.error_code == LeaseErrorCode.FENCE_STALE

    def test_hintless_40001_is_not_fencing_error(self, lease):
        """The blind-mapping regression test: a synthetic 40001 WITHOUT the
        FENCE_STALE hint surfaces as generic LeaseError, .sqlstate intact."""
        with pytest.raises(LeaseError) as exc_info:
            lease._fetch_val(
                """DO $$ BEGIN
                    RAISE EXCEPTION 'synthetic serialization failure'
                        USING ERRCODE = 'serialization_failure';
                END $$""",
                (),
            )
        assert not isinstance(exc_info.value, LeaseFencingError)
        assert exc_info.value.sqlstate == "40001"


class TestVerifyRequiresTransaction:
    """SDK guard: verify() outside an open transaction protects nothing
    (the wrapper transaction would commit and release the lock at return),
    so the client refuses to run it."""

    def test_verify_without_transaction_raises(self, lease):
        got = lease.acquire("job", "w1")

        # The lease fixture's connection is autocommit: no transaction open
        with pytest.raises(
            LeaseError, match="requires an open transaction"
        ) as exc_info:
            lease.verify("job", "w1", got["fence_token"])
        assert not isinstance(exc_info.value, LeaseFencingError)

    def test_verify_inside_transaction_succeeds(self, lease):
        got = lease.acquire("job", "w1")
        with lease.cursor.connection.transaction():
            lease.verify("job", "w1", got["fence_token"])  # no raise
