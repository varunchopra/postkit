"""Postkit Lease SDK - Postgres-native leases with fencing tokens."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, ClassVar, NoReturn

import psycopg

from postkit.base import BaseClient, PostkitError


class LeaseError(PostkitError):
    """Exception for lease operations."""


class LeaseValidationError(LeaseError):
    """Raised when input validation fails."""


class LeaseFencingError(LeaseError):
    """Raised by verify() when the lease is lost, expired, or taken over.

    The fence is dead: the correct recovery is RE-ACQUIRE, THEN REDO the
    work – never replay the same transaction with the same fence (the replay
    fails deterministically, so a naive retry loop spins).
    """


class LeaseClient(BaseClient):
    """Client for Postkit lease module.

    TTL-based named locks with fencing tokens. Call verify() inside the same
    transaction as the writes the lease protects – the fence check and the
    protected writes then commit or abort together.

    Example:
        lease = LeaseClient(cursor, namespace="acme")

        got = lease.acquire("scheduler", holder="worker-1")
        if got["acquired"]:
            fence = got["fence_token"]
            # ... inside the protected transaction:
            lease.verify("scheduler", "worker-1", fence)  # raises if lost
            # ... protected writes ...
            lease.release("scheduler", "worker-1", fence)
    """

    _schema = "lease"
    _error_class = LeaseError
    _module_sqlstate_map: ClassVar[dict[str, type[PostkitError]]] = {
        "22023": LeaseValidationError,  # invalid_parameter_value
        "22004": LeaseValidationError,  # null_value_not_allowed
        "22001": LeaseValidationError,  # string_data_right_truncation
        "22026": LeaseValidationError,  # string_data_length_mismatch
    }

    def _handle_error(self, e: psycopg.Error) -> NoReturn:
        # 40001 is a SHARED sqlstate: FOR SHARE under REPEATABLE READ can
        # raise a genuine serialization failure inside any lease call. Only
        # our hint makes it a fencing error; everything else must surface as
        # the retryable serialization error it is (generic LeaseError,
        # .sqlstate intact).
        sqlstate = getattr(e, "sqlstate", None)
        hint = e.diag.message_hint if hasattr(e, "diag") and e.diag else None
        if sqlstate == "40001" and hint == "postkit:lease:FENCE_STALE":
            raise LeaseFencingError(str(e), sqlstate, hint) from e
        super()._handle_error(e)

    def _apply_actor_context(self) -> None:
        """Apply actor context via lease.set_actor()."""
        self.cursor.execute(
            """SELECT lease.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def acquire(
        self,
        name: str,
        holder: str,
        *,
        ttl: timedelta | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Acquire or take over a named lease.

        A free or expired lease makes the caller the holder with a new fence
        token (takeovers are event-logged). Re-acquiring a lease you already
        hold live extends it with the SAME fence; passing metadata replaces
        the stored value, passing None keeps it. A lease held live by
        someone else is not touched.

        Do not call verify() then acquire() on the same name inside one
        transaction: under concurrency that can abort as a deadlock
        (SQLSTATE 40P01, retryable).

        Args:
            name: Lease name (e.g. 'scheduler', 'exporter:cust_42')
            holder: Opaque holder identity (hostname, pod name, worker ID)
            ttl: Lease duration (default from config; capped at max_ttl)
            metadata: Metadata stored on the lease; None keeps the existing
                metadata on a live re-acquire (new acquisitions start empty)

        Returns:
            Dict with acquired (bool), fence_token (None when held by
            another live holder), expires_at, and current_holder (all
            None on a lock timeout - an ordinary contended miss).
        """
        result = self._fetch_one(
            """SELECT * FROM lease.acquire(
                p_namespace := %s,
                p_name := %s,
                p_holder := %s,
                p_ttl := %s,
                p_metadata := %s::jsonb
            )""",
            (
                self.namespace,
                name,
                holder,
                ttl,
                json.dumps(metadata) if metadata is not None else None,
            ),
            write=True,
        )
        if result is None:
            raise LeaseError("lease.acquire returned no row")
        return result

    def renew(
        self,
        name: str,
        holder: str,
        fence: int,
        *,
        ttl: timedelta | None = None,
    ) -> dict[str, Any]:
        """Extend a live lease you hold.

        Fails (renewed=False) once the lease is past its expiry – even if
        nobody else has taken it. Re-acquire to continue, receiving a new
        fence. Does not update metadata (acquire's same-holder path does).

        Args:
            name: Lease name
            holder: Holder identity (must match the lease)
            fence: Fence token from acquire (must match the lease)
            ttl: New duration from now (default from config; capped at max_ttl)

        Returns:
            Dict with renewed (bool) and expires_at (None when not renewed)
        """
        result = self._fetch_one(
            """SELECT * FROM lease.renew(
                p_namespace := %s,
                p_name := %s,
                p_holder := %s,
                p_fence := %s,
                p_ttl := %s
            )""",
            (self.namespace, name, holder, fence, ttl),
            write=True,
        )
        if result is None:
            raise LeaseError("lease.renew returned no row")
        return result

    def release(self, name: str, holder: str, fence: int) -> bool:
        """Release a lease you hold.

        Idempotent: releasing a lease you no longer hold returns False,
        never raises.

        Args:
            name: Lease name
            holder: Holder identity (must match the lease)
            fence: Fence token from acquire (must match the lease)

        Returns:
            True if released, False if not held with this holder and fence
        """
        result = self._fetch_val(
            "SELECT lease.release(%s, %s, %s, %s)",
            (self.namespace, name, holder, fence),
            write=True,
        )
        return bool(result)

    def verify(self, name: str, holder: str, fence: int) -> None:
        """Assert, inside your transaction, that you still hold a lease.

        Must be called inside the same open transaction as the writes the
        lease protects; the check and the writes then commit or abort
        together. Without one (autocommit, or between transactions) the
        fence lock would be released immediately and protect nothing, so
        this method refuses to run.

        Do not call verify() then acquire() on the same name inside one
        transaction: under concurrency that can abort as a deadlock
        (SQLSTATE 40P01, retryable).

        Args:
            name: Lease name
            holder: Holder identity (must match the lease)
            fence: Fence token from acquire (must match the lease)

        Raises:
            LeaseError: No transaction is open on the connection.
            LeaseFencingError: The lease is lost, expired, or taken over.
                Re-acquire, then redo – never replay with the same fence.
        """
        # Same check _with_context uses: without an open transaction it
        # would wrap verify in its own transaction that commits at return,
        # releasing the FOR SHARE lock and silently voiding the guarantee.
        if self.cursor.connection.info.transaction_status == 0:
            raise LeaseError(
                "verify() requires an open transaction: without one the "
                "fence lock is released immediately and protects nothing. "
                "Open a transaction around verify() and the writes it "
                "protects."
            )
        self._fetch_val(
            "SELECT lease.verify(%s, %s, %s, %s)",
            (self.namespace, name, holder, fence),
        )

    def current(self, name: str) -> dict[str, Any] | None:
        """Inspect a lease without locking it.

        Returns the row even when past its expiry (compare expires_at to
        judge liveness); use verify() for a fenced check.

        Args:
            name: Lease name

        Returns:
            Dict with holder_id, fence_token, expires_at, metadata,
            or None when no lease row exists
        """
        return self._fetch_one(
            "SELECT * FROM lease.current(%s, %s)", (self.namespace, name)
        )

    def get_stats(self) -> dict[str, Any]:
        """Get namespace-wide lease statistics.

        Returns:
            Dict with total_leases, live, expired, total_names (every lease
            name ever used), and total_events counts
        """
        result = self._fetch_one(
            "SELECT * FROM lease.get_stats(%s)",
            (self.namespace,),
        )
        return result or {}

    def get_events(
        self, name: str | None = None, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Read the lease event log, newest first.

        Args:
            name: Lease name filter (None = all names)
            limit: Maximum events to return

        Returns:
            List of event dicts (acquired, released, taken_over) with
            actor context
        """
        return self._fetch_all(
            "SELECT * FROM lease.get_events(%s, %s, %s)",
            (self.namespace, name, limit),
        )

    def prune_events(
        self, older_than: timedelta, name: str | None = None, *, limit: int = 10000
    ) -> int:
        """Delete old lease events.

        The event log is the module's audit surface, so retention has no
        default – pass it explicitly and call this from a maintenance loop.
        Each call deletes at most `limit` events; call repeatedly until the
        return value is below the limit.

        Args:
            older_than: Delete events older than this (required, positive)
            name: Lease name filter (None = all names)
            limit: Maximum events to delete per call

        Returns:
            Count of deleted events
        """
        result = self._fetch_val(
            "SELECT lease.prune_events(%s, %s, %s, %s)",
            (self.namespace, older_than, name, limit),
            write=True,
        )
        if result is None:
            raise LeaseError("lease.prune_events returned no value")
        return int(result)

    def list_leases(self, *, include_expired: bool = True) -> list[dict[str, Any]]:
        """List leases in the namespace, most recently acquired first.

        Args:
            include_expired: Include rows past their expiry (default True)

        Returns:
            List of lease row dicts
        """
        return self._fetch_all(
            "SELECT * FROM lease.list(%s, %s)", (self.namespace, include_expired)
        )
