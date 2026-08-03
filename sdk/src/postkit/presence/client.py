"""Postkit Presence SDK - heartbeat liveness with transition edge detection."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, ClassVar

from postkit.base import BaseClient, PostkitError


class PresenceError(PostkitError):
    """Exception for presence operations."""


class PresenceValidationError(PresenceError):
    """Raised when input validation fails."""


class PresenceClient(BaseClient):
    """Client for Postkit presence module.

    Heartbeat liveness for a fleet of entities. Register once, heartbeat
    periodically, and run sweep() on a timer; the module emits an
    append-only transition stream (alive -> dead -> alive) and can enqueue
    alert jobs atomically with each edge when the queue module is
    installed.

    Example:
        presence = PresenceClient(cursor, namespace="acme")

        presence.register("worker-7")            # once, idempotent
        presence.heartbeat("worker-7")           # every 10-60s

        # From a cron, anywhere:
        for death in presence.sweep():
            page(death["entity_id"])
    """

    _schema = "presence"
    _error_class = PresenceError
    _module_sqlstate_map: ClassVar[dict[str, type[PostkitError]]] = {
        "22023": PresenceValidationError,  # invalid_parameter_value
        "22004": PresenceValidationError,  # null_value_not_allowed
        "22001": PresenceValidationError,  # string_data_right_truncation
        "22026": PresenceValidationError,  # string_data_length_mismatch
    }

    def _apply_actor_context(self) -> None:
        """Apply actor context via presence.set_actor()."""
        self.cursor.execute(
            """SELECT presence.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def register(
        self,
        entity: str,
        *,
        kind: str | None = None,
        timeout: timedelta | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register an entity for liveness tracking, or update its attributes.

        Idempotent: None arguments preserve what is stored, so deploys can
        re-run register safely. Re-registering is an attribute update, not
        a heartbeat - liveness only changes through heartbeat() and
        sweep(). A new entity starts at 'unknown' and cannot die before its
        first heartbeat.

        Args:
            entity: Entity id (e.g. 'worker-7', 'sensor:eu:42')
            kind: Entity kind, keys the config row. None means 'default'
                for a new entity and keeps the current kind on re-register
            timeout: Per-entity liveness window replacing the kind's
                dead_after. None keeps the current override
            metadata: Metadata stored on the entity; None keeps the
                existing metadata on re-register (new entities start empty)

        Returns:
            The entity row dict
        """
        result = self._fetch_one(
            """SELECT * FROM presence.register(
                p_namespace := %s,
                p_entity := %s,
                p_kind := %s,
                p_timeout := %s,
                p_metadata := %s::jsonb
            )""",
            (
                self.namespace,
                entity,
                kind,
                timeout,
                json.dumps(metadata) if metadata is not None else None,
            ),
            write=True,
        )
        if result is None:
            raise PresenceError("presence.register returned no row")
        return result

    def heartbeat(self, entity: str) -> str:
        """Report an entity alive.

        A dead or never-seen entity revives here and now - the revival
        transition is emitted by this call, never deferred to a sweep. An
        unregistered entity raises (registration is explicit;
        heartbeat_many reports 'unknown' instead of raising).

        Args:
            entity: Entity id (must be registered)

        Returns:
            The resulting status (always 'alive')
        """
        result = self._fetch_val(
            "SELECT presence.heartbeat(%s, %s)",
            (self.namespace, entity),
            write=True,
        )
        if result is None:
            raise PresenceError("presence.heartbeat returned no value")
        return str(result)

    def heartbeat_many(self, entities: list[str]) -> list[dict[str, Any]]:
        """Report a batch of entities alive in one round trip.

        Per-entity semantics match heartbeat(), including revivals.
        Unregistered entities come back with status 'unknown' instead of
        raising - one typo must not abort a fleet batch.

        Args:
            entities: Entity ids

        Returns:
            One dict per distinct entity: entity_id and its resulting status
        """
        return self._fetch_all(
            "SELECT * FROM presence.heartbeat_many(%s, %s)",
            (self.namespace, entities),
            write=True,
        )

    def sweep(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """Mark overdue entities dead and deliver deferred death alerts.

        Call from a cron or timer; nothing runs on its own, and death is
        detected no faster than the sweep cadence. Deaths emit transitions
        and fire the configured queue hooks in the same transaction.

        Args:
            limit: Maximum entities to process per call

        Returns:
            The death transitions emitted by this call
        """
        return self._fetch_all(
            "SELECT * FROM presence.sweep(%s, %s)",
            (self.namespace, limit),
            write=True,
        )

    def deregister(self, entity: str) -> bool:
        """Remove an entity deliberately, emitting a departed transition.

        Intentional exit is not death: no death hooks fire and nobody gets
        paged for a planned shutdown. Idempotent - removing an absent
        entity returns False, never raises.

        Args:
            entity: Entity id

        Returns:
            True if the entity existed and was removed
        """
        result = self._fetch_val(
            "SELECT presence.deregister(%s, %s)",
            (self.namespace, entity),
            write=True,
        )
        return bool(result)

    def status(self, entity: str) -> dict[str, Any] | None:
        """Inspect one entity, with the wall-clock truth alongside the cache.

        The stored status lags until the next sweep; the returned overdue
        flag is true when the entity is nominally alive but already past
        its liveness window.

        Args:
            entity: Entity id

        Returns:
            Dict with the liveness fields plus overdue, or None when the
            entity is not registered
        """
        return self._fetch_one(
            "SELECT * FROM presence.status(%s, %s)", (self.namespace, entity)
        )

    def list_entities(
        self, *, kind: str | None = None, status: str | None = None
    ) -> list[dict[str, Any]]:
        """List entities in the namespace.

        Args:
            kind: Kind filter (None = all kinds)
            status: Status filter: 'unknown', 'alive', or 'dead'

        Returns:
            List of entity row dicts
        """
        return self._fetch_all(
            "SELECT * FROM presence.list(%s, %s, %s)",
            (self.namespace, kind, status),
        )

    def get_transitions(
        self, entity: str | None = None, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Read the transition history, newest first.

        History, not a feed: delivery is the queue hooks and NOTIFY; do
        not poll this by id.

        Args:
            entity: Entity filter (None = all entities)
            limit: Maximum transitions to return

        Returns:
            List of transition dicts with actor context
        """
        return self._fetch_all(
            "SELECT * FROM presence.get_transitions(%s, %s, %s)",
            (self.namespace, entity, limit),
        )

    def get_stats(self) -> dict[str, Any]:
        """Get namespace-wide presence statistics.

        Returns:
            Dict with total_entities, alive, dead, unknown, overdue, and
            total_transitions counts
        """
        result = self._fetch_one(
            "SELECT * FROM presence.get_stats(%s)", (self.namespace,)
        )
        return result or {}

    def trim(
        self, older_than: timedelta, *, limit: int = 10000
    ) -> list[dict[str, Any]]:
        """Delete old transitions. Retention has no default; pass it explicitly.

        Args:
            older_than: Delete transitions older than this (required, positive)
            limit: Maximum transitions to delete per call

        Returns:
            One dict per namespace touched, with the deleted count
        """
        return self._fetch_all(
            "SELECT * FROM presence.trim(%s, %s, %s)",
            (older_than, self.namespace, limit),
            write=True,
        )
