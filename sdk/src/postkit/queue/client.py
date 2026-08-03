"""Postkit Queue SDK - Postgres-native job queues."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import timedelta
from typing import Any, ClassVar, NoReturn

import psycopg

from postkit.base import BaseClient, PostkitError


class QueueError(PostkitError):
    """Exception for queue operations."""


class QueueValidationError(QueueError):
    """Raised when input validation fails."""


class QueueFencingError(QueueError):
    """The supplied token does not identify the current, unexpired attempt.

    Raised when the job is missing or no longer running, the token belongs to a
    different pull, or the visibility deadline has passed. Retrying with the same
    token cannot succeed.
    """


class QueueClient(BaseClient):
    """Client for Postkit queue module.

    Queue operations join an existing caller transaction, so a push, pull, or
    acknowledgement can commit or roll back with surrounding database work. On
    an idle connection, the SDK runs the operation in its own transaction.

    Example:
        queue = QueueClient(cursor, namespace="acme")

        queue.push("email", {"to": "alice@example.com", "subject": "Hello"})
        cursor.connection.commit()

        job = queue.pull("email", worker_id="worker-1")
        cursor.connection.commit()
        if job is not None:
            try:
                send_email(job["payload"], idempotency_key=f"queue:{job['id']}")
            except Exception as error:
                queue.nack(job["id"], job["fence_token"], error=str(error))
            else:
                queue.ack(job["id"], job["fence_token"])
            cursor.connection.commit()
    """

    _schema = "queue"
    _error_class = QueueError
    _module_sqlstate_map: ClassVar[dict[str, type[PostkitError]]] = {
        "22023": QueueValidationError,  # invalid_parameter_value
        "22004": QueueValidationError,  # null_value_not_allowed
        "22001": QueueValidationError,  # string_data_right_truncation
        "22026": QueueValidationError,  # string_data_length_mismatch
    }

    def _handle_error(self, e: psycopg.Error) -> NoReturn:
        # 40001 is shared with genuine serialization failures. Only the exact
        # SQL contract hint identifies a stale queue fence.
        sqlstate = getattr(e, "sqlstate", None)
        hint = e.diag.message_hint if hasattr(e, "diag") and e.diag else None
        if sqlstate == "40001" and hint == "postkit:queue:FENCE_STALE":
            raise QueueFencingError(str(e), sqlstate, hint) from e
        super()._handle_error(e)

    def __init__(self, cursor: Any, namespace: str) -> None:
        """Initialize the queue client.

        Args:
            cursor: A psycopg 3 cursor using the default tuple row factory
            namespace: Tenant namespace for multi-tenancy
        """
        super().__init__(cursor, namespace)

    def _apply_actor_context(self) -> None:
        """Apply actor context via queue.set_actor()."""
        self.cursor.execute(
            """SELECT queue.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    # =========================================================================
    # Push Operations
    # =========================================================================

    def push(
        self,
        queue: str,
        payload: dict[str, Any],
        *,
        delay: timedelta | None = None,
        priority: int = 0,
        max_attempts: int | None = None,
        unique_key: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int | None:
        """Push a job onto a queue.

        Args:
            queue: Queue name
            payload: Job payload (must be JSON-serializable)
            delay: Delay before job becomes visible
            priority: Job priority (-1000 to 1000, higher = more important)
            max_attempts: Maximum retry attempts (default from config)
            unique_key: Deduplication key (None = no dedup)
            tags: Optional tags for filtering
            metadata: Optional metadata

        Returns:
            Job ID, or None if deduplicated (unique_key already exists)
        """
        result = self._fetch_val(
            """SELECT queue.push(
                p_namespace := %s,
                p_queue := %s,
                p_payload := %s::jsonb,
                p_delay := %s,
                p_priority := %s,
                p_max_attempts := %s,
                p_unique_key := %s,
                p_tags := %s,
                p_metadata := %s::jsonb
            )""",
            (
                self.namespace,
                queue,
                json.dumps(payload),
                delay,
                priority,
                max_attempts,
                unique_key,
                tags,
                json.dumps(metadata) if metadata else None,
            ),
            write=True,
        )
        return int(result) if result is not None else None

    def push_batch(
        self,
        queue: str,
        payloads: list[dict[str, Any]],
        *,
        priority: int = 0,
        max_attempts: int | None = None,
        tags: list[str] | None = None,
    ) -> list[int]:
        """Push multiple jobs onto a queue efficiently.

        Args:
            queue: Queue name
            payloads: List of job payloads
            priority: Priority for all jobs
            max_attempts: Maximum retry attempts for all jobs
            tags: Tags for all jobs

        Returns:
            List of job IDs
        """
        result = self._fetch_val(
            """SELECT queue.push_batch(
                p_namespace := %s,
                p_queue := %s,
                p_payloads := %s::jsonb[],
                p_priority := %s,
                p_max_attempts := %s,
                p_tags := %s
            )""",
            (
                self.namespace,
                queue,
                [json.dumps(p) for p in payloads],
                priority,
                max_attempts,
                tags,
            ),
            write=True,
        )
        return [int(x) for x in result] if result else []

    # =========================================================================
    # Pull Operations
    # =========================================================================

    def pull(
        self,
        queue: str,
        *,
        worker_id: str | None = None,
        visibility_timeout: timedelta | None = None,
    ) -> dict[str, Any] | None:
        """Pull one job from a queue.

        The job becomes running and receives a fence token that must accompany
        later operations on this attempt. If no job is available, returns None.

        Database-only work and settlement may share the pull transaction.
        Before an external effect, confirm that the pull committed and use a stable
        idempotency key. After a rollback or unknown commit outcome, discard the
        result, reconnect, and poll again.

        Args:
            queue: Queue name
            worker_id: Optional diagnostic worker identifier
            visibility_timeout: How long before tick_timeouts may reclaim the job

        Returns:
            Job dict with its payload, attempt count, and fence_token, or None
        """
        result = self._fetch_one(
            """SELECT * FROM queue.pull(
                p_namespace := %s,
                p_queue := %s,
                p_worker_id := %s,
                p_visibility_timeout := %s
            )""",
            (
                self.namespace,
                queue,
                worker_id,
                visibility_timeout,
            ),
            write=True,
        )
        return result

    def pull_batch(
        self,
        queue: str,
        limit: int = 10,
        *,
        worker_id: str | None = None,
        visibility_timeout: timedelta | None = None,
    ) -> list[dict[str, Any]]:
        """Pull multiple jobs from a queue.

        Pulls up to limit jobs in one operation. Each returned job has its own
        fence token for later operations on that attempt.

        Database-only work and settlement may share the pull transaction.
        Before external effects, confirm that the pull committed and use stable
        idempotency keys. After a rollback or unknown commit outcome, discard the
        results, reconnect, and poll again.

        Args:
            queue: Queue name
            limit: Maximum jobs to pull
            worker_id: Optional diagnostic worker identifier
            visibility_timeout: How long before tick_timeouts may reclaim the jobs

        Returns:
            Job dicts with payloads, attempt counts, and distinct fence_token values
        """
        result = self._fetch_all(
            """SELECT * FROM queue.pull_batch(
                p_namespace := %s,
                p_queue := %s,
                p_limit := %s,
                p_worker_id := %s,
                p_visibility_timeout := %s
            )""",
            (
                self.namespace,
                queue,
                limit,
                worker_id,
                visibility_timeout,
            ),
            write=True,
        )
        return result

    def pull_any(
        self,
        queues: list[str],
        *,
        worker_id: str | None = None,
        visibility_timeout: timedelta | None = None,
    ) -> dict[str, Any] | None:
        """Pull one job from the first available queue in priority order.

        The job becomes running and receives a fence token that must accompany
        later operations on this attempt.

        Database-only work and settlement may share the pull transaction.
        Before an external effect, confirm that the pull committed and use a stable
        idempotency key. After a rollback or unknown commit outcome, discard the
        result, reconnect, and poll again.

        Args:
            queues: Queue names in priority order (first checked first)
            worker_id: Optional diagnostic worker identifier
            visibility_timeout: How long before tick_timeouts may reclaim the job

        Returns:
            Job dict including fence_token, or None if every queue is empty

        Example:
            job = queue.pull_any(["critical", "default", "bulk"])
        """
        result = self._fetch_one(
            """SELECT * FROM queue.pull_any(
                p_namespace := %s,
                p_queues := %s,
                p_worker_id := %s,
                p_visibility_timeout := %s
            )""",
            (
                self.namespace,
                queues,
                worker_id,
                visibility_timeout,
            ),
            write=True,
        )
        return result

    def extend_visibility(
        self,
        job_id: int,
        fence: int,
        extension: timedelta,
    ) -> bool:
        """Extend the visibility timeout of a running job.

        Use this when processing will outlast the current deadline. The extension
        is added to that deadline, not to the current time. Raises QueueFencingError
        when the supplied token no longer identifies the current, unexpired attempt.

        Args:
            job_id: Job ID
            fence: Fence token returned by pull
            extension: Amount of time to add to the current visibility timeout

        Returns:
            True if extended
        """
        result = self._fetch_val(
            """SELECT queue.extend_visibility(
                p_namespace := %s,
                p_job_id := %s,
                p_fence := %s,
                p_extension := %s
            )""",
            (
                self.namespace,
                job_id,
                fence,
                extension,
            ),
            write=True,
        )
        return bool(result)

    # =========================================================================
    # Completion Operations
    # =========================================================================

    def ack(self, job_id: int, fence: int) -> bool:
        """Acknowledge successful job completion.

        The job is deleted or retained as completed according to the queue's
        archive_completed setting. Raises QueueFencingError when the supplied token
        no longer identifies the current, unexpired attempt.

        Args:
            job_id: Job ID
            fence: Fence token returned by pull

        Returns:
            True if acknowledged
        """
        result = self._fetch_val(
            """SELECT queue.ack(
                p_namespace := %s,
                p_job_id := %s,
                p_fence := %s
            )""",
            (self.namespace, job_id, fence),
            write=True,
        )
        return bool(result)

    def ack_batch(self, jobs: Sequence[tuple[int, int]]) -> int:
        """Acknowledge multiple jobs atomically.

        Every member is validated before any job changes. A missing or non-running
        job, an expired attempt, or a token from another pull raises
        QueueFencingError and leaves the batch unchanged. An empty sequence returns
        zero; duplicate job IDs are rejected.

        Args:
            jobs: Sequence of (job_id, fence) pairs

        Returns:
            Count of jobs acknowledged
        """
        job_ids = [job_id for job_id, _ in jobs]
        fences = [fence for _, fence in jobs]
        result = self._fetch_val(
            """SELECT queue.ack_batch(
                p_namespace := %s,
                p_job_ids := %s::bigint[],
                p_fences := %s::bigint[]
            )""",
            (self.namespace, job_ids, fences),
            write=True,
        )
        return int(result) if result is not None else 0

    def nack(
        self,
        job_id: int,
        fence: int,
        *,
        error: str | None = None,
        backoff: timedelta | None = None,
    ) -> bool:
        """Schedule another attempt, or dead-letter the job when none remain.

        The error is stored for diagnosis. A custom backoff overrides the queue's
        exponential delay. Raises QueueFencingError when the supplied token no longer
        identifies the current, unexpired attempt.

        Args:
            job_id: Job ID
            fence: Fence token returned by pull
            error: Error message (stored for debugging)
            backoff: Custom backoff delay (default: exponential)

        Returns:
            True if returned to the queue, False if moved to the dead-letter queue
        """
        result = self._fetch_val(
            """SELECT queue.nack(
                p_namespace := %s,
                p_job_id := %s,
                p_fence := %s,
                p_error := %s,
                p_backoff := %s
            )""",
            (
                self.namespace,
                job_id,
                fence,
                error,
                backoff,
            ),
            write=True,
        )
        return bool(result)

    def fail(
        self,
        job_id: int,
        fence: int,
        *,
        error: str | None = None,
    ) -> bool:
        """Move a job directly to the dead-letter queue without retrying.

        Use this for failures that another attempt cannot fix, such as an invalid
        payload. Raises QueueFencingError when the supplied token no longer identifies
        the current, unexpired attempt.

        Args:
            job_id: Job ID
            fence: Fence token returned by pull
            error: Error message

        Returns:
            True if moved to the dead-letter queue
        """
        result = self._fetch_val(
            """SELECT queue.fail(
                p_namespace := %s,
                p_job_id := %s,
                p_fence := %s,
                p_error := %s
            )""",
            (
                self.namespace,
                job_id,
                fence,
                error,
            ),
            write=True,
        )
        return bool(result)

    def release(self, job_id: int, fence: int) -> bool:
        """Return a running job to pending immediately, without backoff.

        Release preserves the attempt count and affects only the supplied pull.
        During graceful shutdown, release each in-flight job instead of waiting
        for timeout recovery. Raises QueueFencingError when the supplied token no
        longer identifies the current, unexpired attempt.

        Args:
            job_id: Job ID
            fence: Fence token returned by pull

        Returns:
            True if released
        """
        result = self._fetch_val(
            """SELECT queue.release(
                p_namespace := %s,
                p_job_id := %s,
                p_fence := %s
            )""",
            (self.namespace, job_id, fence),
            write=True,
        )
        return bool(result)

    def cancel(self, job_id: int) -> bool:
        """Cancel a pending job by deleting it.

        Running jobs must instead be acknowledged, returned for retry, failed, or
        released. Cancelled jobs are not archived because they were never processed.

        Args:
            job_id: Job ID

        Returns:
            True if cancelled, False if job not found or not pending
        """
        result = self._fetch_val(
            """SELECT queue.cancel(
                p_namespace := %s,
                p_job_id := %s
            )""",
            (self.namespace, job_id),
            write=True,
        )
        return bool(result)

    def purge_queue(self, queue: str) -> int:
        """Delete all pending jobs from a queue.

        Running, completed, and dead jobs are not affected. Release running jobs
        individually, or wait for timeout recovery, before purging if they should
        also be removed.

        Args:
            queue: Queue name

        Returns:
            Count of deleted jobs
        """
        result = self._fetch_val(
            """SELECT queue.purge_queue(
                p_namespace := %s,
                p_queue := %s
            )""",
            (self.namespace, queue),
            write=True,
        )
        return int(result) if result is not None else 0

    # =========================================================================
    # Stats
    # =========================================================================

    def get_stats(self) -> dict[str, Any]:
        """Get namespace-wide queue statistics.

        Returns:
            Dict with total_jobs, pending, running, completed, dead, and
            total_queues counts
        """
        result = self._fetch_one(
            "SELECT * FROM queue.get_stats(%s)",
            (self.namespace,),
        )
        return result or {}

    def get_queue_stats(self, queue: str | None = None) -> list[dict[str, Any]]:
        """Get per-queue statistics with operational metrics.

        Unlike get_stats (namespace-wide totals), this breaks down by queue
        and includes operational metrics: how stale the backlog is and how
        many jobs have failed.

        Args:
            queue: Queue filter (None = all queues)

        Returns:
            List of dicts with queue, pending, running, completed, dead,
            oldest_pending_seconds, and dead_letters (un-retried only) per queue
        """
        return self._fetch_all(
            """SELECT * FROM queue.get_queue_stats(
                p_namespace := %s,
                p_queue := %s
            )""",
            (self.namespace, queue),
        )

    # =========================================================================
    # Schedule Operations
    # =========================================================================

    def create_schedule(
        self,
        name: str,
        queue: str,
        payload: dict[str, Any],
        *,
        cron_expression: str | None = None,
        cron_timezone: str = "UTC",
        every_interval: timedelta | None = None,
        priority: int = 0,
        max_attempts: int = 3,
        tags: list[str] | None = None,
        is_active: bool = True,
    ) -> int:
        """Create a recurring schedule that produces jobs automatically.

        Schedules use either a cron expression or a fixed interval, not both.
        The schedule is identified by name (unique within the namespace).

        Args:
            name: Schedule name
            queue: Target queue name for generated jobs
            payload: Job payload template (must be JSON-serializable)
            cron_expression: Standard 5-field cron ('*/5 * * * *')
            cron_timezone: Timezone for cron evaluation (default 'UTC')
            every_interval: Fixed interval between runs (alternative to cron)
            priority: Job priority (-1000 to 1000)
            max_attempts: Maximum retry attempts for generated jobs
            tags: Tags applied to generated jobs
            is_active: Whether schedule starts active (default True)

        Returns:
            Schedule ID
        """
        result = self._fetch_val(
            """SELECT queue.create_schedule(
                p_namespace := %s,
                p_name := %s,
                p_queue := %s,
                p_payload := %s::jsonb,
                p_cron_expression := %s,
                p_cron_timezone := %s,
                p_every_interval := %s,
                p_priority := %s,
                p_max_attempts := %s,
                p_tags := %s,
                p_is_active := %s
            )""",
            (
                self.namespace,
                name,
                queue,
                json.dumps(payload),
                cron_expression,
                cron_timezone,
                every_interval,
                priority,
                max_attempts,
                tags,
                is_active,
            ),
            write=True,
        )
        if result is None:
            raise QueueError("queue.create_schedule returned no value")
        return int(result)

    def get_schedule(self, name: str) -> dict[str, Any] | None:
        """Get a schedule by name.

        Args:
            name: Schedule name

        Returns:
            Schedule dict with all fields, or None if not found
        """
        return self._fetch_one(
            """SELECT * FROM queue.get_schedule(
                p_namespace := %s,
                p_name := %s
            )""",
            (self.namespace, name),
        )

    def list_schedules(
        self,
        *,
        queue: str | None = None,
        is_active: bool | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> list[dict[str, Any]]:
        """List schedules with optional filters and cursor pagination.

        Args:
            queue: Filter by target queue name
            is_active: Filter by active status
            limit: Maximum results (max 1000)
            cursor: Last schedule name from previous page

        Returns:
            List of schedule dicts ordered by name
        """
        return self._fetch_all(
            """SELECT * FROM queue.list_schedules(
                p_namespace := %s,
                p_queue := %s,
                p_is_active := %s,
                p_limit := %s,
                p_cursor := %s
            )""",
            (self.namespace, queue, is_active, limit, cursor),
        )

    def delete_schedule(self, name: str) -> bool:
        """Delete a schedule by name.

        Args:
            name: Schedule name

        Returns:
            True if deleted, False if not found
        """
        result = self._fetch_val(
            """SELECT queue.delete_schedule(
                p_namespace := %s,
                p_name := %s
            )""",
            (self.namespace, name),
            write=True,
        )
        return bool(result)

    def pause_schedule(self, name: str) -> bool:
        """Pause an active schedule.

        Args:
            name: Schedule name

        Returns:
            True if paused, False if already paused or not found
        """
        result = self._fetch_val(
            """SELECT queue.pause_schedule(
                p_namespace := %s,
                p_name := %s
            )""",
            (self.namespace, name),
            write=True,
        )
        return bool(result)

    def resume_schedule(self, name: str) -> bool:
        """Resume a paused schedule. Recalculates next_run_at from now.

        Args:
            name: Schedule name

        Returns:
            True if resumed, False if already active or not found
        """
        result = self._fetch_val(
            """SELECT queue.resume_schedule(
                p_namespace := %s,
                p_name := %s
            )""",
            (self.namespace, name),
            write=True,
        )
        return bool(result)

    def tick_schedules(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Process due schedules and create jobs.

        Finds active schedules where next_run_at <= now(), creates a job for
        each, and advances their next_run_at. Uses FOR UPDATE SKIP LOCKED for
        safe concurrent execution from multiple workers.

        Args:
            limit: Maximum schedules to process per call

        Returns:
            List of dicts with schedule_name, job_id, and next_run_at
        """
        return self._fetch_all(
            """SELECT * FROM queue.tick_schedules(
                p_namespace := %s,
                p_limit := %s
            )""",
            (self.namespace, limit),
            write=True,
        )

    def tick_timeouts(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Reclaim running jobs whose visibility timeout has expired.

        Workers that crash or hang leave jobs stuck in 'running' status. This
        function returns them to 'pending' for re-delivery. Call periodically
        alongside tick_schedules().

        Args:
            limit: Maximum jobs to reclaim per call

        Returns:
            List of dicts with job_id, queue, and stuck_duration
        """
        return self._fetch_all(
            """SELECT * FROM queue.tick_timeouts(
                p_namespace := %s,
                p_limit := %s
            )""",
            (self.namespace, limit),
            write=True,
        )

    # =========================================================================
    # Dead Letter Operations
    # =========================================================================

    def retry_dead_letter(
        self,
        dead_letter_id: int,
        *,
        queue: str | None = None,
    ) -> int:
        """Retry a dead-lettered job by creating a new job from its payload.

        The dead letter is marked as retried to prevent double-retry. The new
        job gets a fresh attempt counter and the caller's actor context (not
        the original actor).

        Args:
            dead_letter_id: Dead letter ID
            queue: Queue override (None = use original queue)

        Returns:
            New job ID

        Raises:
            QueueError: If dead letter not found or already retried
        """
        result = self._fetch_val(
            """SELECT queue.retry_dead_letter(
                p_namespace := %s,
                p_dead_letter_id := %s,
                p_queue := %s
            )""",
            (self.namespace, dead_letter_id, queue),
            write=True,
        )
        if result is None:
            raise QueueError("queue.retry_dead_letter returned no value")
        return int(result)

    def retry_dead_letters(
        self,
        queue: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retry multiple dead letters for a queue in a single transaction.

        Retries un-retried dead letters oldest-first. Uses FOR UPDATE SKIP
        LOCKED so concurrent callers do not double-retry.

        Args:
            queue: Queue to retry dead letters from
            limit: Maximum dead letters to retry (max 1000)

        Returns:
            List of dicts with dead_letter_id and job_id for each retry
        """
        return self._fetch_all(
            """SELECT * FROM queue.retry_dead_letters(
                p_namespace := %s,
                p_queue := %s,
                p_limit := %s
            )""",
            (self.namespace, queue, limit),
            write=True,
        )

    def purge_dead_letters(
        self,
        *,
        queue: str | None = None,
        older_than: timedelta = timedelta(days=30),
    ) -> int:
        """Delete old un-retried dead letters.

        Only purges un-retried entries. Retried dead letters are kept as
        historical records linking the failure to its retry job.

        Args:
            queue: Queue filter (None = all queues)
            older_than: Only delete entries older than this (default 30 days)

        Returns:
            Count of deleted dead letters
        """
        result = self._fetch_val(
            """SELECT queue.purge_dead_letters(
                p_namespace := %s,
                p_queue := %s,
                p_older_than := %s
            )""",
            (self.namespace, queue, older_than),
            write=True,
        )
        return int(result) if result is not None else 0
