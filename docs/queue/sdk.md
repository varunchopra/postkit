<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Queue Python SDK

### ack

```python
ack(job_id: int, fence: int) -> bool
```

Acknowledge successful job completion.

The job is deleted or retained as completed according to the queue's archive_completed setting. Raises QueueFencingError when the supplied token no longer identifies the current, unexpired attempt.

**Parameters:**
- `job_id`: Job ID
- `fence`: Fence token returned by pull

**Returns:** True if acknowledged

*Source: sdk/src/postkit/queue/client.py:374*

---

### ack_batch

```python
ack_batch(jobs: Sequence[tuple[int, int]]) -> int
```

Acknowledge multiple jobs atomically.

Every member is validated before any job changes. A missing or non-running job, an expired attempt, or a token from another pull raises QueueFencingError and leaves the batch unchanged. An empty sequence returns zero; duplicate job IDs are rejected.

**Parameters:**
- `jobs`: Sequence of (job_id, fence) pairs

**Returns:** Count of jobs acknowledged

*Source: sdk/src/postkit/queue/client.py:399*

---

### assert_rls_active

```python
assert_rls_active() -> None
```

Raise unless row-level security applies to the connection's role.

Call from CI setup: a suite connecting as a superuser or BYPASSRLS role bypasses every policy and exercises none of the tenancy model.

*Source: sdk/src/postkit/base.py:397*

---

### cancel

```python
cancel(job_id: int) -> bool
```

Cancel a pending job by deleting it.

Running jobs must instead be acknowledged, returned for retry, failed, or released. Cancelled jobs are not archived because they were never processed.

**Parameters:**
- `job_id`: Job ID

**Returns:** True if cancelled, False if job not found or not pending

*Source: sdk/src/postkit/queue/client.py:532*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:390*

---

### create_schedule

```python
create_schedule(name: str, queue: str, payload: dict[str, Any], *, cron_expression: str | None = None, cron_timezone: str = 'UTC', every_interval: timedelta | None = None, priority: int = 0, max_attempts: int = 3, tags: list[str] | None = None, is_active: bool = True) -> int
```

Create a recurring schedule that produces jobs automatically.

Schedules use either a cron expression or a fixed interval, not both. The schedule is identified by name (unique within the namespace).

**Parameters:**
- `name`: Schedule name
- `queue`: Target queue name for generated jobs
- `payload`: Job payload template (must be JSON-serializable)
- `cron_expression`: Standard 5-field cron ('*/5 * * * *')
- `cron_timezone`: Timezone for cron evaluation (default 'UTC')
- `every_interval`: Fixed interval between runs (alternative to cron)
- `priority`: Job priority (-1000 to 1000)
- `max_attempts`: Maximum retry attempts for generated jobs
- `tags`: Tags applied to generated jobs
- `is_active`: Whether schedule starts active (default True)

**Returns:** Schedule ID

*Source: sdk/src/postkit/queue/client.py:620*

---

### delete_schedule

```python
delete_schedule(name: str) -> bool
```

Delete a schedule by name.

**Parameters:**
- `name`: Schedule name

**Returns:** True if deleted, False if not found

*Source: sdk/src/postkit/queue/client.py:734*

---

### extend_visibility

```python
extend_visibility(job_id: int, fence: int, extension: timedelta) -> bool
```

Extend the visibility timeout of a running job.

Use this when processing will outlast the current deadline. The extension is added to that deadline, not to the current time. Raises QueueFencingError when the supplied token no longer identifies the current, unexpired attempt.

**Parameters:**
- `job_id`: Job ID
- `fence`: Fence token returned by pull
- `extension`: Amount of time to add to the current visibility timeout

**Returns:** True if extended

*Source: sdk/src/postkit/queue/client.py:333*

---

### fail

```python
fail(job_id: int, fence: int, *, error: str | None = None) -> bool
```

Move a job directly to the dead-letter queue without retrying.

Use this for failures that another attempt cannot fix, such as an invalid payload. Raises QueueFencingError when the supplied token no longer identifies the current, unexpired attempt.

**Parameters:**
- `job_id`: Job ID
- `fence`: Fence token returned by pull
- `error`: Error message

**Returns:** True if moved to the dead-letter queue

*Source: sdk/src/postkit/queue/client.py:468*

---

### get_queue_stats

```python
get_queue_stats(queue: str | None = None) -> list[dict[str, Any]]
```

Get per-queue statistics with operational metrics.

Unlike get_stats (namespace-wide totals), this breaks down by queue and includes operational metrics: how stale the backlog is and how many jobs have failed.

**Parameters:**
- `queue`: Queue filter (None = all queues)

**Returns:** List of dicts with queue, pending, running, completed, dead,
oldest_pending_seconds, and dead_letters (un-retried only) per queue

*Source: sdk/src/postkit/queue/client.py:594*

---

### get_schedule

```python
get_schedule(name: str) -> dict[str, Any] | None
```

Get a schedule by name.

**Parameters:**
- `name`: Schedule name

**Returns:** Schedule dict with all fields, or None if not found

*Source: sdk/src/postkit/queue/client.py:687*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Get namespace-wide queue statistics.

**Returns:** Dict with total_jobs, pending, running, completed, dead, and
total_queues counts

*Source: sdk/src/postkit/queue/client.py:581*

---

### list_schedules

```python
list_schedules(*, queue: str | None = None, is_active: bool | None = None, limit: int = 100, cursor: str | None = None) -> list[dict[str, Any]]
```

List schedules with optional filters and cursor pagination.

**Parameters:**
- `queue`: Filter by target queue name
- `is_active`: Filter by active status
- `limit`: Maximum results (max 1000)
- `cursor`: Last schedule name from previous page

**Returns:** List of schedule dicts ordered by name

*Source: sdk/src/postkit/queue/client.py:704*

---

### nack

```python
nack(job_id: int, fence: int, *, error: str | None = None, backoff: timedelta | None = None) -> bool
```

Schedule another attempt, or dead-letter the job when none remain.

The error is stored for diagnosis. A custom backoff overrides the queue's exponential delay. Raises QueueFencingError when the supplied token no longer identifies the current, unexpired attempt.

**Parameters:**
- `job_id`: Job ID
- `fence`: Fence token returned by pull
- `error`: Error message (stored for debugging)
- `backoff`: Custom backoff delay (default: exponential)

**Returns:** True if returned to the queue, False if moved to the dead-letter queue

*Source: sdk/src/postkit/queue/client.py:426*

---

### pause_schedule

```python
pause_schedule(name: str) -> bool
```

Pause an active schedule.

**Parameters:**
- `name`: Schedule name

**Returns:** True if paused, False if already paused or not found

*Source: sdk/src/postkit/queue/client.py:753*

---

### pull

```python
pull(queue: str, *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> dict[str, Any] | None
```

Pull one job from a queue.

The job becomes running and receives a fence token that must accompany later operations on this attempt. If no job is available, returns None.

Database-only work and settlement may share the pull transaction. Before an external effect, confirm that the pull committed and use a stable idempotency key. After a rollback or unknown commit outcome, discard the result, reconnect, and poll again.

**Parameters:**
- `queue`: Queue name
- `worker_id`: Optional diagnostic worker identifier
- `visibility_timeout`: How long before tick_timeouts may reclaim the job

**Returns:** Job dict with its payload, attempt count, and fence_token, or None

*Source: sdk/src/postkit/queue/client.py:200*

---

### pull_any

```python
pull_any(queues: list[str], *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> dict[str, Any] | None
```

Pull one job from the first available queue in priority order.

The job becomes running and receives a fence token that must accompany later operations on this attempt.

Database-only work and settlement may share the pull transaction. Before an external effect, confirm that the pull committed and use a stable idempotency key. After a rollback or unknown commit outcome, discard the result, reconnect, and poll again.

**Parameters:**
- `queues`: Queue names in priority order (first checked first)
- `worker_id`: Optional diagnostic worker identifier
- `visibility_timeout`: How long before tick_timeouts may reclaim the job

**Returns:** Job dict including fence_token, or None if every queue is empty

**Example:**
```python
job = queue.pull_any(["critical", "default", "bulk"])
```

*Source: sdk/src/postkit/queue/client.py:288*

---

### pull_batch

```python
pull_batch(queue: str, limit: int = 10, *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> list[dict[str, Any]]
```

Pull multiple jobs from a queue.

Pulls up to limit jobs in one operation. Each returned job has its own fence token for later operations on that attempt.

Database-only work and settlement may share the pull transaction. Before external effects, confirm that the pull committed and use stable idempotency keys. After a rollback or unknown commit outcome, discard the results, reconnect, and poll again.

**Parameters:**
- `queue`: Queue name
- `limit`: Maximum jobs to pull
- `worker_id`: Optional diagnostic worker identifier
- `visibility_timeout`: How long before tick_timeouts may reclaim the jobs

**Returns:** Job dicts with payloads, attempt counts, and distinct fence_token values

*Source: sdk/src/postkit/queue/client.py:242*

---

### purge_dead_letters

```python
purge_dead_letters(*, queue: str | None = None, older_than: timedelta = datetime.timedelta(days=30)) -> int
```

Delete old un-retried dead letters.

Only purges un-retried entries. Retried dead letters are kept as historical records linking the failure to its retry job.

**Parameters:**
- `queue`: Queue filter (None = all queues)
- `older_than`: Only delete entries older than this (default 30 days)

**Returns:** Count of deleted dead letters

*Source: sdk/src/postkit/queue/client.py:902*

---

### purge_queue

```python
purge_queue(queue: str) -> int
```

Delete all pending jobs from a queue.

Running, completed, and dead jobs are not affected. Release running jobs individually, or wait for timeout recovery, before purging if they should also be removed.

**Parameters:**
- `queue`: Queue name

**Returns:** Count of deleted jobs

*Source: sdk/src/postkit/queue/client.py:554*

---

### push

```python
push(queue: str, payload: dict[str, Any], *, delay: timedelta | None = None, priority: int = 0, max_attempts: int | None = None, unique_key: str | None = None, tags: list[str] | None = None, metadata: dict[str, Any] | None = None) -> int | None
```

Push a job onto a queue.

**Parameters:**
- `queue`: Queue name
- `payload`: Job payload (must be JSON-serializable)
- `delay`: Delay before job becomes visible
- `priority`: Job priority (-1000 to 1000, higher = more important)
- `max_attempts`: Maximum retry attempts (default from config)
- `unique_key`: Deduplication key (None = no dedup)
- `tags`: Optional tags for filtering
- `metadata`: Optional metadata

**Returns:** Job ID, or None if deduplicated (unique_key already exists)

*Source: sdk/src/postkit/queue/client.py:100*

---

### push_batch

```python
push_batch(queue: str, payloads: list[dict[str, Any]], *, priority: int = 0, max_attempts: int | None = None, tags: list[str] | None = None) -> list[int]
```

Push multiple jobs onto a queue efficiently.

**Parameters:**
- `queue`: Queue name
- `payloads`: List of job payloads
- `priority`: Priority for all jobs
- `max_attempts`: Maximum retry attempts for all jobs
- `tags`: Tags for all jobs

**Returns:** List of job IDs

*Source: sdk/src/postkit/queue/client.py:154*

---

### release

```python
release(job_id: int, fence: int) -> bool
```

Return a running job to pending immediately, without backoff.

Release preserves the attempt count and affects only the supplied pull. During graceful shutdown, release each in-flight job instead of waiting for timeout recovery. Raises QueueFencingError when the supplied token no longer identifies the current, unexpired attempt.

**Parameters:**
- `job_id`: Job ID
- `fence`: Fence token returned by pull

**Returns:** True if released

*Source: sdk/src/postkit/queue/client.py:506*

---

### resume_schedule

```python
resume_schedule(name: str) -> bool
```

Resume a paused schedule. Recalculates next_run_at from now.

**Parameters:**
- `name`: Schedule name

**Returns:** True if resumed, False if already active or not found

*Source: sdk/src/postkit/queue/client.py:772*

---

### retry_dead_letter

```python
retry_dead_letter(dead_letter_id: int, *, queue: str | None = None) -> int
```

Retry a dead-lettered job by creating a new job from its payload.

The dead letter is marked as retried to prevent double-retry. The new job gets a fresh attempt counter and the caller's actor context (not the original actor).

**Parameters:**
- `dead_letter_id`: Dead letter ID
- `queue`: Queue override (None = use original queue)

**Returns:** New job ID

*Source: sdk/src/postkit/queue/client.py:839*

---

### retry_dead_letters

```python
retry_dead_letters(queue: str, *, limit: int = 100) -> list[dict[str, Any]]
```

Retry multiple dead letters for a queue in a single transaction.

Retries un-retried dead letters oldest-first. Uses FOR UPDATE SKIP LOCKED so concurrent callers do not double-retry.

**Parameters:**
- `queue`: Queue to retry dead letters from
- `limit`: Maximum dead letters to retry (max 1000)

**Returns:** List of dicts with dead_letter_id and job_id for each retry

*Source: sdk/src/postkit/queue/client.py:874*

---

### set_actor

```python
set_actor(actor_id: str | None = None, request_id: str | None = None, on_behalf_of: str | None = None, reason: str | None = None) -> None
```

Set actor context for audit logging. Only updates fields that are passed.

**Parameters:**
- `actor_id`: The actor making changes (e.g., 'user:alice', 'service:billing')
- `request_id`: Request/correlation ID for tracing
- `on_behalf_of`: Principal being represented (e.g., 'user:customer')
- `reason`: Reason for the action (e.g., 'support_ticket:123')

**Example:**
```python
client.clear_actor()
client.set_actor(request_id="req-123")  # Set request context first
client.set_actor(actor_id="user:alice")  # Add actor after auth
```

*Source: sdk/src/postkit/base.py:361*

---

### tick_schedules

```python
tick_schedules(*, limit: int = 100) -> list[dict[str, Any]]
```

Process due schedules and create jobs.

Finds active schedules where next_run_at <= now(), creates a job for each, and advances their next_run_at. Uses FOR UPDATE SKIP LOCKED for safe concurrent execution from multiple workers.

**Parameters:**
- `limit`: Maximum schedules to process per call

**Returns:** List of dicts with schedule_name, job_id, and next_run_at

*Source: sdk/src/postkit/queue/client.py:791*

---

### tick_timeouts

```python
tick_timeouts(*, limit: int = 100) -> list[dict[str, Any]]
```

Reclaim running jobs whose visibility timeout has expired.

Workers that crash or hang leave jobs stuck in 'running' status. This function returns them to 'pending' for re-delivery. Call periodically alongside tick_schedules().

**Parameters:**
- `limit`: Maximum jobs to reclaim per call

**Returns:** List of dicts with job_id, queue, and stuck_duration

*Source: sdk/src/postkit/queue/client.py:813*

---
