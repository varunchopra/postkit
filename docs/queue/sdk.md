<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Queue Python SDK

### ack

```python
ack(job_id: int) -> bool
```

Acknowledge successful job completion.

**Parameters:**
- `job_id`: Job ID

**Returns:** True if acknowledged, False if job not found or not running

*Source: sdk/src/postkit/queue/client.py:318*

---

### ack_batch

```python
ack_batch(job_ids: list[int]) -> int
```

Acknowledge multiple jobs as completed.

**Parameters:**
- `job_ids`: List of job IDs

**Returns:** Count of jobs acknowledged

*Source: sdk/src/postkit/queue/client.py:337*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:376*

---

### create_schedule

```python
create_schedule(name: str, queue: str, payload: dict[str, Any], *, cron_expression: str | None = None, cron_timezone: str = 'UTC', every_interval: timedelta | None = None, priority: int = 0, max_attempts: int = 3, tags: list[str] | None = None, is_active: bool = True) -> int
```

Create a recurring schedule that produces jobs automatically.

Schedules use either a cron expression or a fixed interval, not both. The schedule is identified by name (unique within the namespace).

**Parameters:**
- `name`: Schedule name (alphanumeric, underscores, hyphens)
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

*Source: sdk/src/postkit/queue/client.py:440*

---

### delete_schedule

```python
delete_schedule(name: str) -> bool
```

Delete a schedule by name.

**Parameters:**
- `name`: Schedule name

**Returns:** True if deleted, False if not found

*Source: sdk/src/postkit/queue/client.py:554*

---

### extend_visibility

```python
extend_visibility(job_id: int, extension: timedelta) -> bool
```

Extend the visibility timeout of a running job.

**Parameters:**
- `job_id`: Job ID
- `extension`: How much time to add

**Returns:** True if extended, False if job not found or not running

*Source: sdk/src/postkit/queue/client.py:285*

---

### fail

```python
fail(job_id: int, *, error: str | None = None) -> bool
```

Move job to dead letter queue (permanent failure).

**Parameters:**
- `job_id`: Job ID
- `error`: Error message

**Returns:** True if moved to DLQ, False if job not found

*Source: sdk/src/postkit/queue/client.py:390*

---

### get_schedule

```python
get_schedule(name: str) -> dict[str, Any] | None
```

Get a schedule by name.

**Parameters:**
- `name`: Schedule name

**Returns:** Schedule dict with all fields, or None if not found

*Source: sdk/src/postkit/queue/client.py:507*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Get namespace-wide queue statistics.

**Returns:** Dict with total_jobs, pending, running, completed, dead counts

*Source: sdk/src/postkit/queue/client.py:424*

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

*Source: sdk/src/postkit/queue/client.py:524*

---

### nack

```python
nack(job_id: int, *, error: str | None = None, backoff: timedelta | None = None) -> bool
```

Return job to queue for retry (temporary failure).

**Parameters:**
- `job_id`: Job ID
- `error`: Error message (stored for debugging)
- `backoff`: Custom backoff delay (default: exponential)

**Returns:** True if returned to queue, False if max attempts exceeded (moved to DLQ)

*Source: sdk/src/postkit/queue/client.py:356*

---

### pause_schedule

```python
pause_schedule(name: str) -> bool
```

Pause an active schedule.

**Parameters:**
- `name`: Schedule name

**Returns:** True if paused, False if already paused or not found

*Source: sdk/src/postkit/queue/client.py:573*

---

### pull

```python
pull(queue: str, *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> dict[str, Any] | None
```

Pull one job from a queue.

**Parameters:**
- `queue`: Queue name
- `worker_id`: Worker identifier (for debugging stuck jobs)
- `visibility_timeout`: How long before job returns to queue if not ack'd

**Returns:** Job dict with id, queue, payload, attempts, etc., or None if empty

*Source: sdk/src/postkit/queue/client.py:176*

---

### pull_any

```python
pull_any(queues: list[str], *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> dict[str, Any] | None
```

Pull one job from multiple queues (priority order).

**Parameters:**
- `queues`: Queue names in priority order (first checked first)
- `worker_id`: Worker identifier
- `visibility_timeout`: How long before job returns to queue

**Returns:** Job dict from first queue with available job, or None

**Example:**
```python
job = queue.pull_any(["critical", "default", "bulk"])
```

*Source: sdk/src/postkit/queue/client.py:248*

---

### pull_batch

```python
pull_batch(queue: str, limit: int = 10, *, worker_id: str | None = None, visibility_timeout: timedelta | None = None) -> list[dict[str, Any]]
```

Pull multiple jobs from a queue.

**Parameters:**
- `queue`: Queue name
- `limit`: Maximum jobs to pull
- `worker_id`: Worker identifier
- `visibility_timeout`: How long before jobs return to queue

**Returns:** List of job dicts

*Source: sdk/src/postkit/queue/client.py:210*

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

*Source: sdk/src/postkit/queue/client.py:76*

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

*Source: sdk/src/postkit/queue/client.py:130*

---

### resume_schedule

```python
resume_schedule(name: str) -> bool
```

Resume a paused schedule. Recalculates next_run_at from now.

**Parameters:**
- `name`: Schedule name

**Returns:** True if resumed, False if already active or not found

*Source: sdk/src/postkit/queue/client.py:592*

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

*Source: sdk/src/postkit/base.py:347*

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

*Source: sdk/src/postkit/queue/client.py:611*

---
