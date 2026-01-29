<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Queue SQL API

## Completion

### queue.ack

```sql
queue.ack(p_namespace: text, p_job_id: int8) -> bool
```

Acknowledge successful job completion.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_job_id`: Job ID

**Returns:** True if acknowledged, false if job not found or not running Job is either deleted or marked completed (based on archive_completed config).

*Source: queue/src/functions/030_ack.sql:1*

---

### queue.ack_batch

```sql
queue.ack_batch(p_namespace: text, p_job_ids: int8[]) -> int4
```

Acknowledge multiple jobs as completed.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_job_ids`: Array of job IDs

**Returns:** Count of jobs acknowledged

*Source: queue/src/functions/030_ack.sql:58*

---

### queue.fail

```sql
queue.fail(p_namespace: text, p_job_id: int8, p_error: text) -> bool
```

Move job to dead letter queue (permanent failure).

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_job_id`: Job ID
- `p_error`: Error message

**Returns:** True if moved to DLQ, false if job not found Use when a job cannot be retried (invalid data, business logic failure, etc).

*Source: queue/src/functions/030_ack.sql:198*

---

### queue.nack

```sql
queue.nack(p_namespace: text, p_job_id: int8, p_error: text, p_backoff: interval) -> bool
```

Return job to queue for retry (temporary failure).

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_job_id`: Job ID
- `p_error`: Error message (stored for debugging)
- `p_backoff`: Optional custom backoff delay (default: exponential)

**Returns:** True if returned to queue, false if max attempts exceeded (moved to DLQ) If max_attempts is exceeded, automatically moves to dead letter queue.

*Source: queue/src/functions/030_ack.sql:112*

---

## Context

### queue.clear_actor

```sql
queue.clear_actor() -> void
```

Clear actor context. Call before returning connections to pool.

*Source: queue/src/functions/080_rls.sql:53*

---

### queue.clear_tenant

```sql
queue.clear_tenant() -> void
```

Clear the tenant context. Call before returning connections to pool.

*Source: queue/src/functions/080_rls.sql:19*

---

### queue.set_actor

```sql
queue.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for audit trail.

**Parameters:**
- `p_actor_id`: ID of the user/system performing the action
- `p_request_id`: Optional request/trace ID for correlation
- `p_on_behalf_of`: Optional ID if acting on behalf of another user
- `p_reason`: Optional reason for the action (for audit) Actor context is captured when jobs are pushed and stored with the job.

*Source: queue/src/functions/080_rls.sql:30*

---

### queue.set_tenant

```sql
queue.set_tenant(p_tenant_id: text) -> void
```

Set the tenant context for RLS policies.

**Parameters:**
- `p_tenant_id`: Tenant/namespace identifier Must be called before any operations. Transaction-local scope.

*Source: queue/src/functions/080_rls.sql:1*

---

## Pull

### queue.extend_visibility

```sql
queue.extend_visibility(p_namespace: text, p_job_id: int8, p_extension: interval) -> bool
```

Extend the visibility timeout of a running job.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_job_id`: Job ID
- `p_extension`: How much time to add

**Returns:** True if extended, false if job not found or not running Use when processing takes longer than expected.

*Source: queue/src/functions/020_pull.sql:193*

---

### queue.pull

```sql
queue.pull(p_namespace: text, p_queue: text, p_worker_id: text, p_visibility_timeout: interval) -> setof queue.jobs
```

Pull one job from a queue.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queue`: Queue name
- `p_worker_id`: Worker identifier (for debugging stuck jobs)
- `p_visibility_timeout`: How long before job returns to queue if not ack'd

**Returns:** Job record, or NULL if queue is empty Uses SELECT FOR UPDATE SKIP LOCKED for efficient concurrent access. Job status changes to 'running' and becomes invisible until ack/nack/timeout.

*Source: queue/src/functions/020_pull.sql:1*

---

### queue.pull_any

```sql
queue.pull_any(p_namespace: text, p_queues: text[], p_worker_id: text, p_visibility_timeout: interval) -> setof queue.jobs
```

Pull one job from multiple queues (priority order).

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queues`: Queue names in priority order (first queue checked first)
- `p_worker_id`: Worker identifier
- `p_visibility_timeout`: How long before job returns to queue

**Returns:** Job record from first queue with available job, or NULL Useful for workers that handle multiple queues with different priorities. Example: pull_any(ns, ARRAY['critical', 'default', 'bulk'])

*Source: queue/src/functions/020_pull.sql:122*

---

### queue.pull_batch

```sql
queue.pull_batch(p_namespace: text, p_queue: text, p_limit: int4, p_worker_id: text, p_visibility_timeout: interval) -> setof queue.jobs
```

Pull multiple jobs from a queue.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queue`: Queue name
- `p_limit`: Maximum jobs to pull
- `p_worker_id`: Worker identifier (for debugging stuck jobs)
- `p_visibility_timeout`: How long before jobs return to queue if not ack'd

**Returns:** Set of job records More efficient than multiple pull() calls for batch processing.

*Source: queue/src/functions/020_pull.sql:60*

---

## Push

### queue.push

```sql
queue.push(p_namespace: text, p_queue: text, p_payload: jsonb, p_delay: interval, p_priority: int4, p_max_attempts: int4, p_unique_key: text, p_tags: text[], p_metadata: jsonb) -> int8
```

Push a job onto a queue.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queue`: Queue name
- `p_payload`: Job payload (JSONB)
- `p_delay`: Optional delay before job becomes visible
- `p_priority`: Priority (-1000 to 1000, higher = more important)
- `p_max_attempts`: Maximum retry attempts
- `p_unique_key`: Deduplication key (NULL = no dedup)
- `p_tags`: Optional tags for filtering
- `p_metadata`: Optional metadata

**Returns:** Job ID, or NULL if deduplicated Jobs are immediately visible unless p_delay is specified. With unique_key, returns NULL if a pending/running job with same key exists.

*Source: queue/src/functions/010_push.sql:1*

---

### queue.push_batch

```sql
queue.push_batch(p_namespace: text, p_queue: text, p_payloads: jsonb[], p_priority: int4, p_max_attempts: int4, p_tags: text[]) -> int8[]
```

Push multiple jobs onto a queue efficiently.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queue`: Queue name
- `p_payloads`: Array of job payloads
- `p_priority`: Priority for all jobs (default 0)
- `p_max_attempts`: Maximum retry attempts for all jobs
- `p_tags`: Tags for all jobs

**Returns:** Array of job IDs More efficient than multiple push() calls. Does not support unique_key.

*Source: queue/src/functions/010_push.sql:110*

---

## Schedules

### queue.create_schedule

```sql
queue.create_schedule(p_namespace: text, p_name: text, p_queue: text, p_payload: jsonb, p_cron_expression: text, p_cron_timezone: text, p_every_interval: interval, p_priority: int4, p_max_attempts: int4, p_tags: text[], p_is_active: bool) -> int8
```

Create a recurring schedule that produces jobs automatically.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Schedule name (unique per namespace)
- `p_queue`: Target queue for generated jobs
- `p_payload`: Job payload template
- `p_cron_expression`: 5-field cron expression (mutually exclusive with p_every_interval)
- `p_cron_timezone`: Timezone for cron evaluation (default 'UTC')
- `p_every_interval`: Fixed interval between runs (mutually exclusive with p_cron_expression)
- `p_priority`: Job priority (-1000 to 1000)
- `p_max_attempts`: Maximum retry attempts for generated jobs
- `p_tags`: Tags applied to generated jobs
- `p_is_active`: Whether schedule starts active

**Returns:** Schedule ID

*Source: queue/src/functions/050_schedules.sql:1*

---

### queue.delete_schedule

```sql
queue.delete_schedule(p_namespace: text, p_name: text) -> bool
```

Delete a schedule by name.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Schedule name

**Returns:** True if deleted, false if not found

*Source: queue/src/functions/050_schedules.sql:193*

---

### queue.get_schedule

```sql
queue.get_schedule(p_namespace: text, p_name: text) -> table(id: int8, name: text, queue: text, payload: jsonb, priority: int4, max_attempts: int4, tags: text[], cron_expression: text, cron_timezone: text, every_interval: interval, is_active: bool, last_run_at: timestamptz, last_job_id: int8, next_run_at: timestamptz, run_count: int8, created_at: timestamptz, updated_at: timestamptz)
```

Get a schedule by name.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Schedule name

**Returns:** Schedule row, or empty if not found

*Source: queue/src/functions/050_schedules.sql:100*

---

### queue.list_schedules

```sql
queue.list_schedules(p_namespace: text, p_queue: text, p_is_active: bool, p_limit: int4, p_cursor: text) -> table(name: text, queue: text, cron_expression: text, every_interval: interval, is_active: bool, next_run_at: timestamptz, last_run_at: timestamptz, run_count: int8, created_at: timestamptz)
```

List schedules with optional filters and cursor pagination.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_queue`: Filter by target queue (NULL = all)
- `p_is_active`: Filter by active status (NULL = all)
- `p_limit`: Maximum results (clamped to 1000)
- `p_cursor`: Last schedule name from previous page

**Returns:** Schedule rows ordered by name

*Source: queue/src/functions/050_schedules.sql:145*

---

### queue.pause_schedule

```sql
queue.pause_schedule(p_namespace: text, p_name: text) -> bool
```

Pause an active schedule.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Schedule name

**Returns:** True if paused, false if already paused or not found

*Source: queue/src/functions/050_schedules.sql:220*

---

### queue.resume_schedule

```sql
queue.resume_schedule(p_namespace: text, p_name: text) -> bool
```

Resume a paused schedule. Recalculates next_run_at from now.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Schedule name

**Returns:** True if resumed, false if already active or not found

*Source: queue/src/functions/050_schedules.sql:251*

---

### queue.tick_schedules

```sql
queue.tick_schedules(p_namespace: text, p_limit: int4) -> table(schedule_name: text, job_id: int8, next_run_at: timestamptz)
```

Process due schedules and create jobs.

**Parameters:**
- `p_namespace`: Tenant namespace (NULL = all namespaces, requires RLS bypass)
- `p_limit`: Maximum schedules to process per call

**Returns:** Rows of (schedule_name, job_id, next_run_at) for each processed schedule Finds active schedules where next_run_at <= now(), creates a job for each, and advances next_run_at. Uses FOR UPDATE SKIP LOCKED for safe concurrent execution from multiple workers.

*Source: queue/src/functions/055_tick.sql:1*

---

## Stats

### queue.get_stats

```sql
queue.get_stats(p_namespace: text) -> table(total_jobs: int8, pending: int8, running: int8, completed: int8, dead: int8, total_queues: int8)
```

Get namespace-wide queue statistics.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Row with total_jobs, pending, running, completed, dead, total_queues

*Source: queue/src/functions/040_stats.sql:1*

---
