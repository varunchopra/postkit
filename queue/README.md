# queue

Postgres-native job queues with retries, scheduling, and dead letter handling. Jobs commit or rollback with your transaction.

**Good fit:** Background tasks, email sending, webhook delivery, periodic maintenance, or any work that needs retries and should survive app restarts.

**Not a fit:** Sub-second latency requirements, millions of jobs per second, or fan-out pub/sub. Use Redis or a message broker for those.

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Set tenant context
SELECT queue.set_tenant('acme');

-- Push a job
SELECT queue.push('acme', 'email', '{"to": "alice@example.com", "subject": "Welcome"}');
-- -> 1 (job ID)

-- Pull next job (locks it for processing)
SELECT * FROM queue.pull('acme', 'email', p_worker_id := 'worker-1');
-- -> id: 1, queue: 'email', payload: {...}, attempts: 1, ...

-- Success: acknowledge completion
SELECT queue.ack('acme', 1);
-- -> true

-- Failure: return to queue for retry
SELECT queue.nack('acme', 1, p_error := 'SMTP timeout');
-- -> true (back to pending with exponential backoff)

-- Permanent failure: move to dead letter queue
SELECT queue.fail('acme', 1, p_error := 'invalid recipient');
-- -> true
```

## Job States

Jobs move through four states:

- **pending** - waiting to be pulled (includes scheduled/delayed jobs)
- **running** - locked by a worker, with a visibility timeout
- **completed** - acknowledged by worker (deleted or archived per config)
- **dead** - moved to dead letter queue after max attempts or explicit fail

If a worker crashes, the visibility timeout expires and the job returns to pending automatically.

## Schedules

Create recurring jobs with cron expressions or fixed intervals:

```sql
-- Every 5 minutes
SELECT queue.create_schedule(
    'acme', 'cleanup', 'maintenance',
    '{"action": "expire_sessions"}',
    p_cron_expression := '*/5 * * * *'
);

-- Every 2 hours
SELECT queue.create_schedule(
    'acme', 'sync', 'data',
    '{"source": "upstream"}',
    p_every_interval := '2 hours'
);

-- Process due schedules (call from an external cron or timer)
SELECT * FROM queue.tick_schedules('acme');
-- -> schedule_name, job_id, next_run_at for each fired schedule
```

Pause and resume without losing schedule definitions:

```sql
SELECT queue.pause_schedule('acme', 'cleanup');
SELECT queue.resume_schedule('acme', 'cleanup');
```

## Deduplication

Prevent duplicate jobs with unique keys:

```sql
SELECT queue.push('acme', 'sync', '{"user": 42}', p_unique_key := 'sync:user:42');
-- -> 5

SELECT queue.push('acme', 'sync', '{"user": 42}', p_unique_key := 'sync:user:42');
-- -> NULL (deduplicated)
```

## Common Operations

```sql
-- Pull from multiple queues in priority order
SELECT * FROM queue.pull_any('acme', ARRAY['critical', 'default', 'bulk']);

-- Pull a batch of jobs
SELECT * FROM queue.pull_batch('acme', 'email', p_limit := 10);

-- Acknowledge a batch
SELECT queue.ack_batch('acme', ARRAY[1, 2, 3]);

-- Extend processing time for a long-running job
SELECT queue.extend_visibility('acme', 1, '10 minutes');

-- Namespace-wide stats
SELECT * FROM queue.get_stats('acme');
-- -> total_jobs, pending, running, completed, dead, total_queues
```

See [docs/queue/](../docs/queue/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
queue.clear_actor()  # Clear audit actor context
```

Tenant context (`queue.tenant_id`) is set per-request via `QueueClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
