# queue

Postgres-native job queues with retries, scheduling, and dead letter handling. Jobs commit or rollback with your transaction.

**Good fit:** Background tasks, email sending, webhook delivery, periodic maintenance, or any work that needs retries and should survive app restarts.

**Not a fit:** Sub-second latency requirements, millions of jobs per second, or fan-out where every consumer needs every event (that is [outbox](../outbox/) - queue jobs are consumed once, by whichever worker pulls them).

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Push a job transactionally with the application change that produced it.
BEGIN;
SELECT queue.set_tenant('acme');
SELECT queue.push('acme', 'email', '{"to": "alice@example.com", "subject": "Welcome"}');
-- -> 1 (job ID)
COMMIT;

-- Pull in a short transaction and keep both the job ID and fence token.
BEGIN;
SELECT queue.set_tenant('acme');
SELECT * FROM queue.pull('acme', 'email', p_worker_id := 'worker-1');
-- -> id: 1, fence_token: 41, payload: {...}, attempts: 1, ...
COMMIT;

-- After successful processing, acknowledge that particular pull.
BEGIN;
SELECT queue.set_tenant('acme');
SELECT queue.ack('acme', 1, 41);
-- -> true

-- On temporary failure, run this instead of ack to schedule a retry:
-- SELECT queue.nack('acme', 1, 41, p_error := 'SMTP timeout');
-- -> true: returned to pending with backoff
-- -> false: max_attempts was reached and the job was dead-lettered

-- On permanent failure, run this instead of ack to dead-letter the job:
-- SELECT queue.fail('acme', 1, 41, p_error := 'invalid recipient');
-- -> true: moved to the dead-letter queue
COMMIT;
```

Database-only handlers may pull, write their result, and acknowledge in one transaction so a rollback undoes all three. For email, HTTP calls, payments, or other external effects, commit the pull before processing and use a stable idempotency key. The fence protects queue state only; delivery remains at least once. If the pull commit outcome is unknown, discard that result, reconnect, and resume polling.

## Job States

Jobs move through four states:

- **pending** - waiting to be pulled (includes scheduled/delayed jobs)
- **running** - locked by a worker, with a visibility timeout
- **completed** - acknowledged by worker (deleted or archived per config)
- **dead** - moved to dead letter queue after max attempts or explicit fail

If a worker crashes, its job stays in running until the visibility timeout expires and the next `queue.tick_timeouts` call returns it to pending. Nothing reclaims jobs on its own: until that tick runs, the job is delayed, not lost. Schedule `tick_timeouts` from the same cron that runs `tick_schedules`.

Each successful pull returns a `fence_token`. If a job times out and is pulled again, it keeps the same job ID but gets a new token. Operations that change a running job require that pull's token, so an earlier pull result cannot change a later attempt. Worker IDs are diagnostic only.

If a transaction containing `pull` rolls back, the job is pending again and its attempt count is unchanged. Sequence values do not roll back, so discard the returned fence token and pull again; that token will never be issued to a later attempt.

Operations on a missing or non-running job, or with an expired or superseded token, raise SQLSTATE `40001` with HINT `postkit:queue:FENCE_STALE`. Discard the token; retrying with it will fail again.

Fence tokens are opaque and gaps are normal; never reset the sequence. Grant worker roles `USAGE`, but not `UPDATE`, on `queue.fence_token_seq`: `UPDATE` permits `setval()`, which can rewind the sequence and reuse an old token. Postkit does not issue deployment-specific grants.

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

-- Process due schedules (call from an external cron or timer, together
-- with tick_timeouts, which reclaims timed-out jobs)
SELECT * FROM queue.tick_schedules('acme');
-- -> schedule_name, job_id, next_run_at for each fired schedule
SELECT * FROM queue.tick_timeouts('acme');
-- -> job_id, queue, stuck_duration for each reclaimed job
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

-- Acknowledge a batch atomically with aligned fence tokens
SELECT queue.ack_batch('acme', ARRAY[1, 2, 3], ARRAY[41, 42, 43]);

-- Extend the deadline when processing will take longer than expected
SELECT queue.extend_visibility('acme', 1, 41, '10 minutes');

-- During shutdown, return an in-flight job immediately without backoff
SELECT queue.release('acme', 1, 41);

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
