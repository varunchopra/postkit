# Queue API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`ack`](sdk.md#ack) | Acknowledge successful job completion. |
| [`ack_batch`](sdk.md#ack_batch) | Acknowledge multiple jobs as completed. |
| [`assert_rls_active`](sdk.md#assert_rls_active) | Raise unless row-level security applies to the connection's role. |
| [`cancel`](sdk.md#cancel) | Cancel a pending job by deleting it. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`create_schedule`](sdk.md#create_schedule) | Create a recurring schedule that produces jobs automatically. |
| [`delete_schedule`](sdk.md#delete_schedule) | Delete a schedule by name. |
| [`extend_visibility`](sdk.md#extend_visibility) | Extend the visibility timeout of a running job. |
| [`fail`](sdk.md#fail) | Move job to dead letter queue (permanent failure). |
| [`get_queue_stats`](sdk.md#get_queue_stats) | Get per-queue statistics with operational metrics. |
| [`get_schedule`](sdk.md#get_schedule) | Get a schedule by name. |
| [`get_stats`](sdk.md#get_stats) | Get namespace-wide queue statistics. |
| [`list_schedules`](sdk.md#list_schedules) | List schedules with optional filters and cursor pagination. |
| [`nack`](sdk.md#nack) | Return job to queue for retry (temporary failure). |
| [`pause_schedule`](sdk.md#pause_schedule) | Pause an active schedule. |
| [`pull`](sdk.md#pull) | Pull one job from a queue. |
| [`pull_any`](sdk.md#pull_any) | Pull one job from multiple queues (priority order). |
| [`pull_batch`](sdk.md#pull_batch) | Pull multiple jobs from a queue. |
| [`purge_dead_letters`](sdk.md#purge_dead_letters) | Delete old un-retried dead letters. |
| [`purge_queue`](sdk.md#purge_queue) | Delete all pending jobs from a queue. |
| [`push`](sdk.md#push) | Push a job onto a queue. |
| [`push_batch`](sdk.md#push_batch) | Push multiple jobs onto a queue efficiently. |
| [`release_jobs`](sdk.md#release_jobs) | Release all jobs held by a worker, returning them to pending. |
| [`resume_schedule`](sdk.md#resume_schedule) | Resume a paused schedule. Recalculates next_run_at from now. |
| [`retry_dead_letter`](sdk.md#retry_dead_letter) | Retry a dead-lettered job by creating a new job from its payload. |
| [`retry_dead_letters`](sdk.md#retry_dead_letters) | Retry multiple dead letters for a queue in a single transaction. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`tick_schedules`](sdk.md#tick_schedules) | Process due schedules and create jobs. |
| [`tick_timeouts`](sdk.md#tick_timeouts) | Reclaim running jobs whose visibility timeout has expired. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`queue.ack`](sql.md#queueack) | Acknowledge successful job completion. |
| [`queue.ack_batch`](sql.md#queueack_batch) | Acknowledge multiple jobs as completed. |
| [`queue.cancel`](sql.md#queuecancel) | Cancel a pending job by deleting it. |
| [`queue.fail`](sql.md#queuefail) | Move job to dead letter queue (permanent failure). |
| [`queue.nack`](sql.md#queuenack) | Return job to queue for retry (temporary failure). |
| [`queue.purge_queue`](sql.md#queuepurge_queue) | Delete all pending jobs from a queue. |
| [`queue.release_jobs`](sql.md#queuerelease_jobs) | Release all jobs held by a worker, returning them to pending. |
| [`queue.assert_rls_active`](sql.md#queueassert_rls_active) | Raise unless row-level security applies to the current role. |
| [`queue.clear_actor`](sql.md#queueclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`queue.clear_tenant`](sql.md#queueclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`queue.set_actor`](sql.md#queueset_actor) | Set actor context for audit trail. |
| [`queue.set_tenant`](sql.md#queueset_tenant) | Set the tenant context for RLS policies. |
| [`queue.purge_dead_letters`](sql.md#queuepurge_dead_letters) | Delete old un-retried dead letters. |
| [`queue.retry_dead_letter`](sql.md#queueretry_dead_letter) | Retry a dead-lettered job by creating a new job from its payload. |
| [`queue.retry_dead_letters`](sql.md#queueretry_dead_letters) | Retry multiple dead letters for a queue in a single transaction. |
| [`queue.extend_visibility`](sql.md#queueextend_visibility) | Extend the visibility timeout of a running job. |
| [`queue.pull`](sql.md#queuepull) | Pull one job from a queue. |
| [`queue.pull_any`](sql.md#queuepull_any) | Pull one job from multiple queues (priority order). |
| [`queue.pull_batch`](sql.md#queuepull_batch) | Pull multiple jobs from a queue. |
| [`queue.push`](sql.md#queuepush) | Push a job onto a queue. |
| [`queue.push_batch`](sql.md#queuepush_batch) | Push multiple jobs onto a queue efficiently. |
| [`queue.create_schedule`](sql.md#queuecreate_schedule) | Create a recurring schedule that produces jobs automatically. |
| [`queue.delete_schedule`](sql.md#queuedelete_schedule) | Delete a schedule by name. |
| [`queue.get_schedule`](sql.md#queueget_schedule) | Get a schedule by name. |
| [`queue.list_schedules`](sql.md#queuelist_schedules) | List schedules with optional filters and cursor pagination. |
| [`queue.pause_schedule`](sql.md#queuepause_schedule) | Pause an active schedule. |
| [`queue.resume_schedule`](sql.md#queueresume_schedule) | Resume a paused schedule. Recalculates next_run_at from now. |
| [`queue.tick_schedules`](sql.md#queuetick_schedules) | Process due schedules and create jobs. |
| [`queue.tick_timeouts`](sql.md#queuetick_timeouts) | Reclaim running jobs whose visibility timeout has expired. |
| [`queue.get_queue_stats`](sql.md#queueget_queue_stats) | Get per-queue statistics with operational metrics. |
| [`queue.get_stats`](sql.md#queueget_stats) | Get namespace-wide queue statistics. |
