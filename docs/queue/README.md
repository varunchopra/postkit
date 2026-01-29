# Queue API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`ack`](sdk.md#ack) | Acknowledge successful job completion. |
| [`ack_batch`](sdk.md#ack_batch) | Acknowledge multiple jobs as completed. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`create_schedule`](sdk.md#create_schedule) | Create a recurring schedule that produces jobs automatically. |
| [`delete_schedule`](sdk.md#delete_schedule) | Delete a schedule by name. |
| [`extend_visibility`](sdk.md#extend_visibility) | Extend the visibility timeout of a running job. |
| [`fail`](sdk.md#fail) | Move job to dead letter queue (permanent failure). |
| [`get_schedule`](sdk.md#get_schedule) | Get a schedule by name. |
| [`get_stats`](sdk.md#get_stats) | Get namespace-wide queue statistics. |
| [`list_schedules`](sdk.md#list_schedules) | List schedules with optional filters and cursor pagination. |
| [`nack`](sdk.md#nack) | Return job to queue for retry (temporary failure). |
| [`pause_schedule`](sdk.md#pause_schedule) | Pause an active schedule. |
| [`pull`](sdk.md#pull) | Pull one job from a queue. |
| [`pull_any`](sdk.md#pull_any) | Pull one job from multiple queues (priority order). |
| [`pull_batch`](sdk.md#pull_batch) | Pull multiple jobs from a queue. |
| [`push`](sdk.md#push) | Push a job onto a queue. |
| [`push_batch`](sdk.md#push_batch) | Push multiple jobs onto a queue efficiently. |
| [`resume_schedule`](sdk.md#resume_schedule) | Resume a paused schedule. Recalculates next_run_at from now. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`tick_schedules`](sdk.md#tick_schedules) | Process due schedules and create jobs. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`queue.ack`](sql.md#queueack) | Acknowledge successful job completion. |
| [`queue.ack_batch`](sql.md#queueack_batch) | Acknowledge multiple jobs as completed. |
| [`queue.fail`](sql.md#queuefail) | Move job to dead letter queue (permanent failure). |
| [`queue.nack`](sql.md#queuenack) | Return job to queue for retry (temporary failure). |
| [`queue.clear_actor`](sql.md#queueclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`queue.clear_tenant`](sql.md#queueclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`queue.set_actor`](sql.md#queueset_actor) | Set actor context for audit trail. |
| [`queue.set_tenant`](sql.md#queueset_tenant) | Set the tenant context for RLS policies. |
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
| [`queue.get_stats`](sql.md#queueget_stats) | Get namespace-wide queue statistics. |
