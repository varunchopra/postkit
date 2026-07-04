# Outbox API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`ack`](sdk.md#ack) | Advance a consumer's cursor after processing. |
| [`assert_rls_active`](sdk.md#assert_rls_active) | Raise unless row-level security applies to the connection's role. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`emit`](sdk.md#emit) | Append an event inside the caller's open transaction. |
| [`get_stats`](sdk.md#get_stats) | Get namespace-wide outbox statistics. |
| [`horizon_blockers`](sdk.md#horizon_blockers) | Backends whose open write transactions pin the visibility horizon. |
| [`lag`](sdk.md#lag) | Per-consumer backlog, plus the current visibility horizon. |
| [`list_consumers`](sdk.md#list_consumers) | List consumer cursors in the namespace. |
| [`load`](sdk.md#load) |  |
| [`load`](sdk.md#load) |  |
| [`poll`](sdk.md#poll) | Read the next events for a consumer. Does not advance the cursor. |
| [`read_from`](sdk.md#read_from) | Read events after a position, for callers keeping their own cursor. |
| [`replay`](sdk.md#replay) | Move an existing consumer's cursor to a chosen position. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`subscribe`](sdk.md#subscribe) | Register a consumer and set its starting position. |
| [`trim`](sdk.md#trim) | Delete old events. Retention has no default; pass it explicitly. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`outbox.assert_rls_active`](sql.md#outboxassert_rls_active) | Raise unless row-level security applies to the current role. |
| [`outbox.clear_actor`](sql.md#outboxclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`outbox.clear_tenant`](sql.md#outboxclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`outbox.set_actor`](sql.md#outboxset_actor) | Set actor context, captured on emitted events. |
| [`outbox.set_tenant`](sql.md#outboxset_tenant) | Set the tenant context for RLS policies. |
| [`outbox.emit`](sql.md#outboxemit) | Append an event inside the caller's transaction. |
| [`outbox.get_stats`](sql.md#outboxget_stats) | Get namespace-wide outbox statistics. |
| [`outbox.horizon_blockers`](sql.md#outboxhorizon_blockers) | Backends whose open write transactions pin the visibility horizon. |
| [`outbox.lag`](sql.md#outboxlag) | Per-consumer backlog for a topic (or all topics). |
| [`outbox.list_consumers`](sql.md#outboxlist_consumers) | List consumer cursors in a namespace. |
| [`outbox.trim`](sql.md#outboxtrim) | Delete old events, keeping deletions a contiguous (xid, id) prefix. |
| [`outbox.ack`](sql.md#outboxack) | Advance a consumer's cursor after processing. |
| [`outbox.poll`](sql.md#outboxpoll) | Read the next events for a consumer. Does not advance the cursor. |
| [`outbox.read_from`](sql.md#outboxread_from) | Read events from a position, for callers that keep their own cursor. |
| [`outbox.replay`](sql.md#outboxreplay) | Move an existing consumer's cursor to a chosen position. |
| [`outbox.subscribe`](sql.md#outboxsubscribe) | Register a consumer on a topic and set its starting position. |
