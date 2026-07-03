# Presence API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`deregister`](sdk.md#deregister) | Remove an entity deliberately, emitting a departed transition. |
| [`get_stats`](sdk.md#get_stats) | Get namespace-wide presence statistics. |
| [`get_transitions`](sdk.md#get_transitions) | Read the transition history, newest first. |
| [`heartbeat`](sdk.md#heartbeat) | Report an entity alive. |
| [`heartbeat_many`](sdk.md#heartbeat_many) | Report a batch of entities alive in one round trip. |
| [`list_entities`](sdk.md#list_entities) | List entities in the namespace. |
| [`register`](sdk.md#register) | Register an entity for liveness tracking, or update its attributes. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`status`](sdk.md#status) | Inspect one entity, with the wall-clock truth alongside the cache. |
| [`sweep`](sdk.md#sweep) | Mark overdue entities dead and deliver deferred death alerts. |
| [`trim`](sdk.md#trim) | Delete old transitions. Retention has no default; pass it explicitly. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`presence.clear_actor`](sql.md#presenceclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`presence.clear_tenant`](sql.md#presenceclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`presence.set_actor`](sql.md#presenceset_actor) | Set actor context for the transition history. |
| [`presence.set_tenant`](sql.md#presenceset_tenant) | Set the tenant context for RLS policies. |
| [`presence.heartbeat`](sql.md#presenceheartbeat) | Report an entity alive. |
| [`presence.heartbeat_many`](sql.md#presenceheartbeat_many) | Report a batch of entities alive in one round trip. |
| [`presence.get_stats`](sql.md#presenceget_stats) | Get namespace-wide presence statistics. |
| [`presence.get_transitions`](sql.md#presenceget_transitions) | Read the transition history, newest first. |
| [`presence.list`](sql.md#presencelist) | List entities in a namespace. |
| [`presence.status`](sql.md#presencestatus) | Inspect one entity, with the wall-clock truth alongside the cache. |
| [`presence.trim`](sql.md#presencetrim) | Delete old transitions. |
| [`presence.deregister`](sql.md#presencederegister) | Remove an entity deliberately, emitting a departed transition. |
| [`presence.register`](sql.md#presenceregister) | Register an entity for liveness tracking, or update its attributes. |
| [`presence.sweep`](sql.md#presencesweep) | Mark overdue entities dead and deliver deferred death alerts. |
