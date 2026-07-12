# Memory API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`assert_rls_active`](sdk.md#assert_rls_active) | Raise unless row-level security applies to the connection's role. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`consolidate`](sdk.md#consolidate) | Apply a distillation batch in one transaction. |
| [`consolidation_due`](sdk.md#consolidation_due) | Surface unconsolidated episodes for a distillation worker. |
| [`get_node`](sdk.md#get_node) | Fetch a single node including its evidence episode ids. |
| [`get_stats`](sdk.md#get_stats) | Namespace-wide memory counts. |
| [`list_episodes`](sdk.md#list_episodes) | List episodes newest first, with cursor pagination. |
| [`list_nodes`](sdk.md#list_nodes) | List nodes newest first, with cursor pagination. |
| [`neighbors`](sdk.md#neighbors) | Return the nodes one edge away from a node, in either direction. |
| [`recall`](sdk.md#recall) | Find memories relevant to a query by meaning, keywords, and connection. |
| [`record`](sdk.md#record) | Append one episode to the interaction log. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`set_dimension`](sdk.md#set_dimension) | Fix the embedding dimension and build the vector search indexes. |
| [`supersede`](sdk.md#supersede) | Replace a node with a newer one, keeping the old for history. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`memory.consolidate`](sql.md#memoryconsolidate) | Apply a distillation batch: insert facts and entities, link edges, mark episodes. |
| [`memory.consolidation_due`](sql.md#memoryconsolidation_due) | Surface unconsolidated episodes for a distillation worker to process. |
| [`memory.assert_rls_active`](sql.md#memoryassert_rls_active) | Raise unless row-level security applies to the current role. |
| [`memory.clear_actor`](sql.md#memoryclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`memory.clear_tenant`](sql.md#memoryclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`memory.set_actor`](sql.md#memoryset_actor) | Set actor context for episode and node attribution. |
| [`memory.set_tenant`](sql.md#memoryset_tenant) | Set the tenant context for RLS policies. |
| [`memory.set_dimension`](sql.md#memoryset_dimension) | Fix the embedding dimension and build the vector search indexes. |
| [`memory.get_node`](sql.md#memoryget_node) | Fetch a single node including its evidence episode ids. |
| [`memory.get_stats`](sql.md#memoryget_stats) | Namespace-wide memory counts. |
| [`memory.list_episodes`](sql.md#memorylist_episodes) | List episodes newest first, with keyset pagination. |
| [`memory.list_nodes`](sql.md#memorylist_nodes) | List nodes newest first, with keyset pagination. |
| [`memory.channel_name`](sql.md#memorychannel_name) | NOTIFY channel for a namespace; LISTEN on this to receive record wake-ups. |
| [`memory.neighbors`](sql.md#memoryneighbors) | Return the nodes one edge away from a node, in either direction. |
| [`memory.recall`](sql.md#memoryrecall) | Find memories relevant to a query by meaning, keywords, and connection. |
| [`memory.record`](sql.md#memoryrecord) | Append one episode to the interaction log. |
| [`memory.supersede`](sql.md#memorysupersede) | Replace a node with a newer one, keeping the old for history (M4). |
