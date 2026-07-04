# Lease API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`acquire`](sdk.md#acquire) | Acquire or take over a named lease. |
| [`assert_rls_active`](sdk.md#assert_rls_active) | Raise unless row-level security applies to the connection's role. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`current`](sdk.md#current) | Inspect a lease without locking it. |
| [`get_events`](sdk.md#get_events) | Read the lease event log, newest first. |
| [`get_stats`](sdk.md#get_stats) | Get namespace-wide lease statistics. |
| [`list_leases`](sdk.md#list_leases) | List leases in the namespace, most recently acquired first. |
| [`prune_events`](sdk.md#prune_events) | Delete old lease events. |
| [`release`](sdk.md#release) | Release a lease you hold. |
| [`renew`](sdk.md#renew) | Extend a live lease you hold. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`verify`](sdk.md#verify) | Assert, inside your transaction, that you still hold a lease. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`lease.acquire`](sql.md#leaseacquire) | Acquire or take over a named lease. |
| [`lease.assert_rls_active`](sql.md#leaseassert_rls_active) | Raise unless row-level security applies to the current role. |
| [`lease.clear_actor`](sql.md#leaseclear_actor) | Clear actor context. Call before returning connections to pool. |
| [`lease.clear_tenant`](sql.md#leaseclear_tenant) | Clear the tenant context. Call before returning connections to pool. |
| [`lease.set_actor`](sql.md#leaseset_actor) | Set actor context for the event log. |
| [`lease.set_tenant`](sql.md#leaseset_tenant) | Set the tenant context for RLS policies. |
| [`lease.current`](sql.md#leasecurrent) | Inspect a lease without locking it. |
| [`lease.get_events`](sql.md#leaseget_events) | Read the lease event log, newest first. |
| [`lease.get_stats`](sql.md#leaseget_stats) | Get namespace-wide lease statistics. |
| [`lease.list`](sql.md#leaselist) | List leases in a namespace. |
| [`lease.prune_events`](sql.md#leaseprune_events) | Delete old lease events. |
| [`lease.release`](sql.md#leaserelease) | Release a lease you hold. |
| [`lease.renew`](sql.md#leaserenew) | Extend a live lease you hold. |
| [`lease.verify`](sql.md#leaseverify) | Assert, inside your transaction, that you still hold a lease. |
