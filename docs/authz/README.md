# Authz API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`add_hierarchy_rule`](sdk.md#add_hierarchy_rule) | Add a single hierarchy rule (for complex/branching hierarchies). |
| [`bulk_grant`](sdk.md#bulk_grant) | Grant permission to many subjects at once. |
| [`bulk_grant_resources`](sdk.md#bulk_grant_resources) | Grant permission to a subject on many resources at once. |
| [`check`](sdk.md#check) | Check if a subject has a permission on a resource. |
| [`check_all`](sdk.md#check_all) | Check if a subject has all of the specified permissions. |
| [`check_any`](sdk.md#check_any) | Check if a subject has any of the specified permissions. |
| [`cleanup_expired`](sdk.md#cleanup_expired) | Remove expired grants. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`clear_expiration`](sdk.md#clear_expiration) | Remove expiration from a grant (make it permanent). |
| [`clear_hierarchy`](sdk.md#clear_hierarchy) | Clear all hierarchy rules for a resource type in the client's namespace. |
| [`clear_viewer`](sdk.md#clear_viewer) | Clear the viewer context. |
| [`count_subjects`](sdk.md#count_subjects) | Count subjects who have a permission on a resource. |
| [`explain`](sdk.md#explain) | Explain why a subject has a permission. |
| [`extend_expiration`](sdk.md#extend_expiration) | Extend an existing expiration by a given interval. |
| [`filter_authorized`](sdk.md#filter_authorized) | Batch-check which resources a subject can access. |
| [`get_audit_events`](sdk.md#get_audit_events) | Query audit events with optional filters. |
| [`get_stats`](sdk.md#get_stats) | Get namespace statistics for monitoring. |
| [`grant`](sdk.md#grant) | Grant a permission on a resource to a subject. |
| [`list_expiring`](sdk.md#list_expiring) | List grants expiring within the given timeframe. |
| [`list_external_resources`](sdk.md#list_external_resources) | List resources shared with a subject from other namespaces. |
| [`list_grants`](sdk.md#list_grants) | List all grants for a subject. |
| [`list_resources`](sdk.md#list_resources) | List resources a subject has a permission on. |
| [`list_subjects`](sdk.md#list_subjects) | List subjects who have a permission on a resource. |
| [`remove_hierarchy_rule`](sdk.md#remove_hierarchy_rule) | Remove a hierarchy rule from the client's namespace. |
| [`revoke`](sdk.md#revoke) | Revoke a permission on a resource from a subject. |
| [`revoke_all_grants`](sdk.md#revoke_all_grants) | Revoke all grants for a subject (e.g., when deleting an API key). |
| [`revoke_resource_grants`](sdk.md#revoke_resource_grants) | Revoke all grants ON a resource. Call before deleting the resource. |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`set_expiration`](sdk.md#set_expiration) | Set or update expiration on an existing grant. |
| [`set_hierarchy`](sdk.md#set_hierarchy) | Define permission hierarchy for a resource type. |
| [`set_viewer`](sdk.md#set_viewer) | Set the viewer context for cross-namespace queries. |
| [`transfer_grant`](sdk.md#transfer_grant) | Transfer a grant from one subject to another. |
| [`verify`](sdk.md#verify) | Check for data integrity issues (e.g., group membership cycles). |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`authz.clear_actor`](sql.md#authzclear_actor) | Clear actor context (subsequent audit events will have NULL actor) |
| [`authz.create_audit_partition`](sql.md#authzcreate_audit_partition) | Create a monthly partition for audit events |
| [`authz.drop_audit_partitions`](sql.md#authzdrop_audit_partitions) | Delete old audit partitions (default: keep 7 years for compliance) |
| [`authz.ensure_audit_partitions`](sql.md#authzensure_audit_partitions) | Create partitions for upcoming months (run monthly via cron) |
| [`authz.set_actor`](sql.md#authzset_actor) | Tag audit events with who made the change (call before write/delete) |
| [`authz.explain`](sql.md#authzexplain) | Debug why a subject has (or doesn't have) a permission |
| [`authz.explain_text`](sql.md#authzexplain_text) | Human-readable explanation of why a subject has access |
| [`authz.delete`](sql.md#authzdelete) | Simpler delete_tuple when you don't need subject_relation |
| [`authz.delete_tuple`](sql.md#authzdelete_tuple) | Revoke a permission (remove a grant) |
| [`authz.cleanup_expired`](sql.md#authzcleanup_expired) | Delete expired grants to reclaim storage (optional, run via cron) |
| [`authz.clear_expiration`](sql.md#authzclear_expiration) | Make a grant permanent (remove expiration) |
| [`authz.extend_expiration`](sql.md#authzextend_expiration) | Extend an existing grant's expiration by an interval |
| [`authz.list_expiring`](sql.md#authzlist_expiring) | Find grants that will expire soon (for renewal reminders) |
| [`authz.set_expiration`](sql.md#authzset_expiration) | Add or update expiration on an existing grant |
| [`authz.add_hierarchy`](sql.md#authzadd_hierarchy) | Define that one permission implies another (e.g., admin implies write) |
| [`authz.clear_hierarchy`](sql.md#authzclear_hierarchy) | Remove all hierarchy rules for a resource type (start fresh) |
| [`authz.remove_hierarchy`](sql.md#authzremove_hierarchy) | Remove a permission implication rule |
| [`authz.count_subjects`](sql.md#authzcount_subjects) | Count subjects who can access a resource (without fetching all) |
| [`authz.filter_authorized`](sql.md#authzfilter_authorized) | Filter a list to only resources the subject can access (batch check) |
| [`authz.list_resources`](sql.md#authzlist_resources) | List all resources a subject can access ("What can Alice read?") |
| [`authz.list_subjects`](sql.md#authzlist_subjects) | List all subjects who can access a resource ("Who can read this doc?") |
| [`authz.get_stats`](sql.md#authzget_stats) | Get namespace statistics for monitoring dashboards |
| [`authz.grant_to_resources_bulk`](sql.md#authzgrant_to_resources_bulk) | Grant same user/team access to many resources at once |
| [`authz.verify_integrity`](sql.md#authzverify_integrity) | Check for data corruption (circular memberships, broken hierarchies, partition issues) |
| [`authz.clear_tenant`](sql.md#authzclear_tenant) | Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants. |
| [`authz.set_tenant`](sql.md#authzset_tenant) | Set tenant context for RLS (session-level, persists across transactions). For connection pools, call clear_tenant() before returning connections. |
| [`authz.check`](sql.md#authzcheck) | Check if a subject has a permission on a resource |
| [`authz.check_all`](sql.md#authzcheck_all) | Check if a subject has all of the specified permissions |
| [`authz.check_any`](sql.md#authzcheck_any) | Check if a subject has any of the specified permissions |
| [`authz.list_subject_grants`](sql.md#authzlist_subject_grants) | List all grants for a subject ("What can this API key access?") |
| [`authz.revoke_resource_grants`](sql.md#authzrevoke_resource_grants) | Revoke all grants on a resource (cleanup when deleting a resource) |
| [`authz.revoke_subject_grants`](sql.md#authzrevoke_subject_grants) | Revoke all grants for a subject (cleanup on deletion) |
| [`authz.write`](sql.md#authzwrite) | Simpler write_tuple when you don't need subject_relation |
| [`authz.write_tuple`](sql.md#authzwrite_tuple) | Grant a permission to a user or team on a resource |
| [`authz.write_tuples_bulk`](sql.md#authzwrite_tuples_bulk) | Grant same permission to many users at once (one SQL round-trip) |
