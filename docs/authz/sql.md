<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Authz SQL API

## Audit

### authz.clear_actor

```sql
authz.clear_actor() -> void
```

Clear actor context (subsequent audit events will have NULL actor)

**Example:**
```sql
SELECT authz.clear_actor();
```

*Source: authz/src/functions/033_audit.sql:28*

---

### authz.create_audit_partition

```sql
authz.create_audit_partition(p_year: int4, p_month: int4) -> text
```

Create a monthly partition for audit events

**Returns:** Partition name if created, NULL if already exists

**Example:**
```sql
SELECT authz.create_audit_partition(2024, 1); -- January 2024
```

*Source: authz/src/functions/033_audit.sql:44*

---

### authz.drop_audit_partitions

```sql
authz.drop_audit_partitions(p_older_than_months: int4) -> setof text
```

Delete old audit partitions (default: keep 7 years for compliance)

**Parameters:**
- `p_older_than_months`: Delete partitions older than this (default 84 = 7 years)

**Returns:** Names of dropped partitions

**Example:**
```sql
-- Keep 7 years, delete older
SELECT * FROM authz.drop_audit_partitions(84);
```

*Source: authz/src/functions/033_audit.sql:123*

---

### authz.ensure_audit_partitions

```sql
authz.ensure_audit_partitions(p_months_ahead: int4) -> setof text
```

Create partitions for upcoming months (run monthly via cron)

**Parameters:**
- `p_months_ahead`: How many months ahead to create (default 3)

**Returns:** Names of newly created partitions

**Example:**
```sql
-- Add to monthly cron job
SELECT * FROM authz.ensure_audit_partitions(3);
```

*Source: authz/src/functions/033_audit.sql:94*

---

### authz.set_actor

```sql
authz.set_actor(p_actor_id: text, p_request_id: text, p_reason: text, p_on_behalf_of: text) -> void
```

Tag audit events with who made the change (call before write/delete)

**Parameters:**
- `p_actor_id`: The admin or user making the change (for audit trail)
- `p_request_id`: Optional request/ticket ID for traceability
- `p_reason`: Optional reason for the change
- `p_on_behalf_of`: Optional principal being represented (e.g., admin acting as customer)

**Example:**
```sql
-- Before making changes, set who's doing it
SELECT authz.set_actor('user:admin-bob', on_behalf_of := 'user:customer-alice', reason := 'support_ticket:12345');
SELECT authz.write('repo', 'api', 'admin', 'team', 'eng');
```

*Source: authz/src/functions/033_audit.sql:1*

---

## Debugging

### authz.explain

```sql
authz.explain(p_subject_type: text, p_subject_id: text, p_permission: text, p_resource_type: text, p_resource_id: text, p_namespace: text, p_max_depth: int4) -> setof authz.permission_path
```

Debug why a subject has (or doesn't have) a permission

**Parameters:**
- `p_subject_type`: The subject type (e.g., 'user', 'api_key', 'service')
- `p_subject_id`: The subject ID

**Returns:** Structured paths showing how access was granted (via direct grant, team membership, permission hierarchy, or folder inheritance)

**Example:**
```sql
SELECT * FROM authz.explain('user', 'alice', 'read', 'doc', 'spec');
SELECT * FROM authz.explain('api_key', 'key-123', 'read', 'repo', 'api');
```

*Source: authz/src/functions/024_explain.sql:1*

---

### authz.explain_text

```sql
authz.explain_text(p_subject_type: text, p_subject_id: text, p_permission: text, p_resource_type: text, p_resource_id: text, p_namespace: text) -> setof text
```

Human-readable explanation of why a subject has access

**Parameters:**
- `p_subject_type`: The subject type (e.g., 'user', 'api_key', 'service')
- `p_subject_id`: The subject ID

**Returns:** One line per path, e.g., "GROUP: user:alice is member of team:eng which has read"

**Example:**
```sql
SELECT * FROM authz.explain_text('user', 'alice', 'read', 'doc', 'spec');
SELECT * FROM authz.explain_text('api_key', 'key-123', 'read', 'repo', 'api');
```

*Source: authz/src/functions/024_explain.sql:202*

---

## Deletes

### authz.delete

```sql
authz.delete(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_namespace: text) -> bool
```

Simpler delete_tuple when you don't need subject_relation

**Example:**
```sql
SELECT authz.delete('doc', 'spec', 'read', 'user', 'alice', 'default');
```

*Source: authz/src/functions/021_delete.sql:45*

---

### authz.delete_tuple

```sql
authz.delete_tuple(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_subject_relation: text, p_namespace: text) -> bool
```

Revoke a permission (remove a grant)

**Returns:** True if a grant was found and removed, false if it didn't exist

**Example:**
```sql
-- Remove alice's read access to a doc
SELECT authz.delete_tuple('doc', 'spec', 'read', 'user', 'alice', NULL, 'default');
```

*Source: authz/src/functions/021_delete.sql:1*

---

## Expiration

### authz.cleanup_expired

```sql
authz.cleanup_expired(p_namespace: text) -> table(tuples_deleted: int8)
```

Delete expired grants to reclaim storage (optional, run via cron)

**Returns:** Count of grants deleted

**Example:**
```sql
SELECT * FROM authz.cleanup_expired('default');
```

*Source: authz/src/functions/031_expiration.sql:141*

---

### authz.clear_expiration

```sql
authz.clear_expiration(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_namespace: text) -> bool
```

Make a grant permanent (remove expiration)

**Example:**
```sql
SELECT authz.clear_expiration('repo', 'api', 'read', 'user', 'alice', 'default');
```

*Source: authz/src/functions/031_expiration.sql:38*

---

### authz.extend_expiration

```sql
authz.extend_expiration(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_extension: interval, p_namespace: text) -> timestamptz
```

Extend an existing grant's expiration by an interval

**Parameters:**
- `p_extension`: Time to add (e.g., '30 days')

**Returns:** New expiration timestamp

**Example:**
```sql
-- Give alice another 30 days
SELECT authz.extend_expiration('repo', 'api', 'read', 'user', 'alice',
interval '30 days', 'default');
```

*Source: authz/src/functions/031_expiration.sql:51*

---

### authz.list_expiring

```sql
authz.list_expiring(p_within: interval, p_namespace: text) -> table(resource_type: text, resource_id: text, relation: text, subject_type: text, subject_id: text, subject_relation: text, expires_at: timestamptz)
```

Find grants that will expire soon (for renewal reminders)

**Parameters:**
- `p_within`: Time window to check (default 7 days)

**Returns:** Grants expiring within the window, ordered by expiration

**Example:**
```sql
-- Email users whose access expires this week
SELECT * FROM authz.list_expiring(interval '7 days', 'default');
```

*Source: authz/src/functions/031_expiration.sql:100*

---

### authz.set_expiration

```sql
authz.set_expiration(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_expires_at: timestamptz, p_namespace: text) -> bool
```

Add or update expiration on an existing grant

**Parameters:**
- `p_expires_at`: When the permission should auto-revoke (NULL to make permanent)

**Returns:** True if grant was found and updated

**Example:**
```sql
-- Contractor access expires in 90 days
SELECT authz.set_expiration('repo', 'api', 'read', 'user', 'contractor-bob',
now() + interval '90 days', 'default');
```

*Source: authz/src/functions/031_expiration.sql:1*

---

## Hierarchy

### authz.add_hierarchy

```sql
authz.add_hierarchy(p_resource_type: text, p_permission: text, p_implies: text, p_namespace: text) -> int8
```

Define that one permission implies another (e.g., admin implies write)

**Parameters:**
- `p_permission`: The higher permission (e.g., 'admin')
- `p_implies`: The implied permission (e.g., 'write')

**Returns:** Rule ID

**Example:**
```sql
-- admin can do everything write can do, write can do everything read can do
SELECT authz.add_hierarchy('repo', 'admin', 'write', 'default');
SELECT authz.add_hierarchy('repo', 'write', 'read', 'default');
```

*Source: authz/src/functions/030_hierarchy.sql:1*

---

### authz.clear_hierarchy

```sql
authz.clear_hierarchy(p_resource_type: text, p_namespace: text) -> int4
```

Remove all hierarchy rules for a resource type (start fresh)

**Returns:** Number of rules deleted

**Example:**
```sql
SELECT authz.clear_hierarchy('repo', 'default');
```

*Source: authz/src/functions/030_hierarchy.sql:133*

---

### authz.remove_hierarchy

```sql
authz.remove_hierarchy(p_resource_type: text, p_permission: text, p_implies: text, p_namespace: text) -> bool
```

Remove a permission implication rule

**Example:**
```sql
SELECT authz.remove_hierarchy('repo', 'admin', 'write', 'default');
```

*Source: authz/src/functions/030_hierarchy.sql:106*

---

## Listing

### authz.count_subjects

```sql
authz.count_subjects(p_resource_type: text, p_resource_id: text, p_permission: text, p_namespace: text, p_subject_type: text) -> int8
```

Count subjects who can access a resource (without fetching all)

**Parameters:**
- `p_resource_type`: Resource type (e.g., 'team')
- `p_resource_id`: Resource ID
- `p_permission`: Permission to check (e.g., 'member')
- `p_subject_type`: Optional filter to specific subject type (e.g., 'user')

**Returns:** Count of subjects with access

**Example:**
```sql
SELECT authz.count_subjects('team', 'engineering', 'member', 'default', 'user');
```

*Source: authz/src/functions/023_list.sql:204*

---

### authz.filter_authorized

```sql
authz.filter_authorized(p_subject_type: text, p_subject_id: text, p_resource_type: text, p_permission: text, p_resource_ids: text[], p_namespace: text) -> text[]
```

Filter a list to only resources the subject can access (batch check)

**Parameters:**
- `p_subject_type`: The subject type (e.g., 'user', 'api_key', 'service')
- `p_subject_id`: The subject ID
- `p_resource_ids`: Candidate resources to check (e.g., from a search query)

**Returns:** Subset of p_resource_ids the subject has permission on

**Example:**
```sql
-- User searches for "api", filter to only repos they can see
SELECT authz.filter_authorized('user', 'alice', 'repo', 'read',
ARRAY['payments-api', 'internal-api', 'public-api'], 'default');
-- Returns: ['payments-api', 'public-api'] (if alice can't see internal-api)
```

*Source: authz/src/functions/023_list.sql:285*

---

### authz.list_resources

```sql
authz.list_resources(p_subject_type: text, p_subject_id: text, p_resource_type: text, p_permission: text, p_namespace: text, p_limit: int4, p_cursor: text) -> table(resource_id: text)
```

List all resources a subject can access ("What can Alice read?")

**Parameters:**
- `p_subject_type`: The subject type (e.g., 'user', 'api_key', 'service')
- `p_subject_id`: The subject ID
- `p_limit`: Pagination limit. For >1000 resources, use filter_authorized() instead.
- `p_cursor`: Pass last resource_id from previous page to get next page

**Returns:** Resource IDs the subject can access (via direct grant, team membership, or folder inheritance)

**Example:**
```sql
-- Show alice all docs she can read
SELECT * FROM authz.list_resources('user', 'alice', 'doc', 'read', 'default');
-- Show API key all repos it can access
SELECT * FROM authz.list_resources('api_key', 'key-123', 'repo', 'read', 'default');
```

*Source: authz/src/functions/023_list.sql:1*

---

### authz.list_subjects

```sql
authz.list_subjects(p_resource_type: text, p_resource_id: text, p_permission: text, p_namespace: text, p_limit: int4, p_subject_type: text, p_cursor_type: text, p_cursor_id: text) -> table(subject_type: text, subject_id: text)
```

List all subjects who can access a resource ("Who can read this doc?")

**Parameters:**
- `p_subject_type`: Optional filter to only return subjects of this type (e.g., 'user')
- `p_cursor_type`: Subject type from last result for pagination (NULL for first page)
- `p_cursor_id`: Subject ID from last result for pagination (NULL for first page)

**Returns:** Subject (type, id) pairs with access (expands team memberships to leaf subjects)

**Example:**
```sql
-- First page
SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default');
-- Filter to only users
SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default', 100, 'user');
-- Next page using cursor from last result
SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default', 100, NULL, 'user', 'alice');
```

*Source: authz/src/functions/023_list.sql:97*

---

## Maintenance

### authz.get_stats

```sql
authz.get_stats(p_namespace: text) -> table(tuple_count: int8, hierarchy_rule_count: int8, unique_users: int8, unique_resources: int8)
```

Get namespace statistics for monitoring dashboards

**Returns:** tuple_count, hierarchy_rule_count, unique_users, unique_resources

**Example:**
```sql
SELECT * FROM authz.get_stats('default');
```

*Source: authz/src/functions/032_maintenance.sql:51*

---

### authz.grant_to_resources_bulk

```sql
authz.grant_to_resources_bulk(p_resource_type: text, p_resource_ids: text[], p_relation: text, p_subject_type: text, p_subject_id: text, p_subject_relation: text, p_namespace: text) -> int4
```

Grant same user/team access to many resources at once

**Parameters:**
- `p_resource_ids`: Array of resource IDs to grant access on

**Returns:** Count of grants created

**Example:**
```sql
-- Give alice read access to 100 docs in one call
SELECT authz.grant_to_resources_bulk('doc', ARRAY['doc1', 'doc2', ...],
'read', 'user', 'alice', NULL, 'default');
```

*Source: authz/src/functions/032_maintenance.sql:81*

---

### authz.verify_integrity

```sql
authz.verify_integrity(p_namespace: text) -> table(resource_type: text, resource_id: text, status: text, details: text)
```

Check for data corruption (circular memberships, broken hierarchies, partition issues)

**Returns:** Rows describing any issues found, empty if healthy

**Example:**
```sql
-- Run as part of health checks
SELECT * FROM authz.verify_integrity('default');
```

*Source: authz/src/functions/032_maintenance.sql:1*

---

## Multi-tenancy

### authz.clear_tenant

```sql
authz.clear_tenant() -> void
```

Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants.

**Example:**
```sql
SELECT authz.clear_tenant();
```

*Source: authz/src/functions/034_rls.sql:17*

---

### authz.set_tenant

```sql
authz.set_tenant(p_tenant_id: text) -> void
```

Set tenant context for RLS (session-level, persists across transactions). For connection pools, call clear_tenant() before returning connections.

**Parameters:**
- `p_tenant_id`: Tenant ID

**Example:**
```sql
SELECT authz.set_tenant('acme-corp');
```

*Source: authz/src/functions/034_rls.sql:1*

---

## Permission Checks

### authz.check

```sql
authz.check(p_subject_type: text, p_subject_id: text, p_permission: text, p_resource_type: text, p_resource_id: text, p_namespace: text) -> bool
```

Check if a subject has a permission on a resource

**Parameters:**
- `p_subject_type`: The subject type (e.g., 'user', 'api_key', 'service')
- `p_subject_id`: The subject ID
- `p_permission`: The permission to verify (e.g., 'read', 'write', 'admin')
- `p_resource_type`: The type of resource (e.g., 'repo', 'doc')
- `p_resource_id`: The resource identifier

**Returns:** True if the subject has the permission PERFORMANCE: This function performs graph traversal on every call (subject groups, resource ancestors, permission hierarchy). Recursion depth is bounded at 50. For high-throughput scenarios, consider application-layer caching of results.

**Example:**
```sql
SELECT authz.check('user', 'alice', 'read', 'doc', 'spec-123');
SELECT authz.check('api_key', 'key-123', 'read', 'repo', 'api');
```

*Source: authz/src/functions/022_check.sql:84*

---

### authz.check_all

```sql
authz.check_all(p_subject_type: text, p_subject_id: text, p_permissions: text[], p_resource_type: text, p_resource_id: text, p_namespace: text) -> bool
```

Check if a subject has all of the specified permissions

**Parameters:**
- `p_subject_type`: The subject type
- `p_subject_id`: The subject ID
- `p_permissions`: Array of permissions (subject needs all of them)
- `p_resource_type`: The type of resource
- `p_resource_id`: The resource identifier

**Returns:** True if the subject has all of the permissions

**Example:**
```sql
SELECT authz.check_all('user', 'alice', ARRAY['read', 'write'], 'doc', 'spec-123');
```

*Source: authz/src/functions/022_check.sql:148*

---

### authz.check_any

```sql
authz.check_any(p_subject_type: text, p_subject_id: text, p_permissions: text[], p_resource_type: text, p_resource_id: text, p_namespace: text) -> bool
```

Check if a subject has any of the specified permissions

**Parameters:**
- `p_subject_type`: The subject type
- `p_subject_id`: The subject ID
- `p_permissions`: Array of permissions (subject needs at least one)
- `p_resource_type`: The type of resource
- `p_resource_id`: The resource identifier

**Returns:** True if the subject has at least one of the permissions

**Example:**
```sql
SELECT authz.check_any('user', 'alice', ARRAY['read', 'write'], 'doc', 'spec-123');
```

*Source: authz/src/functions/022_check.sql:119*

---

## Subject Grants

### authz.list_subject_grants

```sql
authz.list_subject_grants(p_subject_type: text, p_subject_id: text, p_namespace: text, p_resource_type: text) -> table(resource_type: text, resource_id: text, relation: text, subject_relation: text, expires_at: timestamptz)
```

List all grants for a subject ("What can this API key access?")

**Parameters:**
- `p_subject_type`: Subject type (e.g., 'api_key', 'service')
- `p_subject_id`: Subject identifier
- `p_namespace`: Namespace to search in
- `p_resource_type`: Optional filter by resource type

**Returns:** All active (non-expired) grants for this subject

**Example:**
```sql
-- Get all grants for an API key
SELECT * FROM authz.list_subject_grants('api_key', 'key-123', 'default');
-- Get only note-related grants
SELECT * FROM authz.list_subject_grants('api_key', 'key-123', 'default', 'note');
```

*Source: authz/src/functions/035_subject_grants.sql:1*

---

### authz.revoke_resource_grants

```sql
authz.revoke_resource_grants(p_resource_type: text, p_resource_id: text, p_namespace: text, p_relation: text) -> int4
```

Revoke all grants on a resource (cleanup when deleting a resource)

**Parameters:**
- `p_resource_type`: Resource type (e.g., 'note', 'doc', 'repo')
- `p_resource_id`: Resource identifier
- `p_namespace`: Namespace to search in
- `p_relation`: Optional filter to only revoke specific relation/permission

**Returns:** Count of grants revoked

**Example:**
```sql
-- Revoke all grants on a note before deletion
SELECT authz.revoke_resource_grants('note', 'note-123', 'default');
-- Revoke only 'view' grants on a note
SELECT authz.revoke_resource_grants('note', 'note-123', 'default', 'view');
```

*Source: authz/src/functions/035_subject_grants.sql:75*

---

### authz.revoke_subject_grants

```sql
authz.revoke_subject_grants(p_subject_type: text, p_subject_id: text, p_namespace: text, p_resource_type: text) -> int4
```

Revoke all grants for a subject (cleanup on deletion)

**Parameters:**
- `p_subject_type`: Subject type (e.g., 'api_key', 'service')
- `p_subject_id`: Subject identifier
- `p_namespace`: Namespace to search in
- `p_resource_type`: Optional filter to only revoke grants on specific resource type

**Returns:** Count of grants revoked

**Example:**
```sql
-- Revoke all grants for an API key before deletion
SELECT authz.revoke_subject_grants('api_key', 'key-123', 'default');
-- Revoke only note-related grants
SELECT authz.revoke_subject_grants('api_key', 'key-123', 'default', 'note');
```

*Source: authz/src/functions/035_subject_grants.sql:36*

---

## Writes

### authz.write

```sql
authz.write(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_namespace: text, p_expires_at: timestamptz) -> int8
```

Simpler write_tuple when you don't need subject_relation

**Example:**
```sql
SELECT authz.write('doc', 'spec', 'read', 'user', 'alice', 'default');
```

*Source: authz/src/functions/020_write.sql:116*

---

### authz.write_tuple

```sql
authz.write_tuple(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_id: text, p_subject_relation: text, p_namespace: text, p_expires_at: timestamptz) -> int8
```

Grant a permission to a user or team on a resource

**Parameters:**
- `p_relation`: Use 'member' for team nesting, 'parent' for folder hierarchies, otherwise this is the permission being granted (e.g., 'read', 'admin')
- `p_subject_relation`: Grants to a subset of a team. 'admin' means only team admins get this permission, not all members.
- `p_expires_at`: Permission auto-revokes at this time. Useful for temporary access like contractor permissions or review periods.

**Returns:** Tuple ID (for tracking/debugging)

**Example:**
```sql
-- Give alice read access to a doc
SELECT authz.write_tuple('doc', 'spec', 'read', 'user', 'alice', NULL, 'default');
-- Make the infra team part of the platform team (team nesting)
SELECT authz.write_tuple('team', 'platform', 'member', 'team', 'infra', NULL, 'default');
-- Give only team admins (not all members) write access
SELECT authz.write_tuple('repo', 'api', 'write', 'team', 'eng', 'admin', 'default');
```

*Source: authz/src/functions/020_write.sql:1*

---

### authz.write_tuples_bulk

```sql
authz.write_tuples_bulk(p_resource_type: text, p_resource_id: text, p_relation: text, p_subject_type: text, p_subject_ids: text[], p_namespace: text) -> int4
```

Grant same permission to many users at once (one SQL round-trip)

**Parameters:**
- `p_subject_ids`: Array of user/team IDs to grant access to

**Returns:** Count of grants created

**Example:**
```sql
-- Onboard 100 users to a project in one call
SELECT authz.write_tuples_bulk('project', 'atlas', 'read', 'user',
ARRAY['alice', 'bob', 'charlie'], 'default');
```

*Source: authz/src/functions/020_write.sql:135*

---
