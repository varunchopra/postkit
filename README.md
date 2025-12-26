# pg-authz

Authorization for Postgres. No external services, no SDKs -- just SQL functions.

```sql
SELECT authz.check('alice', 'read', 'document', 'doc-123');  -- true/false
```

## Why?

- Runs inside your existing Postgres
- Nested teams (groups can contain groups)
- Permission hierarchies (admin -> write -> read)
- Multi-tenant with row-level security
- Time-bound permissions with expiration
- Built-in audit logging

## Install

```bash
psql $DATABASE_URL -f https://raw.githubusercontent.com/varunchopra/pg-authz/main/dist/pg-authz.sql
```

## Quick Start

```sql
-- Create a permission hierarchy: admin -> write -> read
SELECT authz.add_hierarchy('repo', 'admin', 'write');
SELECT authz.add_hierarchy('repo', 'write', 'read');

-- Create a team and add members
SELECT authz.write('team', 'engineering', 'member', 'user', 'alice');
SELECT authz.write('team', 'engineering', 'member', 'user', 'bob');

-- Grant the team admin access to a repo
SELECT authz.write('repo', 'acme/api', 'admin', 'team', 'engineering');

-- Check permissions
SELECT authz.check('alice', 'read', 'repo', 'acme/api');   -- true (admin implies read)
SELECT authz.check('alice', 'admin', 'repo', 'acme/api');  -- true (via team)
SELECT authz.check('charlie', 'read', 'repo', 'acme/api'); -- false (not on team)
```

## Core API

```sql
-- Grant/revoke permissions
authz.write(resource_type, resource_id, relation, subject_type, subject_id)
authz.delete(resource_type, resource_id, relation, subject_type, subject_id)

-- Check permissions
authz.check(user_id, permission, resource_type, resource_id)
authz.check_any(user_id, permissions[], resource_type, resource_id)
authz.check_all(user_id, permissions[], resource_type, resource_id)

-- List/filter
authz.list_resources(user_id, resource_type, permission)
authz.list_users(resource_type, resource_id, permission)
authz.filter_authorized(user_id, resource_type, permission, resource_ids[])

-- Hierarchy
authz.add_hierarchy(resource_type, permission, implies)

-- Debug
authz.explain_text(user_id, permission, resource_type, resource_id)
```

## Nested Teams

Teams can contain other teams:

```sql
-- alice is in infrastructure, which is in platform, which is in engineering
SELECT authz.write('team', 'infrastructure', 'member', 'user', 'alice');
SELECT authz.write('team', 'platform', 'member', 'team', 'infrastructure');
SELECT authz.write('team', 'engineering', 'member', 'team', 'platform');

-- Grant engineering access to a repo
SELECT authz.write('repo', 'api', 'read', 'team', 'engineering');

-- alice has access through the chain
SELECT authz.check('alice', 'read', 'repo', 'api');  -- true
```

Circular memberships are detected and rejected.

## Resource Hierarchies

Resources can contain other resources:

```sql
-- doc:spec is inside folder:projects
SELECT authz.write('doc', 'spec', 'parent', 'folder', 'projects');

-- folder:projects is inside folder:root
SELECT authz.write('folder', 'projects', 'parent', 'folder', 'root');

-- Grant read on the root folder
SELECT authz.write('folder', 'root', 'read', 'user', 'alice');

-- alice can read doc:spec (inherited through hierarchy)
SELECT authz.check('alice', 'read', 'doc', 'spec');  -- true
```

This combines with nested teams and permission hierarchies:

```sql
-- team:eng has admin on folder:projects
SELECT authz.write('folder', 'projects', 'admin', 'team', 'eng');

-- alice is in team:eng
SELECT authz.write('team', 'eng', 'member', 'user', 'alice');

-- alice has read on doc:spec (via: eng membership -> admin on folder -> admin implies read -> folder contains doc)
SELECT authz.check('alice', 'read', 'doc', 'spec');  -- true
```

Circular hierarchies are detected and rejected.

## Time-Bound Permissions

```sql
-- Grant access that expires in 30 days
SELECT authz.write('repo', 'api', 'read', 'user', 'contractor', NULL, 'default',
                   now() + interval '30 days');

-- Find expiring grants
SELECT * FROM authz.list_expiring('7 days');

-- Clean up expired (run via cron)
SELECT authz.cleanup_expired();
```

## Multi-Tenancy

All functions accept an optional `namespace` parameter (default: `'default'`):

```sql
SELECT authz.write('doc', '1', 'read', 'user', 'alice', NULL, 'tenant-acme');
SELECT authz.check('alice', 'read', 'doc', '1', 'tenant-acme');  -- true
SELECT authz.check('alice', 'read', 'doc', '1', 'tenant-other'); -- false
```

Row-level security enforces tenant isolation for non-superusers:

```sql
SELECT authz.set_tenant('acme');
-- All queries now scoped to 'acme' namespace
```

## Audit Logging

All changes are logged to `authz.audit_events`:

```sql
-- Set actor context before operations
SELECT authz.set_actor('admin@acme.com', 'req-123', 'Quarterly review');

-- Query audit log
SELECT * FROM authz.audit_events ORDER BY event_time DESC LIMIT 100;
```

Event types:
- `tuple_created` / `tuple_updated` / `tuple_deleted` — permission changes
- `hierarchy_created` / `hierarchy_deleted` — hierarchy rule changes

Expiration timestamps are captured in `expires_at`, enabling historical analysis of time-bound permissions.

## Dry Run / What-If

Use transactions to preview the impact of permission changes:

```sql
BEGIN;

-- Make the change
SELECT authz.delete('team', 'eng', 'member', 'user', 'alice');

-- See the impact
SELECT * FROM authz.list_resources('alice', 'repo', 'read');
SELECT * FROM authz.list_users('read', ('repo', 'api'));

-- Undo
ROLLBACK;
```

## How It Works

Permissions are evaluated at query time using recursive CTEs. When you call `authz.check()`:

1. Find all groups the user belongs to (including nested teams)
2. Find resource and all ancestor resources (via parent relations)
3. Find all grants on resource or ancestors (direct + via groups)
4. Expand permission hierarchy (admin -> write -> read)
5. Check if the requested permission exists

## Limitations

- Nested teams and resource hierarchies limited to 50 levels

## Development

```bash
make setup   # Start Postgres in Docker
make test    # Run tests
make clean   # Cleanup
```

## License

Apache 2.0
