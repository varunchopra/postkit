# pg-authz

Authorization for Postgres. No external services, no SDKs -- just SQL functions.

```sql
SELECT authz.check('alice', 'read', 'document', 'doc-123');  -- true/false
```

## Why?

- Runs inside your existing Postgres, no extra infrastructure
- O(1) permission checks (pre-computed, not graph traversal)
- Multi-tenant via namespaces
- Supports teams and permission hierarchies

## Install

```bash
psql $DATABASE_URL -f https://raw.githubusercontent.com/varunchopra/pg-authz/main/dist/pg-authz.sql
```

Or build from source:

```bash
git clone https://github.com/varunchopra/pg-authz.git
cd pg-authz && make build
psql $DATABASE_URL -f dist/pg-authz.sql
```

## Quick Start

```sql
-- 1. Define permission hierarchy
SELECT authz.add_hierarchy('repo', 'admin', 'write');
SELECT authz.add_hierarchy('repo', 'write', 'read');

-- 2. Create a team and add members
SELECT authz.write('team', 'engineering', 'member', 'user', 'alice');
SELECT authz.write('team', 'engineering', 'member', 'user', 'bob');

-- 3. Grant the team access to a resource
SELECT authz.write('repo', 'acme/api', 'admin', 'team', 'engineering');

-- 4. Check permissions
SELECT authz.check('alice', 'read', 'repo', 'acme/api');   -- true (admin implies read)
SELECT authz.check('alice', 'admin', 'repo', 'acme/api');  -- true
SELECT authz.check('charlie', 'read', 'repo', 'acme/api'); -- false (not on team)
```

## API Reference

### Core

| Function | Description |
|----------|-------------|
| `authz.write(resource_type, resource_id, relation, subject_type, subject_id)` | Grant permission |
| `authz.delete(resource_type, resource_id, relation, subject_type, subject_id)` | Revoke permission |
| `authz.check(user_id, permission, resource_type, resource_id)` | Check if user has permission |

### Batch Operations

| Function | Description |
|----------|-------------|
| `authz.check_any(user_id, permissions[], resource_type, resource_id)` | Has any of these permissions? |
| `authz.check_all(user_id, permissions[], resource_type, resource_id)` | Has all of these permissions? |
| `authz.filter_authorized(user_id, resource_type, permission, resource_ids[])` | Filter to authorized resources |

### Queries

| Function | Description |
|----------|-------------|
| `authz.list_resources(user_id, resource_type, permission)` | What resources can user access? |
| `authz.list_users(permission, resource_type, resource_id)` | Who can access this resource? |

### Hierarchy

| Function | Description |
|----------|-------------|
| `authz.add_hierarchy(resource_type, permission, implies)` | Add hierarchy rule |

### Debugging

| Function | Description |
|----------|-------------|
| `authz.explain_text(user_id, permission, resource_type, resource_id)` | Show permission path |
| `authz.get_stats(namespace)` | Tuple counts and amplification factor |
| `authz.verify_computed(namespace)` | Check for consistency issues |
| `authz.repair_computed(namespace)` | Rebuild computed permissions |

### Audit Logging

| Function | Description |
|----------|-------------|
| `authz.set_actor(actor_id, request_id, reason)` | Set actor context for audit trail |
| `authz.ensure_audit_partitions(months_ahead)` | Create partitions for future months |
| `authz.drop_audit_partitions(older_than_months)` | Drop old partitions (default: 84 months) |

## Usage Examples

### Check permissions in your app

```python
allowed = db.execute(
    "SELECT authz.check(%s, 'edit', 'document', %s)",
    [user_id, doc_id]
).fetchone()[0]

if not allowed:
    raise PermissionDenied()
```

### Filter queries to authorized resources

```sql
SELECT d.* FROM documents d
WHERE d.id = ANY(
    authz.filter_authorized('alice', 'document', 'view',
        ARRAY(SELECT id FROM documents WHERE folder_id = 123)
    )
)
```

### Multi-tenancy

All functions accept an optional namespace parameter (default: `'default'`):

```sql
SELECT authz.write('doc', 'doc-1', 'owner', 'user', 'alice', NULL, 'tenant-acme');
SELECT authz.check('alice', 'view', 'doc', 'doc-1', 'tenant-acme');  -- true
SELECT authz.check('alice', 'view', 'doc', 'doc-1', 'tenant-other'); -- false
```

### Row-Level Security

pg-authz enforces tenant isolation via RLS. Set tenant context (`authz.set_tenant`) before operations:

```sql
SELECT authz.set_tenant('acme');

-- All operations now scoped to 'acme' namespace
SELECT authz.write('doc', '1', 'read', 'user', 'alice', 'acme');
SELECT authz.check('alice', 'read', 'doc', '1', 'acme');
```

Without tenant context, queries return no rows and writes fail. Only superusers bypass RLS.

### Audit Logging

All changes are logged to `authz.audit_events`:

```sql
-- Set actor context (recommended)
SELECT authz.set_actor('admin@acme.com', 'req-123', 'Quarterly access review');

-- Perform operations
SELECT authz.write('repo', 'api', 'admin', 'team', 'platform');

-- Query audit log
SELECT * FROM authz.audit_events
WHERE namespace = 'default'
ORDER BY event_time DESC
LIMIT 100;
```

Partition management:

```sql
-- Create partitions for next 6 months (run monthly via cron)
SELECT authz.ensure_audit_partitions(6);

-- Drop partitions older than 7 years
SELECT authz.drop_audit_partitions(84);
```

## How It Works

Relationships are stored as tuples:

```
(team, engineering, member, user, alice)   -- alice is member of engineering
(repo, acme/api, admin, team, engineering) -- engineering has admin on repo
```

Permission hierarchy defines implications:

```
admin -> write -> read
```

On write, permissions are pre-computed. When you call `authz.write()`, a trigger expands group memberships and hierarchy rules into a `computed` table. This makes `authz.check()` an O(1) index lookup.

## Limitations

- Single-level groups: teams can have members, but not nested teams
- No resource hierarchies: folders containing documents must be modeled explicitly
- Write amplification: large groups multiply computed entries (monitor with `authz.get_stats()`)

## Development

```bash
make setup   # Start Postgres in Docker
make test    # Build and run tests
make clean   # Stop Postgres, remove dist/
```

## License

Apache 2.0
