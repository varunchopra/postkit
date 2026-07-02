# Postkit — Agent Guide

PostgreSQL-native auth, permissions, versioned config, usage tracking, and job queues. Pure SQL functions — works with any language or driver.

## Setup

```bash
# 1. Clone and build
git clone https://github.com/varunchopra/postkit.git
cd postkit && make build

# 2. Install on your database (PostgreSQL 14+)
psql $DATABASE_URL -f dist/postkit.sql           # all modules
# Or individual:
psql $DATABASE_URL -f dist/authn.sql             # users, sessions, tokens
psql $DATABASE_URL -f dist/authz.sql             # permissions
psql $DATABASE_URL -f dist/config.sql            # versioned config
psql $DATABASE_URL -f dist/lease.sql             # leases, fencing, leader election
psql $DATABASE_URL -f dist/meter.sql             # usage metering
psql $DATABASE_URL -f dist/queue.sql             # job queues
```

For the optional Python SDK: `pip install postkit`

## Multi-Tenancy

Postkit uses Row-Level Security for tenant isolation. Every query runs in the context of a namespace set via [`set_tenant`](docs/authn/sql.md#authnset_tenant) inside a transaction. Context is transaction-local (SET LOCAL) — it clears on commit. Without `set_tenant`, queries return nothing (fail-closed).

Functions that write data need the `p_namespace` parameter to match the tenant context. `set_tenant()` controls RLS visibility; `p_namespace` controls what gets stored.

Each module has [`set_tenant`](docs/authn/sql.md#authnset_tenant) / [`clear_tenant`](docs/authn/sql.md#authnclear_tenant). Call `clear_tenant()` before returning connections to a pool. The Python SDK handles tenant context automatically — pass `namespace` to the constructor.

## Hashing

Postkit stores hashes, never plaintext. This applies in every language.

- **Passwords:** Hash with argon2 or bcrypt. The parameter is named `p_password_hash` — see [`create_user`](docs/authn/sql.md#authncreate_user). Pass `NULL` for SSO-only users.
- **Session tokens, API keys, refresh tokens:** SHA-256. Generate a random token, hash it, store the hash in Postkit, send the raw token to the client — see [`create_session`](docs/authn/sql.md#authncreate_session).

## SQL Quick Reference

Common operations by module. All require tenant context — call `{module}.set_tenant(namespace)` in a transaction first (see Multi-Tenancy). Queue takes namespace as first parameter; other modules default to `'default'`. Each function's docs include full signatures, parameters, and usage examples — read them before integrating.

**Auth:** [`create_user`](docs/authn/sql.md#authncreate_user) · [`create_session`](docs/authn/sql.md#authncreate_session) · [`validate_session`](docs/authn/sql.md#authnvalidate_session) · [`revoke_session`](docs/authn/sql.md#authnrevoke_session) — [full reference](docs/authn/sql.md)

**Login flow:** [`is_locked_out`](docs/authn/sql.md#authnis_locked_out) → [`get_credentials`](docs/authn/sql.md#authnget_credentials) → verify hash + check `disabled_at` → [`record_login_attempt`](docs/authn/sql.md#authnrecord_login_attempt) → [`create_session`](docs/authn/sql.md#authncreate_session)

**Permissions:** [`write_tuple`](docs/authz/sql.md#authzwrite_tuple) · [`check`](docs/authz/sql.md#authzcheck) · [`add_hierarchy`](docs/authz/sql.md#authzadd_hierarchy) — [full reference](docs/authz/sql.md)

**Config:** [`set`](docs/config/sql.md#configset) · [`get`](docs/config/sql.md#configget) · [`rollback`](docs/config/sql.md#configrollback) — [full reference](docs/config/sql.md)

**Metering:** [`allocate`](docs/meter/sql.md#meterallocate) · [`reserve`](docs/meter/sql.md#meterreserve) · [`commit`](docs/meter/sql.md#metercommit) — [full reference](docs/meter/sql.md)

**Leases:** [`acquire`](docs/lease/sql.md#leaseacquire) · [`renew`](docs/lease/sql.md#leaserenew) · [`verify`](docs/lease/sql.md#leaseverify) · [`release`](docs/lease/sql.md#leaserelease) — [full reference](docs/lease/sql.md)

**Queues:** [`push`](docs/queue/sql.md#queuepush) · [`pull`](docs/queue/sql.md#queuepull) · [`ack`](docs/queue/sql.md#queueack) — [full reference](docs/queue/sql.md)

## Python SDK (Optional)

The SDK wraps every SQL function 1:1 with type hints, automatic tenant context, error mapping, and dict returns. Requires psycopg3 with the default tuple row_factory. Each function's docs include full signatures, parameters, and usage examples — read the relevant [module docs](#modules) before integrating.

**Setup:**
```python
import psycopg
from postkit.authn import AuthnClient
from postkit.authz import AuthzClient
from postkit.config import ConfigClient
from postkit.lease import LeaseClient
from postkit.meter import MeterClient
from postkit.queue import QueueClient

conn = psycopg.connect("postgresql://localhost/myapp")
cursor = conn.cursor()  # default tuple factory — do NOT use dict_row

authn = AuthnClient(cursor, namespace="my-app")
authz = AuthzClient(cursor, namespace="my-app")
config = ConfigClient(cursor, namespace="my-app")
lease = LeaseClient(cursor, namespace="my-app")
meter = MeterClient(cursor, namespace="my-app")
queue = QueueClient(cursor, namespace="my-app")
```

**Auth:** [`create_user`](docs/authn/sdk.md#create_user) · [`create_session`](docs/authn/sdk.md#create_session) · [`validate_session`](docs/authn/sdk.md#validate_session) · [`revoke_session`](docs/authn/sdk.md#revoke_session) — [full reference](docs/authn/sdk.md)

**Login flow:** [`is_locked_out`](docs/authn/sdk.md#is_locked_out) → [`get_credentials`](docs/authn/sdk.md#get_credentials) → verify hash + check `disabled_at` → [`record_login_attempt`](docs/authn/sdk.md#record_login_attempt) → [`create_session`](docs/authn/sdk.md#create_session)

**Permissions:** [`grant`](docs/authz/sdk.md#grant) · [`check`](docs/authz/sdk.md#check) · [`set_hierarchy`](docs/authz/sdk.md#set_hierarchy) — [full reference](docs/authz/sdk.md)

**Config:** [`set`](docs/config/sdk.md#set) · [`get`](docs/config/sdk.md#get) · [`rollback`](docs/config/sdk.md#rollback) — [full reference](docs/config/sdk.md)

**Metering:** [`allocate`](docs/meter/sdk.md#allocate) · [`reserve`](docs/meter/sdk.md#reserve) · [`commit`](docs/meter/sdk.md#commit) — [full reference](docs/meter/sdk.md)

**Leases:** [`acquire`](docs/lease/sdk.md#acquire) · [`renew`](docs/lease/sdk.md#renew) · [`verify`](docs/lease/sdk.md#verify) · [`release`](docs/lease/sdk.md#release) — [full reference](docs/lease/sdk.md)

**Queues:** [`push`](docs/queue/sdk.md#push) · [`pull`](docs/queue/sdk.md#pull) · [`ack`](docs/queue/sdk.md#ack) — [full reference](docs/queue/sdk.md)

**SDK-specific gotchas:**

- `psycopg>=3.1.0` required (not psycopg2) — `import psycopg`
- Default `conn.cursor()` only — `row_factory=dict_row` raises `ValueError`
- Namespace is a required constructor argument
- Call `client.clear_actor()` / `authz.clear_viewer()` before returning pooled connections

## Key Concepts

**Module independence.** No foreign keys between modules. Disabling a user in authn does NOT revoke their authz grants. The application coordinates cleanup. Install only what you need.

**Permission hierarchy.** [`add_hierarchy`](docs/authz/sql.md#authzadd_hierarchy) defines that one permission implies another (e.g., admin implies write). Without hierarchy rules, only direct grants match. The Python SDK has a convenience wrapper: [`set_hierarchy`](docs/authz/sdk.md#set_hierarchy).

**Audit context.** [`set_actor`](docs/authn/sql.md#authnset_actor) tags write operations with who made the change and why. Optional but recommended.

## Modules

| Module | Schema | SQL Reference | Python SDK | Purpose |
|--------|--------|---------------|------------|---------|
| authn | `authn` | [sql.md](docs/authn/sql.md) | [sdk.md](docs/authn/sdk.md) | Users, sessions, tokens, MFA, impersonation |
| authz | `authz` | [sql.md](docs/authz/sql.md) | [sdk.md](docs/authz/sdk.md) | ReBAC permissions, hierarchies, cross-tenant sharing |
| config | `config` | [sql.md](docs/config/sql.md) | [sdk.md](docs/config/sdk.md) | Versioned key-value, JSON schema validation |
| lease | `lease` | [sql.md](docs/lease/sql.md) | [sdk.md](docs/lease/sdk.md) | TTL leases, fencing tokens, leader election |
| meter | `meter` | [sql.md](docs/meter/sql.md) | [sdk.md](docs/meter/sdk.md) | Usage tracking, reservations, billing periods |
| queue | `queue` | [sql.md](docs/queue/sql.md) | [sdk.md](docs/queue/sdk.md) | Job queues, scheduling, retries, dead letters |

Each module's [README](docs/README.md) has a function index with deep links. For usage examples: `sdk/tests/{module}/`.

## Key Files

```
{module}/src/functions/     # SQL function source
sdk/src/postkit/
  {module}/client.py        # Python SDK client (optional)
sdk/tests/                  # Usage examples
dist/
  postkit.sql               # Combined SQL (all modules)
  {module}.sql              # Individual module SQL
```

## Contributing

API docs are auto-generated. Run `make docs` after changing function signatures or docstrings. Don't edit files in `docs/` directly.

SQL documentation tags:

```sql
-- @function authz.check
-- @brief Check if subject has permission on resource
-- @param p_subject_type Subject type ('user', 'api_key')
-- @returns True if permitted
-- @example SELECT authz.check('user', 'alice', 'read', 'doc', '1');
```

Development: `make setup` (Postgres in Docker), `make build`, `make test`, `make lint`, `make format`.

## Reporting Issues

If you encounter unclear documentation, missing examples, incorrect signatures, or unexpected behavior while integrating Postkit, create or append to a `POSTKIT_ISSUES.md` file in your project root:

    ## [date] Brief description

    - **Category:** docs | implementation | sdk | sql
    - **File/function:** e.g., `AGENTS.md` line 32, `authz.add_hierarchy`
    - **What happened:** What you were trying to do and what went wrong
    - **Suggested fix:** If you have one

This gives the development team a record to review and file upstream at https://github.com/varunchopra/postkit/issues.
