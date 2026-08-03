# postkit SDK

Python client for postkit.

## Installation

```bash
pip install postkit
```

## Usage

```python
import psycopg
from postkit.authz import AuthzClient
from postkit.authn import AuthnClient

conn = psycopg.connect("postgresql://...")
cursor = conn.cursor()

# Authorization
authz = AuthzClient(cursor, namespace="my-app")
authz.set_hierarchy("repo", "admin", "write", "read")
authz.grant("admin", resource=("repo", "api"), subject=("user", "alice"))
if authz.check(("user", "alice"), "read", ("repo", "api")):
    print("Access granted")

# Authentication
authn = AuthnClient(cursor, namespace="my-app")
user_id = authn.create_user("alice@example.com", password_hash="argon2...")
session_id = authn.create_session(user_id, token_hash="sha256...")
```

## Tenant Context and Transactions

Constructing a client calls `{module}.set_tenant(namespace)` immediately. The setting is transaction-scoped, so inside an open transaction the constructor taints that transaction's context for the module until commit or rollback; an unrelated client built mid-transaction can therefore change which rows a later raw SQL statement sees.

Every SDK call needs a transaction for that context. When the connection is idle, the SDK opens and commits a transaction for the call. When a non-autocommit connection already has an open transaction, the call joins it and is not durable until that transaction commits.

Queue workers pass the `fence_token` returned by `pull()` to every operation on that attempt. Database work, the pull, and `ack()` can share one transaction and roll back together. For external effects such as email, payments, or HTTP calls, commit the pull before processing, use a stable idempotency key, and acknowledge in a later transaction. If the pull commit outcome is unknown, do not process the returned job; reconnect and resume polling.

If a transaction containing `pull()` rolls back, the job is pending again and its attempt count is unchanged. Sequence values do not roll back, so discard the returned fence token and pull again; that token will never be issued to a later attempt.

In CI, call `client.assert_rls_active()` during setup. A suite connecting as a superuser or `BYPASSRLS` role (the docker default) bypasses every RLS policy and exercises none of the tenancy model.

## Requirements

- PostgreSQL 14+
- The postkit SQL schema installed in your database

See the [main repository](https://github.com/varunchopra/postkit) for SQL installation instructions.
