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

Every SDK call needs a transaction for that context. On autocommit connections each call runs in its own transaction and commits immediately. On non-autocommit connections each call joins the connection's open transaction: nothing is durable until you commit, and a rollback takes it all with it, including a queue claim from `pull()`. That is the intended model for transactional consumers; `nack`/`fail` accept the pending job a rollback leaves behind.

In CI, call `client.assert_rls_active()` during setup. A suite connecting as a superuser or `BYPASSRLS` role (the docker default) bypasses every RLS policy and exercises none of the tenancy model.

## Requirements

- PostgreSQL 14+
- The postkit SQL schema installed in your database

See the [main repository](https://github.com/varunchopra/postkit) for SQL installation instructions.
