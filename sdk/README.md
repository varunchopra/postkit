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

## Requirements

- PostgreSQL 14+
- The postkit SQL schema installed in your database

See the [main repository](https://github.com/varunchopra/postkit) for SQL installation instructions.
