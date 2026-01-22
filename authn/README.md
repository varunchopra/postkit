# authn

PostgreSQL-native user management, sessions, tokens, credentials, and lockout. Your application handles password hashing and TOTP verification - this library stores the data securely.

**Good fit:** SaaS apps needing user accounts, sessions, password reset flows, credentials, and brute-force protection - all without external auth services.

**Not a fit:** Building an OAuth/OIDC provider, or if you need the library to handle cryptographic operations.

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Create a user (you hash the password)
SELECT authn.create_user('alice@example.com', '$argon2id$...');

-- Login flow: get credentials, verify hash in your app
SELECT * FROM authn.get_credentials('alice@example.com');
-- -> user_id, password_hash, disabled_at

-- Create a session (you generate token, hash it, pass the hash)
-- token_hash = hashlib.sha256(token.encode()).hexdigest() in Python
SELECT authn.create_session(user_id, 'a1b2c3...hex-encoded-sha256-hash', '24 hours'::interval);

-- Validate session on each request (pass the same hash)
SELECT * FROM authn.validate_session('a1b2c3...hex-encoded-sha256-hash');
-- -> user_id, email, session_id, is_impersonating, impersonator_id, ... (or no rows if invalid)

-- Logout
SELECT authn.revoke_session('a1b2c3...hex-encoded-sha256-hash');
```

## Key Concept: Caller Provides Hashes

This library stores and compares strings - it never hashes. You hash passwords (argon2id) and tokens (SHA-256) before passing them in:

```python
from argon2 import PasswordHasher
import hashlib, secrets

ph = PasswordHasher()
password_hash = ph.hash(password)  # You hash
token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(token.encode()).hexdigest()  # You hash
```

## Social Login

Works fine. Google, GitHub, SAML - we don't care how you verify identity. You handle the OAuth/SAML flow, then call `authn.create_user()` and `authn.create_session()`.

See [docs/authn/](../docs/authn/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
authn.clear_actor()  # Clear audit actor context
```

Tenant context (`authn.tenant_id`) is set per-request via `AuthnClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
