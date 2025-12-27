# authn

PostgreSQL-native user management, sessions, tokens, MFA, and lockout. Your application handles
password hashing and TOTP verification - this library stores the data securely.

**Good fit:** SaaS apps needing user accounts, sessions, password reset flows, MFA, and
brute-force protection - all without external auth services.

**Not a fit:** Building an OAuth/OIDC provider (letting other apps "Login with YourApp"),
or if you need the library to handle cryptographic operations (we store hashes, you generate them).

**Note:** Social login works fine. Google, GitHub, carrier pigeon - we don't care how you verify
identity. You handle the OAuth flow, then use authn to store users and sessions.

## Install

```bash
psql $DATABASE_URL -f https://raw.githubusercontent.com/varunchopra/postkit/main/dist/authn.sql
```

## Features

- User management with email normalization
- Session tokens with configurable expiry
- One-time tokens (password reset, email verify, magic links)
- MFA secrets storage (TOTP, WebAuthn, recovery codes)
- Brute-force protection with lockout
- Multi-tenant with row-level security
- Audit logging

## Philosophy

1. **Pure SQL** - No extensions. Standard PostgreSQL 14+.
2. **Caller provides hashes** - Passwords arrive pre-hashed (argon2id). Tokens arrive pre-hashed (SHA-256).
3. **No crypto opinions** - Library stores and compares strings, never hashes.
4. **Multi-tenant** - All tables have `namespace` column. RLS isolates tenants.

## Quick Start

```sql
-- Create a user (you hash the password)
SELECT authn.create_user('alice@example.com', '$argon2id$...');

-- Login flow: get credentials, verify hash in your app
SELECT * FROM authn.get_credentials('alice@example.com');
-- → user_id, password_hash, disabled_at

-- Create a session (you generate and hash the token)
SELECT authn.create_session(user_id, sha256('random-token'), '24 hours'::interval);

-- Validate session on each request
SELECT * FROM authn.validate_session(sha256('random-token'));
-- → user_id, email, session_id (or empty if invalid)

-- Logout
SELECT authn.revoke_session(sha256('random-token'));
```

## Social Login / SSO

authn stores users and sessions. It doesn't care how you verified identity - password, Google,
SAML, carrier pigeon. You handle the verification, then call authn.

### Google OAuth

```python
# 1. User clicks "Login with Google", you handle OAuth
google_user = google_oauth.verify(id_token)

# 2. Find or create user
user = cursor.execute(
    "SELECT * FROM authn.get_user_by_email(%s)",
    [google_user['email']]
).fetchone()

if not user:
    user_id = cursor.execute(
        "SELECT authn.create_user(%s, NULL)",
        [google_user['email']]
    ).fetchone()[0]
else:
    user_id = user['id']

# 3. Create session
token = secrets.token_urlsafe(32)
cursor.execute(
    "SELECT authn.create_session(%s, %s)",
    [user_id, hashlib.sha256(token.encode()).hexdigest()]
)
return {"session_token": token}
```

### SAML

Same pattern - validate the assertion, then find/create user:

```python
saml_response = saml_lib.parse_response(request)
email = saml_response.get_attribute('email')

# Same as above: get_user_by_email → create_user if needed → create_session
```

### Enterprise SSO Config

One company might have multiple IdPs (Okta for employees, Azure AD for contractors). That config
lives in your own table - it's outside authn's scope:

```sql
CREATE TABLE sso_configs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL,
    provider text NOT NULL,        -- 'saml', 'oidc'
    name text,                      -- 'Okta - Employees'
    idp_entity_id text,
    idp_sso_url text,
    idp_certificate text,
    enabled boolean DEFAULT true
);
```

## API

```sql
-- Users
authn.create_user(email, password_hash)  -- returns user_id
authn.get_user(user_id)
authn.get_user_by_email(email)
authn.update_email(user_id, new_email)
authn.disable_user(user_id)              -- also revokes sessions
authn.enable_user(user_id)
authn.delete_user(user_id)               -- cascades to sessions, tokens, mfa
authn.list_users(namespace, limit, cursor)

-- Credentials (only place password_hash is returned)
authn.get_credentials(email)             -- for login verification
authn.update_password(user_id, new_hash)

-- Sessions
authn.create_session(user_id, token_hash, expires_in, ip, user_agent)
authn.validate_session(token_hash)       -- hot path, no audit log
authn.extend_session(token_hash, extend_by)
authn.revoke_session(token_hash)
authn.revoke_all_sessions(user_id)
authn.list_sessions(user_id)

-- One-time tokens
authn.create_token(user_id, token_hash, 'password_reset')
authn.consume_token(token_hash, 'password_reset')  -- returns user_id, email
authn.verify_email(token_hash)           -- consumes token + sets verified_at
authn.invalidate_tokens(user_id, 'password_reset')

-- MFA (you verify the codes)
authn.add_mfa(user_id, 'totp', secret, name)
authn.get_mfa(user_id, 'totp')           -- returns secrets for verification
authn.list_mfa(user_id)                  -- for display (no secrets)
authn.remove_mfa(mfa_id)
authn.record_mfa_use(mfa_id)
authn.has_mfa(user_id)

-- Lockout
authn.record_login_attempt(email, success, ip)
authn.is_locked_out(email)               -- constant-time, no email leak
authn.get_recent_attempts(email)
authn.clear_attempts(email)
```

## Password Reset Flow

```sql
-- 1. User requests reset (generate token in your app)
SELECT authn.create_token(user_id, sha256('reset-token'), 'password_reset');

-- 2. User clicks link, you verify token
SELECT * FROM authn.consume_token(sha256('reset-token'), 'password_reset');
-- → user_id, email (or empty if expired/used)

-- 3. User submits new password (you hash it)
SELECT authn.update_password(user_id, '$argon2id$...');

-- 4. Invalidate any other reset tokens
SELECT authn.invalidate_tokens(user_id, 'password_reset');
```

## MFA Flow

```sql
-- Setup: generate secret in your app, store it
SELECT authn.add_mfa(user_id, 'totp', 'JBSWY3DPEHPK3PXP', 'Authenticator App');

-- Login: get secret, verify code in your app
SELECT * FROM authn.get_mfa(user_id, 'totp');
-- Verify TOTP code against secret...
SELECT authn.record_mfa_use(mfa_id);  -- update last_used_at
```

## Brute-Force Protection

```sql
-- Record every login attempt
SELECT authn.record_login_attempt('alice@example.com', false, '192.168.1.1');

-- Check before allowing login (constant-time, doesn't leak email existence)
SELECT authn.is_locked_out('alice@example.com');  -- true after 5 failures in 15 min

-- Admin: view attempts or clear lockout
SELECT * FROM authn.get_recent_attempts('alice@example.com');
SELECT authn.clear_attempts('alice@example.com');
```

## Multi-Tenancy

```sql
-- All functions accept namespace parameter (default: 'default')
SELECT authn.create_user('alice@example.com', '$argon2id$...', 'tenant-acme');
SELECT authn.create_session(user_id, token_hash, NULL, NULL, NULL, 'tenant-acme');

-- Same email can exist in different tenants
SELECT authn.create_user('alice@example.com', '$argon2id$...', 'tenant-other');

-- RLS enforcement
SELECT authn.set_tenant('tenant-acme');
```

## Audit Logging

```sql
-- Set actor context before operations
SELECT authn.set_actor('admin@acme.com', 'req-123', '192.168.1.1', 'Mozilla/5.0');

-- Query audit events
SELECT * FROM authn.audit_events ORDER BY event_time DESC LIMIT 100;

-- Partition management (run via cron)
SELECT authn.ensure_audit_partitions(3);   -- create 3 months ahead
SELECT authn.drop_audit_partitions(84);    -- drop older than 7 years
```

## Password Hashing (Caller's Responsibility)

```python
# Python example with argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher()

# On registration/password change
hash = ph.hash(password)
cursor.execute("SELECT authn.create_user(%s, %s)", [email, hash])

# On login
creds = cursor.execute("SELECT * FROM authn.get_credentials(%s)", [email]).fetchone()
if creds and ph.verify(creds['password_hash'], password):
    # Create session...
```

## Token Generation (Caller's Responsibility)

```python
import secrets
import hashlib

# Generate token
token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(token.encode()).hexdigest()

# Store hash, send token to user
cursor.execute("SELECT authn.create_token(%s, %s, 'password_reset')", [user_id, token_hash])
send_email(email, f"Reset link: /reset?token={token}")

# On reset, hash the token from URL and consume
token_hash = hashlib.sha256(request.args['token'].encode()).hexdigest()
result = cursor.execute("SELECT * FROM authn.consume_token(%s, 'password_reset')", [token_hash]).fetchone()
```

## Maintenance

```sql
-- Cleanup expired sessions/tokens (run via cron)
SELECT * FROM authn.cleanup_expired();
-- → expired_sessions, expired_tokens, expired_attempts

-- Stats for monitoring
SELECT * FROM authn.get_stats();
-- → user_count, active_session_count, token_count, mfa_count
```

## Directory Structure

```
authn/
├── install.sql           # Install script for psql
├── docs/                  # Additional documentation
├── src/
│   ├── schema/           # Tables, indexes, types
│   ├── functions/        # SQL functions
│   └── triggers/         # Database triggers
└── tests/                # Python test suite
```

## Development

```bash
# From repository root
make build   # Build dist/authn.sql
make test    # Run tests
```
