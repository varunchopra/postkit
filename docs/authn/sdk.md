<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Authn Python SDK

### add_credential

```python
add_credential(user_id: str, credential_type: str, *, lookup_key: str | None = None, secret_data: str | None = None, name: str | None = None, metadata: dict | None = None, created_by: str | None = None) -> str
```

Add a credential for a user.

**Parameters:**
- `user_id`: User ID
- `credential_type`: 'totp', 'recovery_code', or 'webauthn'
- `lookup_key`: Lookup key (WebAuthn credential_id, recovery code hash)
- `secret_data`: Secret data (TOTP seed, WebAuthn public key)
- `name`: Optional friendly name like "Work Yubikey"
- `metadata`: Optional JSON metadata
- `created_by`: UUID of user who added this credential (for audit)

**Returns:** Credential ID (UUID string)

*Source: sdk/src/postkit/authn/client.py:929*

---

### cleanup_expired

```python
cleanup_expired(batch_size: int = 10000) -> dict
```

Clean up expired sessions, tokens, impersonation records, and old login attempts.

**Parameters:**
- `batch_size`: Max rows to delete per table per iteration (default 10000). Smaller values reduce lock contention but require more iterations.

**Returns:** Dict with counts: sessions_deleted, tokens_deleted, refresh_tokens_deleted,
api_keys_deleted, impersonations_deleted, operator_impersonations_deleted,
attempts_deleted

*Source: sdk/src/postkit/authn/client.py:1185*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/authn/client.py:1248*

---

### clear_attempts

```python
clear_attempts(email: str) -> int
```

Clear login attempts for an email. Returns count deleted.

*Source: sdk/src/postkit/authn/client.py:1177*

---

### consume_credential

```python
consume_credential(credential_id: str) -> bool
```

Consume a one-time credential (e.g., recovery code).

**Parameters:**
- `credential_id`: Credential to consume

**Returns:** True if consumed, False if already consumed/disabled

*Source: sdk/src/postkit/authn/client.py:1021*

---

### consume_token

```python
consume_token(token_hash: str, token_type: str) -> dict | None
```

Consume a one-time token.

*Source: sdk/src/postkit/authn/client.py:892*

---

### create_api_key

```python
create_api_key(user_id: str, key_hash: str, name: str | None = None, expires_in: timedelta | None = None) -> str
```

Create an API key for programmatic access.

**Parameters:**
- `user_id`: User ID (owner of the key)
- `key_hash`: Pre-hashed API key (SHA-256)
- `name`: Optional friendly name ("Production", "CI/CD")
- `expires_in`: Optional expiration duration (None = never expires)

**Returns:** API key ID (UUID string)

*Source: sdk/src/postkit/authn/client.py:785*

---

### create_refresh_token

```python
create_refresh_token(session_id: str, token_hash: str, expires_in: timedelta | None = None) -> dict
```

Create a refresh token for a session.

**Parameters:**
- `session_id`: Session ID to associate with
- `token_hash`: Pre-hashed refresh token (SHA-256)
- `expires_in`: Token lifetime (default: 30 days)

**Returns:** Dict with refresh_token_id, family_id, expires_at

*Source: sdk/src/postkit/authn/client.py:674*

---

### create_session

```python
create_session(user_id: str, token_hash: str, expires_in: timedelta | None = None, ip_address: str | None = None, user_agent: str | None = None) -> str
```

Create a new session.

**Parameters:**
- `user_id`: User ID
- `token_hash`: Pre-hashed session token (SHA-256)
- `expires_in`: Session duration (default: 7 days)
- `ip_address`: Client IP
- `user_agent`: Client user agent

**Returns:** Session ID (UUID string)

*Source: sdk/src/postkit/authn/client.py:240*

---

### create_token

```python
create_token(user_id: str, token_hash: str, token_type: str, expires_in: timedelta | None = None) -> str
```

Create a one-time use token.

**Parameters:**
- `user_id`: User ID
- `token_hash`: Pre-hashed token (SHA-256)
- `token_type`: 'password_reset', 'email_verify', or 'magic_link'
- `expires_in`: Token lifetime (defaults vary by type)

**Returns:** Token ID (UUID string)

*Source: sdk/src/postkit/authn/client.py:866*

---

### create_user

```python
create_user(email: str, password_hash: str | None = None) -> str
```

Create a new user.

**Parameters:**
- `email`: User's email address (will be normalized to lowercase)
- `password_hash`: Pre-hashed password (None for SSO-only users)

**Returns:** User ID (UUID string)

*Source: sdk/src/postkit/authn/client.py:91*

---

### delete_user

```python
delete_user(user_id: str) -> bool
```

Permanently delete a user and all associated data.

*Source: sdk/src/postkit/authn/client.py:151*

---

### disable_all_credentials

```python
disable_all_credentials(user_id: str, reason: str) -> int
```

Disable all credentials for a user (incident response).

**Parameters:**
- `user_id`: User whose credentials to disable
- `reason`: Required reason for audit trail

**Returns:** Count of credentials disabled

*Source: sdk/src/postkit/authn/client.py:1090*

---

### disable_credential

```python
disable_credential(credential_id: str, reason: str) -> bool
```

Soft-disable a credential (preserves for forensics).

**Parameters:**
- `credential_id`: Credential to disable
- `reason`: Required reason for audit trail

**Returns:** True if disabled, False if not found/already disabled

*Source: sdk/src/postkit/authn/client.py:1057*

---

### disable_user

```python
disable_user(user_id: str) -> bool
```

Disable user and revoke all their sessions.

*Source: sdk/src/postkit/authn/client.py:135*

---

### enable_user

```python
enable_user(user_id: str) -> bool
```

Re-enable a disabled user.

*Source: sdk/src/postkit/authn/client.py:143*

---

### end_impersonation

```python
end_impersonation(impersonation_id: str) -> bool
```

End an impersonation session early.

**Parameters:**
- `impersonation_id`: The impersonation to end

**Returns:** True if ended, False if not found or already ended

*Source: sdk/src/postkit/authn/client.py:414*

---

### end_operator_impersonation

```python
end_operator_impersonation(impersonation_id: str) -> bool
```

End an operator impersonation session early.

**Parameters:**
- `impersonation_id`: The impersonation to end

**Returns:** True if ended, False if not found or already ended

*Source: sdk/src/postkit/authn/client.py:545*

---

### extend_session

```python
extend_session(token_hash: str, extend_by: timedelta | None = None) -> datetime | None
```

Extend session expiration.

**Returns:** New expires_at timestamp, or None if session invalid/expired/revoked.

*Source: sdk/src/postkit/authn/client.py:289*

---

### get_api_key

```python
get_api_key(key_id: str, user_id: str) -> dict | None
```

Get an API key by ID if owned by user.

**Parameters:**
- `key_id`: The API key ID to look up
- `user_id`: The user who should own the key

**Returns:** Key metadata dict if found and owned by user, None otherwise

*Source: sdk/src/postkit/authn/client.py:849*

---

### get_audit_events

```python
get_audit_events(limit: int = 100, event_type: str | None = None, actor_id: str | None = None, resource_type: str | None = None, resource_id: str | None = None, before: str | None = None) -> list[dict]
```

Query audit events with optional filters.

**Parameters:**
- `limit`: Maximum number of events to return (default 100)
- `event_type`: Filter by event type (e.g., 'user_created', 'session_revoked')
- `actor_id`: Filter by actor ID (who made the change)
- `resource_type`: Filter by resource type (e.g., 'user', 'session')
- `resource_id`: Filter by resource ID
- `before`: Opaque cursor from a previous response's event['cursor']

**Returns:** List of audit event dictionaries. Each event includes a 'cursor' field
that can be passed to 'before' for pagination.

**Example:**
```python
events = authn.get_audit_events(limit=50)
if events:
    more = authn.get_audit_events(limit=50, before=events[-1]["cursor"])
```

*Source: sdk/src/postkit/authn/client.py:1254*

---

### get_credential_by_lookup

```python
get_credential_by_lookup(user_id: str, lookup_key: str, credential_type: str) -> dict | None
```

Lookup a credential by key. Requires user_id for enumeration safety.

**Parameters:**
- `user_id`: User ID (prevents cross-user enumeration)
- `lookup_key`: The lookup key (e.g., recovery code hash)
- `credential_type`: 'totp', 'recovery_code', or 'webauthn'

**Returns:** Credential with id, secret_data, sign_count, consumed_at - or None

*Source: sdk/src/postkit/authn/client.py:989*

---

### get_credentials

```python
get_credentials(email: str) -> dict | None
```

Get credentials for login verification.

*Source: sdk/src/postkit/authn/client.py:220*

---

### get_impersonation_context

```python
get_impersonation_context(session_id: str) -> dict
```

Check if a session is an impersonation session.

**Parameters:**
- `session_id`: Session ID to check

**Returns:** Dict with is_impersonating (bool), and if True:
impersonation_id, actor_id, actor_email, target_user_id,
reason, started_at, expires_at

*Source: sdk/src/postkit/authn/client.py:432*

---

### get_operator_audit_events

```python
get_operator_audit_events(limit: int = 100, event_type: str | None = None, operator_namespace: str | None = None, target_namespace: str | None = None) -> list[dict]
```

Query operator audit events.

**Parameters:**
- `limit`: Maximum records to return
- `event_type`: Optional filter by event type
- `operator_namespace`: Optional filter by operator namespace
- `target_namespace`: Optional filter by target namespace

**Returns:** List of operator audit event records

*Source: sdk/src/postkit/authn/client.py:646*

---

### get_operator_impersonation_context

```python
get_operator_impersonation_context(session_id: str) -> dict
```

Check if a session is an operator impersonation session.

**Parameters:**
- `session_id`: Session ID to check

**Returns:** Dict with is_operator_impersonating (bool), and if True:
impersonation_id, operator_id, operator_email, operator_namespace,
target_user_id, target_user_email, target_namespace, reason,
ticket_reference, started_at, expires_at

*Source: sdk/src/postkit/authn/client.py:563*

---

### get_or_create_user

```python
get_or_create_user(email: str, password_hash: str | None = None) -> tuple[str, bool]
```

Atomically get existing user or create new one.

**Parameters:**
- `email`: User's email address (normalized to lowercase)
- `password_hash`: Pre-hashed password (None for SSO-only users)

**Returns:** Tuple of (user_id, was_created)

*Source: sdk/src/postkit/authn/client.py:184*

---

### get_recent_attempts

```python
get_recent_attempts(email: str, limit: int = 10) -> list[dict]
```

Get recent login attempts for an email.

*Source: sdk/src/postkit/authn/client.py:1170*

---

### get_stats

```python
get_stats() -> dict
```

Get namespace statistics.

*Source: sdk/src/postkit/authn/client.py:1206*

---

### get_user

```python
get_user(user_id: str) -> dict | None
```

Get user by ID. Does not return password_hash.

*Source: sdk/src/postkit/authn/client.py:113*

---

### get_user_by_email

```python
get_user_by_email(email: str) -> dict | None
```

Get user by email. Does not return password_hash.

*Source: sdk/src/postkit/authn/client.py:120*

---

### get_user_credentials

```python
get_user_credentials(user_id: str, credential_type: str) -> list[dict]
```

Get active credentials for verification. Returns secrets!

**Parameters:**
- `user_id`: User ID
- `credential_type`: 'totp', 'recovery_code', or 'webauthn'

**Returns:** List of credentials with id, lookup_key, secret_data, sign_count

*Source: sdk/src/postkit/authn/client.py:973*

---

### get_users_batch

```python
get_users_batch(user_ids: list[str]) -> dict[str, dict]
```

Get multiple users by ID in a single query.

**Parameters:**
- `user_ids`: List of user IDs (UUIDs as strings)

**Returns:** Dict mapping user_id -> user dict. Missing IDs are omitted.

*Source: sdk/src/postkit/authn/client.py:166*

---

### has_credential

```python
has_credential(user_id: str, credential_type: str) -> bool
```

Check if user has active credential of a specific type.

**Parameters:**
- `user_id`: User ID
- `credential_type`: 'totp', 'recovery_code', or 'webauthn'

**Returns:** True if user has at least one active credential of type

*Source: sdk/src/postkit/authn/client.py:1129*

---

### invalidate_tokens

```python
invalidate_tokens(user_id: str, token_type: str) -> int
```

Invalidate all unused tokens of a type for a user.

*Source: sdk/src/postkit/authn/client.py:917*

---

### is_locked_out

```python
is_locked_out(email: str, window: timedelta | None = None, max_attempts: int | None = None) -> bool
```

Check if an email is locked out due to too many failed attempts.

*Source: sdk/src/postkit/authn/client.py:1158*

---

### list_active_impersonations

```python
list_active_impersonations() -> list[dict]
```

List all active impersonations in the namespace.

**Returns:** List of active impersonation records with actor/target info

*Source: sdk/src/postkit/authn/client.py:453*

---

### list_active_operator_impersonations

```python
list_active_operator_impersonations(limit: int = 100) -> list[dict]
```

List all active operator impersonations.

**Parameters:**
- `limit`: Maximum records to return

**Returns:** List of active impersonation records

*Source: sdk/src/postkit/authn/client.py:628*

---

### list_api_keys

```python
list_api_keys(user_id: str) -> list[dict]
```

List active API keys for a user. Does not return key_hash.

*Source: sdk/src/postkit/authn/client.py:842*

---

### list_impersonation_history

```python
list_impersonation_history(limit: int = 100, actor_id: str | None = None, target_user_id: str | None = None) -> list[dict]
```

List impersonation history for audit purposes.

**Parameters:**
- `limit`: Maximum records to return
- `actor_id`: Optional filter by actor (admin who impersonated)
- `target_user_id`: Optional filter by target (user who was impersonated)

**Returns:** List of impersonation records (including ended ones)

*Source: sdk/src/postkit/authn/client.py:467*

---

### list_operator_impersonations_by_operator

```python
list_operator_impersonations_by_operator(operator_id: str, operator_namespace: str, limit: int = 100) -> list[dict]
```

List impersonations performed by an operator.

**Parameters:**
- `operator_id`: Operator user ID to query
- `operator_namespace`: Operator's namespace
- `limit`: Maximum records to return

**Returns:** List of impersonation records by the operator

*Source: sdk/src/postkit/authn/client.py:606*

---

### list_operator_impersonations_for_target

```python
list_operator_impersonations_for_target(target_namespace: str, limit: int = 100, target_user_id: str | None = None) -> list[dict]
```

List operator impersonation history affecting a target namespace.

**Parameters:**
- `target_namespace`: Namespace to query
- `limit`: Maximum records to return
- `target_user_id`: Optional filter by specific target user

**Returns:** List of impersonation records (including ended ones)

*Source: sdk/src/postkit/authn/client.py:582*

---

### list_refresh_tokens

```python
list_refresh_tokens(user_id: str) -> list[dict]
```

List active refresh tokens for a user.

*Source: sdk/src/postkit/authn/client.py:774*

---

### list_sessions

```python
list_sessions(user_id: str) -> list[dict]
```

List active sessions for a user. Does not return token_hash.

*Source: sdk/src/postkit/authn/client.py:357*

---

### list_user_credentials

```python
list_user_credentials(user_id: str, credential_type: str | None = None, include_disabled: bool = False) -> list[dict]
```

List credentials for settings UI. Does NOT return secrets.

**Parameters:**
- `user_id`: User ID
- `credential_type`: Optional filter by type
- `include_disabled`: Include disabled credentials (for admin/forensics)

**Returns:** List of credential metadata (no secrets)

*Source: sdk/src/postkit/authn/client.py:1107*

---

### list_users

```python
list_users(limit: int = 100, cursor: str | None = None) -> list[dict]
```

List users with pagination.

*Source: sdk/src/postkit/authn/client.py:159*

---

### record_credential_use

```python
record_credential_use(credential_id: str) -> None
```

Record credential usage (lazy update: only if >1hr since last).

**Parameters:**
- `credential_id`: Credential that was used

*Source: sdk/src/postkit/authn/client.py:1008*

---

### record_login_attempt

```python
record_login_attempt(email: str, success: bool, ip_address: str | None = None) -> None
```

Record a login attempt.

*Source: sdk/src/postkit/authn/client.py:1145*

---

### remove_credential

```python
remove_credential(credential_id: str) -> bool
```

Hard-delete a credential (user self-service).

**Parameters:**
- `credential_id`: Credential to remove

**Returns:** True if removed, False if not found

*Source: sdk/src/postkit/authn/client.py:1074*

---

### revoke_all_api_keys

```python
revoke_all_api_keys(user_id: str) -> int
```

Revoke all API keys for a user. Returns count revoked.

*Source: sdk/src/postkit/authn/client.py:834*

---

### revoke_all_refresh_tokens

```python
revoke_all_refresh_tokens(user_id: str) -> int
```

Revoke all refresh tokens for a user.

**Returns:** Count of tokens revoked

*Source: sdk/src/postkit/authn/client.py:761*

---

### revoke_all_sessions

```python
revoke_all_sessions(user_id: str) -> int
```

Revoke all sessions for a user. Returns count revoked.

*Source: sdk/src/postkit/authn/client.py:329*

---

### revoke_api_key

```python
revoke_api_key(key_id: str) -> bool
```

Revoke an API key.

*Source: sdk/src/postkit/authn/client.py:826*

---

### revoke_other_sessions

```python
revoke_other_sessions(user_id: str, except_session_id: str) -> int
```

Revoke all sessions except the specified one ("sign out other devices").

**Parameters:**
- `user_id`: User whose sessions to revoke
- `except_session_id`: Session ID to preserve (the current session)

**Returns:** Count of sessions revoked (excludes the preserved session)

*Source: sdk/src/postkit/authn/client.py:337*

---

### revoke_refresh_token_family

```python
revoke_refresh_token_family(family_id: str) -> int
```

Revoke all tokens in a family (security response).

**Returns:** Count of tokens revoked

*Source: sdk/src/postkit/authn/client.py:748*

---

### revoke_session

```python
revoke_session(token_hash: str) -> bool
```

Revoke a session.

*Source: sdk/src/postkit/authn/client.py:305*

---

### revoke_session_by_id

```python
revoke_session_by_id(session_id: str, user_id: str) -> bool
```

Revoke a session by ID (for manage devices UI).

**Parameters:**
- `session_id`: Session ID to revoke
- `user_id`: User ID (for ownership verification)

**Returns:** True if revoked, False if not found or not owned by user

*Source: sdk/src/postkit/authn/client.py:313*

---

### rotate_refresh_token

```python
rotate_refresh_token(old_token_hash: str, new_token_hash: str, expires_in: timedelta | None = None) -> dict | None
```

Rotate a refresh token (invalidate old, issue new).

**Parameters:**
- `old_token_hash`: Hash of token being rotated
- `new_token_hash`: Hash of new token to issue
- `expires_in`: New token lifetime (default: 30 days)

**Returns:** Dict with user_id, session_id, new_refresh_token_id, family_id,
generation, expires_at - or None if rotation failed

*Source: sdk/src/postkit/authn/client.py:702*

---

### set_actor

```python
set_actor(actor_id: str | None = None, request_id: str | None = None, on_behalf_of: str | None = None, reason: str | None = None, *, ip_address: str | None = None, user_agent: str | None = None) -> None
```

Set actor context for audit logging. Only updates fields that are passed.

**Parameters:**
- `actor_id`: The actor making changes (e.g., 'user:alice')
- `request_id`: Request/correlation ID for tracing
- `on_behalf_of`: Principal being represented
- `reason`: Reason for the action
- `ip_address`: Client IP address
- `user_agent`: Client user agent string

**Example:**
```python
# In before_request: set HTTP context
authn.clear_actor()
authn.set_actor(request_id=req_id, ip_address=ip, user_agent=ua)

# After authentication: add actor_id (preserves HTTP context)
authn.set_actor(actor_id="user:alice")
```

*Source: sdk/src/postkit/authn/client.py:1214*

---

### start_impersonation

```python
start_impersonation(actor_session_id: str, target_user_id: str, reason: str, token_hash: str, duration: timedelta | None = None) -> dict
```

Start impersonating a user.

**Parameters:**
- `actor_session_id`: Session ID of the admin starting impersonation (cannot be an impersonation session - chaining is prevented)
- `target_user_id`: User ID to impersonate
- `reason`: Required justification (cannot be empty)
- `token_hash`: SHA-256 hash of the impersonation session token
- `duration`: How long the impersonation lasts (default 1 hour, max 8 hours)

**Returns:** Dict with impersonation_id, impersonation_session_id, expires_at

*Source: sdk/src/postkit/authn/client.py:368*

---

### start_operator_impersonation

```python
start_operator_impersonation(operator_session_id: str, target_user_id: str, target_namespace: str, token_hash: str, reason: str, duration: timedelta | None = None, ticket_reference: str | None = None) -> dict
```

Start cross-namespace operator impersonation.

**Parameters:**
- `operator_session_id`: Session ID of the operator starting impersonation (cannot be an impersonation session - chaining is prevented)
- `target_user_id`: User ID to impersonate
- `target_namespace`: Namespace of the target user
- `token_hash`: SHA-256 hash of the impersonation session token
- `reason`: Required justification (cannot be empty)
- `duration`: How long the impersonation lasts (default 30 min, max 4 hours)
- `ticket_reference`: Optional external ticket reference (Zendesk, Jira, etc.)

**Returns:** Dict with impersonation_id, impersonation_session_id, expires_at

*Source: sdk/src/postkit/authn/client.py:493*

---

### update_email

```python
update_email(user_id: str, new_email: str) -> bool
```

Update user's email. Clears email_verified_at.

*Source: sdk/src/postkit/authn/client.py:127*

---

### update_password

```python
update_password(user_id: str, new_password_hash: str) -> bool
```

Update user's password hash.

*Source: sdk/src/postkit/authn/client.py:232*

---

### update_sign_count

```python
update_sign_count(credential_id: str, new_count: int) -> bool
```

Update WebAuthn sign count. Returns False if clone detected.

**Parameters:**
- `credential_id`: WebAuthn credential to update
- `new_count`: New sign count from authenticator

**Returns:** True if updated, False if new_count <= current (clone attack!)

*Source: sdk/src/postkit/authn/client.py:1037*

---

### validate_api_key

```python
validate_api_key(key_hash: str) -> dict | None
```

Validate an API key.

**Returns:** Dict with user_id, key_id, name, expires_at or None if invalid

*Source: sdk/src/postkit/authn/client.py:811*

---

### validate_refresh_token

```python
validate_refresh_token(token_hash: str) -> dict | None
```

Validate a refresh token without rotating (read-only check).

**Returns:** Dict with user_id, session_id, family_id, generation,
expires_at, is_current - or None if invalid

*Source: sdk/src/postkit/authn/client.py:733*

---

### validate_session

```python
validate_session(token_hash: str) -> dict | None
```

Validate a session token.

**Returns:** Dict with user_id, email, session_id, is_impersonating,
impersonator_id, impersonator_email, impersonation_reason
- or None if session invalid/expired/revoked.

*Source: sdk/src/postkit/authn/client.py:268*

---

### verify_email

```python
verify_email(token_hash: str) -> dict | None
```

Verify email using a token.

*Source: sdk/src/postkit/authn/client.py:905*

---
