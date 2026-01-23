<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Authn SQL API

## API Keys

### authn.create_api_key

```sql
authn.create_api_key(p_user_id: uuid, p_key_hash: text, p_name: text, p_expires_in: interval, p_namespace: text) -> uuid
```

Create an API key for programmatic access

**Parameters:**
- `p_user_id`: Owner of the key
- `p_key_hash`: SHA-256 hash of the actual key (caller generates, hashes, stores hash)
- `p_name`: Optional friendly name ("Production", "CI/CD")
- `p_expires_in`: Optional expiration interval (NULL = never expires)

**Returns:** API key ID

**Example:**
```sql
SELECT authn.create_api_key(user_id, 'a1b2c3...key_hash', 'Production', '1 year');
```

*Source: authn/src/functions/025_api_keys.sql:1*

---

### authn.get_api_key

```sql
authn.get_api_key(p_key_id: uuid, p_user_id: uuid, p_namespace: text) -> table(key_id: uuid, name: text, created_at: timestamptz, expires_at: timestamptz, last_used_at: timestamptz)
```

Get a single API key by ID if owned by user (for ownership verification)

**Parameters:**
- `p_key_id`: The key ID to look up
- `p_user_id`: The user who should own the key

**Returns:** Key metadata if found and owned by user; empty if not found/not owned/revoked/expired

**Example:**
```sql
SELECT * FROM authn.get_api_key('key-uuid', 'user-uuid');
```

*Source: authn/src/functions/025_api_keys.sql:219*

---

### authn.list_api_keys

```sql
authn.list_api_keys(p_user_id: uuid, p_namespace: text) -> table(key_id: uuid, name: text, created_at: timestamptz, expires_at: timestamptz, last_used_at: timestamptz)
```

List API keys for a user (for management UI)

**Parameters:**
- `p_user_id`: The user whose keys to list

**Returns:** Active keys with metadata (no key_hash exposed)

**Example:**
```sql
SELECT * FROM authn.list_api_keys(user_id);
```

*Source: authn/src/functions/025_api_keys.sql:182*

---

### authn.revoke_all_api_keys

```sql
authn.revoke_all_api_keys(p_user_id: uuid, p_namespace: text) -> int4
```

Revoke all API keys for a user

**Parameters:**
- `p_user_id`: The user whose keys to revoke

**Returns:** Count of keys revoked

**Example:**
```sql
SELECT authn.revoke_all_api_keys(user_id); -- Security concern, revoke all
```

*Source: authn/src/functions/025_api_keys.sql:146*

---

### authn.revoke_api_key

```sql
authn.revoke_api_key(p_key_id: uuid, p_namespace: text) -> bool
```

Revoke an API key

**Parameters:**
- `p_key_id`: The key ID to revoke

**Returns:** True if key was revoked, false if not found or already revoked

**Example:**
```sql
SELECT authn.revoke_api_key('key-uuid-here');
```

*Source: authn/src/functions/025_api_keys.sql:107*

---

### authn.validate_api_key

```sql
authn.validate_api_key(p_key_hash: text, p_namespace: text) -> table(user_id: uuid, key_id: uuid, name: text, expires_at: timestamptz)
```

Validate an API key and get owner info (hot path)

**Parameters:**
- `p_key_hash`: SHA-256 hash of the key being validated

**Returns:** user_id, key_id, name, expires_at if valid; empty if invalid/expired/revoked

**Example:**
```sql
SELECT * FROM authn.validate_api_key('a1b2c3...key_hash');
```

*Source: authn/src/functions/025_api_keys.sql:48*

---

## Audit

### authn.clear_actor

```sql
authn.clear_actor() -> void
```

Clear actor context

**Example:**
```sql
SELECT authn.clear_actor();
```

*Source: authn/src/functions/070_audit.sql:41*

---

### authn.create_audit_partition

```sql
authn.create_audit_partition(p_year: int4, p_month: int4) -> text
```

Create a monthly partition for audit events

**Returns:** Partition name if created, NULL if already exists

**Example:**
```sql
SELECT authn.create_audit_partition(2024, 1); -- January 2024
```

*Source: authn/src/functions/070_audit.sql:57*

---

### authn.drop_audit_partitions

```sql
authn.drop_audit_partitions(p_older_than_months: int4) -> setof text
```

Delete old audit partitions (default: keep 7 years for compliance)

**Parameters:**
- `p_older_than_months`: Delete partitions older than this (default 84 = 7 years)

**Returns:** Names of dropped partitions

**Example:**
```sql
SELECT * FROM authn.drop_audit_partitions(84);
```

*Source: authn/src/functions/070_audit.sql:148*

---

### authn.ensure_audit_partitions

```sql
authn.ensure_audit_partitions(p_months_ahead: int4) -> setof text
```

Create partitions for upcoming months (run monthly via cron)

**Parameters:**
- `p_months_ahead`: How many months ahead to create (default 3)

**Returns:** Names of newly created partitions

**Example:**
```sql
SELECT * FROM authn.ensure_audit_partitions(3);
```

*Source: authn/src/functions/070_audit.sql:115*

---

### authn.set_actor

```sql
authn.set_actor(p_actor_id: text, p_request_id: text, p_ip_address: text, p_user_agent: text, p_on_behalf_of: text, p_reason: text) -> void
```

Tag audit events with who made the change (call before user operations)

**Parameters:**
- `p_actor_id`: The admin or API making changes (for audit trail)
- `p_request_id`: Optional request/ticket ID for traceability
- `p_ip_address`: Optional IP address of the client
- `p_user_agent`: Optional user agent string
- `p_on_behalf_of`: Optional principal being represented (e.g., admin acting as customer)
- `p_reason`: Optional reason/context for the action

**Example:**
```sql
SELECT authn.set_actor('user:admin-bob', on_behalf_of := 'user:customer-alice', reason := 'support_ticket:12345');
```

*Source: authn/src/functions/070_audit.sql:1*

---

## Credentials

### authn.add_credential

```sql
authn.add_credential(p_user_id: uuid, p_type: text, p_lookup_key: text, p_secret_data: text, p_name: text, p_metadata: jsonb, p_created_by: uuid, p_namespace: text) -> uuid
```

Add a credential (TOTP, WebAuthn, or recovery code)

**Parameters:**
- `p_user_id`: User to add credential for
- `p_type`: One of: 'totp', 'recovery_code', 'webauthn'
- `p_lookup_key`: Lookup key (WebAuthn credential_id, recovery code hash)
- `p_secret_data`: Secret data (TOTP seed, WebAuthn public key)
- `p_name`: User-friendly name like "Work Yubikey"
- `p_metadata`: Optional JSON metadata
- `p_created_by`: UUID of user who added this credential (for audit)

**Returns:** Credential ID

**Example:**
```sql
SELECT authn.add_credential(user_id, 'totp', NULL, 'JBSWY3DPEHPK3PXP', 'Authenticator');
```

*Source: authn/src/functions/040_credentials.sql:1*

---

### authn.consume_credential

```sql
authn.consume_credential(p_credential_id: uuid, p_namespace: text) -> bool
```

Consume a one-time credential (e.g., recovery code)

**Parameters:**
- `p_credential_id`: Credential to consume

**Returns:** true if consumed, false if already consumed/disabled

**Example:**
```sql
SELECT authn.consume_credential(recovery_code_id);
```

*Source: authn/src/functions/040_credentials.sql:188*

---

### authn.disable_all_credentials

```sql
authn.disable_all_credentials(p_user_id: uuid, p_reason: text, p_namespace: text) -> int4
```

Bulk disable all credentials for a user (incident response)

**Parameters:**
- `p_user_id`: User whose credentials to disable
- `p_reason`: Reason for bulk disable (required for audit)

**Returns:** Count of credentials disabled

**Example:**
```sql
SELECT authn.disable_all_credentials(user_id, 'User reported device stolen');
```

*Source: authn/src/functions/040_credentials.sql:476*

---

### authn.disable_credential

```sql
authn.disable_credential(p_credential_id: uuid, p_reason: text, p_namespace: text) -> bool
```

Soft-disable a credential (preserves for forensics)

**Parameters:**
- `p_credential_id`: Credential to disable
- `p_reason`: Reason for disabling (required for audit)

**Returns:** true if disabled, false if not found/already disabled

**Example:**
```sql
SELECT authn.disable_credential(credential_id, 'Reported as compromised');
```

*Source: authn/src/functions/040_credentials.sql:289*

---

### authn.get_credential_by_lookup

```sql
authn.get_credential_by_lookup(p_user_id: uuid, p_lookup_key: text, p_type: text, p_namespace: text) -> table(id: uuid, secret_data: text, sign_count: int4, consumed_at: timestamptz)
```

Lookup a credential by its lookup_key (requires user context for security)

**Parameters:**
- `p_user_id`: User to search within (prevents enumeration)
- `p_lookup_key`: The lookup key to search for
- `p_type`: Credential type to filter by

**Returns:** Single credential or empty if not found

**Example:**
```sql
SELECT * FROM authn.get_credential_by_lookup(user_id, hash, 'recovery_code');
```

*Source: authn/src/functions/040_credentials.sql:119*

---

### authn.get_credentials

```sql
authn.get_credentials(p_email: text, p_namespace: text) -> table(user_id: uuid, password_hash: text, disabled_at: timestamptz)
```

Get password hash for login verification (only function that returns hash)

**Returns:** user_id, password_hash, disabled_at. Verify hash in your app, check disabled_at, then call create_session if valid. SECURITY NOTE: This function intentionally does NOT check lockout status. The recommended login flow is: 1. Call is_locked_out(email) - reject if locked 2. Call get_credentials(email) - get hash for verification 3. Verify password hash in application code (argon2id) 4. Call record_login_attempt(email, success, ip) - track attempt 5. If success: call create_session() and return token This separation of concerns allows flexibility: - Different lockout policies per user tier or namespace - Custom rate limiting at the application layer - A/B testing authentication flows The application MUST call is_locked_out() before get_credentials() to prevent credential stuffing attacks. Password hashes should use argon2id to make offline cracking impractical even if hashes are harvested.

**Example:**
```sql
SELECT * FROM authn.get_credentials('alice@example.com');
```

*Source: authn/src/functions/011_credentials.sql:1*

---

### authn.get_credentials

```sql
authn.get_credentials(p_user_id: uuid, p_type: text, p_namespace: text) -> table(id: uuid, lookup_key: text, secret_data: text, sign_count: int4)
```

Get active credentials for verification (returns secrets)

**Parameters:**
- `p_user_id`: User to get credentials for
- `p_type`: Credential type to filter by

**Returns:** Table of credentials with secrets for verification

**Example:**
```sql
SELECT * FROM authn.get_credentials(user_id, 'totp');
```

*Source: authn/src/functions/040_credentials.sql:79*

---

### authn.has_credential

```sql
authn.has_credential(p_user_id: uuid, p_type: text, p_namespace: text) -> bool
```

Check if user has active credential of a specific type

**Parameters:**
- `p_user_id`: User to check
- `p_type`: Credential type to check for

**Returns:** true if user has at least one active credential of type

**Example:**
```sql
IF authn.has_credential(user_id, 'totp') THEN prompt_for_code(); END IF;
```

*Source: authn/src/functions/040_credentials.sql:446*

---

### authn.list_credentials

```sql
authn.list_credentials(p_user_id: uuid, p_type: text, p_include_disabled: bool, p_namespace: text) -> table(id: uuid, credential_type: text, name: text, created_at: timestamptz, last_used_at: timestamptz, consumed_at: timestamptz, disabled_at: timestamptz, disabled_reason: text)
```

List credentials for settings UI (no secrets exposed)

**Parameters:**
- `p_user_id`: User to list credentials for
- `p_type`: Optional: filter by credential type
- `p_include_disabled`: Include disabled credentials (for admin/forensics)

**Returns:** Table of credential metadata

**Example:**
```sql
SELECT * FROM authn.list_credentials(user_id);
```

*Source: authn/src/functions/040_credentials.sql:395*

---

### authn.record_credential_use

```sql
authn.record_credential_use(p_credential_id: uuid, p_namespace: text) -> void
```

Record credential usage (updates last_used_at)

**Parameters:**
- `p_credential_id`: Credential that was used

**Example:**
```sql
SELECT authn.record_credential_use(credential_id);
```

*Source: authn/src/functions/040_credentials.sql:161*

---

### authn.remove_credential

```sql
authn.remove_credential(p_credential_id: uuid, p_namespace: text) -> bool
```

Hard-delete a credential (user self-service)

**Parameters:**
- `p_credential_id`: Credential to remove

**Returns:** true if removed, false if not found

**Example:**
```sql
SELECT authn.remove_credential(credential_id);
```

*Source: authn/src/functions/040_credentials.sql:344*

---

### authn.update_password

```sql
authn.update_password(p_user_id: uuid, p_new_password_hash: text, p_namespace: text) -> bool
```

Update user's password hash (after password change or reset)

**Parameters:**
- `p_new_password_hash`: Argon2id hash of new password

**Example:**
```sql
SELECT authn.update_password(user_id, '$argon2id$...');
```

*Source: authn/src/functions/011_credentials.sql:51*

---

### authn.update_sign_count

```sql
authn.update_sign_count(p_credential_id: uuid, p_new_count: int4, p_namespace: text) -> bool
```

Update WebAuthn sign count (clone detection)

**Parameters:**
- `p_credential_id`: Credential to update
- `p_new_count`: New sign count from authenticator

**Returns:** true if updated, false if clone detected (new_count <= current)

**Example:**
```sql
SELECT authn.update_sign_count(webauthn_credential_id, 42);
```

*Source: authn/src/functions/040_credentials.sql:231*

---

## Impersonation

### authn.end_impersonation

```sql
authn.end_impersonation(p_impersonation_id: uuid, p_namespace: text) -> bool
```

End an impersonation session early (revokes the impersonation session)

**Parameters:**
- `p_impersonation_id`: The impersonation to end

**Returns:** true if ended, false if not found or already ended

**Example:**
```sql
SELECT authn.end_impersonation(impersonation_id);
```

*Source: authn/src/functions/075_impersonation.sql:161*

---

### authn.get_impersonation_context

```sql
authn.get_impersonation_context(p_session_id: uuid, p_namespace: text) -> table(is_impersonating: bool, impersonation_id: uuid, actor_id: uuid, actor_email: text, target_user_id: uuid, reason: text, started_at: timestamptz, expires_at: timestamptz)
```

Get impersonation context for a session (is this an impersonated session?)

**Parameters:**
- `p_session_id`: The session to check

**Returns:** is_impersonating, actor_id, actor_email, target_user_id, reason Returns is_impersonating=false with NULLs if not an impersonation session

**Example:**
```sql
SELECT * FROM authn.get_impersonation_context(session_id);
```

*Source: authn/src/functions/075_impersonation.sql:230*

---

### authn.list_active_impersonations

```sql
authn.list_active_impersonations(p_namespace: text) -> table(impersonation_id: uuid, actor_id: uuid, actor_email: text, target_user_id: uuid, target_email: text, reason: text, started_at: timestamptz, expires_at: timestamptz, impersonation_session_id: uuid)
```

List all active impersonations in a namespace (admin dashboard)

**Parameters:**
- `p_namespace`: Namespace to query

**Returns:** Active impersonations with actor/target info

**Example:**
```sql
SELECT * FROM authn.list_active_impersonations('production');
```

*Source: authn/src/functions/075_impersonation.sql:292*

---

### authn.list_impersonation_history

```sql
authn.list_impersonation_history(p_namespace: text, p_limit: int4, p_actor_id: uuid, p_target_user_id: uuid) -> table(impersonation_id: uuid, actor_id: uuid, actor_email: text, target_user_id: uuid, target_email: text, reason: text, started_at: timestamptz, expires_at: timestamptz, ended_at: timestamptz, is_active: bool)
```

List impersonation history for audit (includes ended impersonations)

**Parameters:**
- `p_namespace`: Namespace to query
- `p_limit`: Maximum records to return
- `p_actor_id`: Optional filter by actor
- `p_target_user_id`: Optional filter by target user

**Returns:** Impersonation history

**Example:**
```sql
SELECT * FROM authn.list_impersonation_history('production', 100);
```

*Source: authn/src/functions/075_impersonation.sql:342*

---

### authn.start_impersonation

```sql
authn.start_impersonation(p_actor_session_id: uuid, p_target_user_id: uuid, p_token_hash: text, p_reason: text, p_duration: interval, p_namespace: text) -> table(impersonation_id: uuid, impersonation_session_id: uuid, expires_at: timestamptz)
```

Start impersonating a user (creates a session acting as target user)

**Parameters:**
- `p_actor_session_id`: Session ID of the admin starting impersonation (cannot be an impersonation session)
- `p_target_user_id`: User ID to impersonate
- `p_token_hash`: SHA-256 hash of the impersonation session token (caller generates and hashes)
- `p_reason`: Required justification for impersonation (e.g., "Support ticket #123")
- `p_duration`: How long the impersonation lasts (default 1 hour, max 8 hours)

**Returns:** impersonation_id, impersonation_session_id, expires_at

**Example:**
```sql
SELECT * FROM authn.start_impersonation(admin_session, target_user, 'a1b2c3...token_hash', 'Support ticket #123');
```

*Source: authn/src/functions/075_impersonation.sql:1*

---

## Lockout

### authn.clear_attempts

```sql
authn.clear_attempts(p_email: text, p_namespace: text) -> int8
```

Clear login attempts to unlock a user (admin function)

**Returns:** Count of attempts cleared

**Example:**
```sql
SELECT authn.clear_attempts('alice@example.com'); -- Unlock user
```

*Source: authn/src/functions/050_lockout.sql:132*

---

### authn.get_recent_attempts

```sql
authn.get_recent_attempts(p_email: text, p_namespace: text, p_limit: int4) -> table(success: bool, ip_address: inet, attempted_at: timestamptz)
```

Get recent login attempts for admin UI or user security page

**Returns:** success, ip_address, attempted_at

**Example:**
```sql
SELECT * FROM authn.get_recent_attempts('alice@example.com');
```

*Source: authn/src/functions/050_lockout.sql:92*

---

### authn.is_locked_out

```sql
authn.is_locked_out(p_email: text, p_namespace: text, p_window: interval, p_max_attempts: int4) -> bool
```

Check if email is locked out due to too many failed attempts

**Parameters:**
- `p_window`: Time window to count failures (default from config)
- `p_max_attempts`: Max failures before lockout (default from config)

**Returns:** True if locked out. Check before allowing login attempt.

**Example:**
```sql
IF authn.is_locked_out(email) THEN show_lockout_error(); END IF;
```

*Source: authn/src/functions/050_lockout.sql:52*

---

### authn.record_login_attempt

```sql
authn.record_login_attempt(p_email: text, p_success: bool, p_ip_address: inet, p_namespace: text) -> void
```

Record a login attempt (success or failure) for lockout tracking

**Parameters:**
- `p_success`: True for successful login, false for failed

**Example:**
```sql
-- After password verification
SELECT authn.record_login_attempt(email, password_correct, '1.2.3.4');
```

*Source: authn/src/functions/050_lockout.sql:1*

---

## Maintenance

### authn.cleanup_expired

```sql
authn.cleanup_expired(p_namespace: text, p_batch_size: int4) -> table(sessions_deleted: int8, tokens_deleted: int8, refresh_tokens_deleted: int8, api_keys_deleted: int8, impersonations_deleted: int8, operator_impersonations_deleted: int8, attempts_deleted: int8)
```

Delete expired sessions, tokens, refresh tokens, API keys, impersonation records, and old login attempts (run via cron)

**Parameters:**
- `p_namespace`: Namespace to clean up
- `p_batch_size`: Max rows to delete per table per iteration (default 10000, prevents long locks)

**Returns:** sessions_deleted, tokens_deleted, refresh_tokens_deleted, api_keys_deleted, impersonations_deleted, operator_impersonations_deleted, attempts_deleted

**Example:**
```sql
-- Add to daily cron job
SELECT * FROM authn.cleanup_expired('default');
SELECT * FROM authn.cleanup_expired('default', 5000); -- smaller batches
```

*Source: authn/src/functions/060_maintenance.sql:1*

---

### authn.get_stats

```sql
authn.get_stats(p_namespace: text) -> table(user_count: int8, verified_user_count: int8, disabled_user_count: int8, active_session_count: int8, active_refresh_token_count: int8, active_api_key_count: int8, credential_enabled_user_count: int8)
```

Get namespace statistics for monitoring dashboards

**Returns:** user_count, verified_user_count, disabled_user_count, active_session_count, active_refresh_token_count, active_api_key_count, credential_enabled_user_count

**Example:**
```sql
SELECT * FROM authn.get_stats('default');
```

*Source: authn/src/functions/060_maintenance.sql:205*

---

## Multi-tenancy

### authn.clear_tenant

```sql
authn.clear_tenant() -> void
```

Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants.

**Example:**
```sql
SELECT authn.clear_tenant();
```

*Source: authn/src/functions/080_rls.sql:20*

---

### authn.set_tenant

```sql
authn.set_tenant(p_tenant_id: text) -> void
```

Set tenant context for RLS (transaction-local, clears on commit). Use BEGIN/COMMIT when autocommit is enabled.

**Parameters:**
- `p_tenant_id`: Tenant ID

**Example:**
```sql
BEGIN;
SELECT authn.set_tenant('acme-corp');
SELECT * FROM authn.users;
COMMIT;
```

*Source: authn/src/functions/080_rls.sql:1*

---

## Operator Impersonation

### authn.end_operator_impersonation

```sql
authn.end_operator_impersonation(p_impersonation_id: uuid) -> bool
```

End an operator impersonation session early

**Parameters:**
- `p_impersonation_id`: The impersonation to end

**Returns:** true if ended, false if not found or already ended

**Example:**
```sql
SELECT authn.end_operator_impersonation(impersonation_id);
```

*Source: authn/src/functions/085_operator_impersonation.sql:331*

---

### authn.get_operator_audit_events

```sql
authn.get_operator_audit_events(p_limit: int4, p_event_type: text, p_operator_namespace: text, p_target_namespace: text) -> table(event_id: uuid, event_type: text, occurred_at: timestamptz, operator_namespace: text, operator_id: uuid, operator_email: text, target_namespace: text, target_user_id: uuid, target_user_email: text, reason: text, ticket_reference: text, ip_address: inet, user_agent: text, details: jsonb)
```

Query operator audit events

**Parameters:**
- `p_limit`: Maximum records to return
- `p_event_type`: Optional filter by event type
- `p_operator_namespace`: Optional filter by operator namespace
- `p_target_namespace`: Optional filter by target namespace

**Returns:** Operator audit event records

**Example:**
```sql
SELECT * FROM authn.get_operator_audit_events(100, NULL, NULL, 'customer_ns');
```

*Source: authn/src/functions/085_operator_impersonation.sql:644*

---

### authn.get_operator_impersonation_context

```sql
authn.get_operator_impersonation_context(p_session_id: uuid) -> table(is_operator_impersonating: bool, impersonation_id: uuid, operator_id: uuid, operator_email: text, operator_namespace: text, target_user_id: uuid, target_user_email: text, target_namespace: text, reason: text, ticket_reference: text, started_at: timestamptz, expires_at: timestamptz)
```

Get operator impersonation context for a session

**Parameters:**
- `p_session_id`: The session to check

**Returns:** is_operator_impersonating, impersonation details if true Returns is_operator_impersonating=false with NULLs if not an operator impersonation session

**Example:**
```sql
SELECT * FROM authn.get_operator_impersonation_context(session_id);
```

*Source: authn/src/functions/085_operator_impersonation.sql:399*

---

### authn.list_active_operator_impersonations

```sql
authn.list_active_operator_impersonations(p_limit: int4) -> table(impersonation_id: uuid, operator_id: uuid, operator_email: text, operator_namespace: text, target_user_id: uuid, target_user_email: text, target_namespace: text, reason: text, ticket_reference: text, started_at: timestamptz, expires_at: timestamptz, impersonation_session_id: uuid)
```

List all active operator impersonations (platform admin view)

**Parameters:**
- `p_limit`: Maximum records to return

**Returns:** Active impersonation records

**Example:**
```sql
SELECT * FROM authn.list_active_operator_impersonations(100);
```

*Source: authn/src/functions/085_operator_impersonation.sql:589*

---

### authn.list_operator_impersonations_by_operator

```sql
authn.list_operator_impersonations_by_operator(p_operator_id: uuid, p_operator_namespace: text, p_limit: int4) -> table(impersonation_id: uuid, target_user_id: uuid, target_user_email: text, target_namespace: text, reason: text, ticket_reference: text, started_at: timestamptz, expires_at: timestamptz, ended_at: timestamptz, is_active: bool)
```

List impersonations performed by an operator

**Parameters:**
- `p_operator_id`: Operator user ID to query
- `p_operator_namespace`: Operator's namespace
- `p_limit`: Maximum records to return

**Returns:** Impersonation records by the operator

**Example:**
```sql
SELECT * FROM authn.list_operator_impersonations_by_operator(operator_id, 'platform');
```

*Source: authn/src/functions/085_operator_impersonation.sql:533*

---

### authn.list_operator_impersonations_for_target

```sql
authn.list_operator_impersonations_for_target(p_target_namespace: text, p_limit: int4, p_target_user_id: uuid) -> table(impersonation_id: uuid, operator_id: uuid, operator_email: text, operator_namespace: text, target_user_id: uuid, target_user_email: text, reason: text, ticket_reference: text, started_at: timestamptz, expires_at: timestamptz, ended_at: timestamptz, is_active: bool)
```

List operator impersonation history affecting a target namespace

**Parameters:**
- `p_target_namespace`: Namespace to query (tenant sees who accessed their users)
- `p_limit`: Maximum records to return
- `p_target_user_id`: Optional filter by specific target user

**Returns:** Impersonation records affecting the namespace

**Example:**
```sql
SELECT * FROM authn.list_operator_impersonations_for_target('customer_ns', 100);
```

*Source: authn/src/functions/085_operator_impersonation.sql:473*

---

### authn.start_operator_impersonation

```sql
authn.start_operator_impersonation(p_operator_session_id: uuid, p_target_user_id: uuid, p_target_namespace: text, p_token_hash: text, p_reason: text, p_duration: interval, p_ticket_reference: text) -> table(impersonation_id: uuid, impersonation_session_id: uuid, expires_at: timestamptz)
```

Start cross-namespace operator impersonation

**Parameters:**
- `p_operator_session_id`: Valid session ID of the operator (any namespace)
- `p_target_user_id`: User ID to impersonate
- `p_target_namespace`: Namespace of the target user
- `p_token_hash`: SHA-256 hash of the impersonation session token
- `p_reason`: Required justification for impersonation
- `p_duration`: How long the impersonation lasts (default 30 minutes, max 4 hours)
- `p_ticket_reference`: Optional external ticket reference (Zendesk, Jira, etc.)

**Returns:** impersonation_id, impersonation_session_id, expires_at IMPORTANT: This function only validates MECHANISM: - Operator has valid session (not revoked, not expired, user not disabled) - Target user exists and is not disabled The calling application MUST validate POLICY: - Whether the session owner is authorized as an operator - Any other business rules about who can impersonate whom

**Example:**
```sql
-- -- App validates operator status first, then calls:
SELECT * FROM authn.start_operator_impersonation(
operator_session_id, target_user_id, 'customer_ns', token_hash,
'Support ticket #123', '30 minutes', 'ZENDESK-456'
);
```

*Source: authn/src/functions/085_operator_impersonation.sql:144*

---

## Refresh Tokens

### authn.create_refresh_token

```sql
authn.create_refresh_token(p_session_id: uuid, p_token_hash: text, p_expires_in: interval, p_namespace: text) -> table(refresh_token_id: uuid, family_id: uuid, expires_at: timestamptz)
```

Create a refresh token for a session (call after create_session)

**Parameters:**
- `p_session_id`: Session to associate with
- `p_token_hash`: SHA-256 hash of the refresh token
- `p_expires_in`: Token lifetime (default 30 days)

**Returns:** Table with refresh_token_id, family_id, expires_at

**Example:**
```sql
SELECT * FROM authn.create_refresh_token(session_id, 'a1b2c3...token_hash');
```

*Source: authn/src/functions/025_refresh_tokens.sql:16*

---

### authn.list_refresh_tokens

```sql
authn.list_refresh_tokens(p_user_id: uuid, p_namespace: text) -> table(refresh_token_id: uuid, session_id: uuid, family_id: uuid, generation: int4, created_at: timestamptz, expires_at: timestamptz)
```

List active refresh tokens for a user (for "manage devices" UI)

**Returns:** Active tokens with family, generation, timestamps (no token hash)

**Example:**
```sql
SELECT * FROM authn.list_refresh_tokens(user_id);
```

*Source: authn/src/functions/025_refresh_tokens.sql:375*

---

### authn.revoke_all_refresh_tokens

```sql
authn.revoke_all_refresh_tokens(p_user_id: uuid, p_namespace: text) -> int4
```

Revoke all refresh tokens for a user (password change, security concern)

**Returns:** Count of tokens revoked

**Example:**
```sql
SELECT authn.revoke_all_refresh_tokens(user_id);
```

*Source: authn/src/functions/025_refresh_tokens.sql:339*

---

### authn.revoke_refresh_token_family

```sql
authn.revoke_refresh_token_family(p_family_id: uuid, p_namespace: text) -> int4
```

Revoke all tokens in a family (for security response)

**Parameters:**
- `p_family_id`: The family to revoke

**Returns:** Count of tokens revoked

**Example:**
```sql
SELECT authn.revoke_refresh_token_family(family_id);
```

*Source: authn/src/functions/025_refresh_tokens.sql:294*

---

### authn.rotate_refresh_token

```sql
authn.rotate_refresh_token(p_old_token_hash: text, p_new_token_hash: text, p_expires_in: interval, p_namespace: text) -> table(user_id: uuid, session_id: uuid, new_refresh_token_id: uuid, family_id: uuid, generation: int4, expires_at: timestamptz)
```

Rotate a refresh token: invalidate old, create new (secure by default)

**Parameters:**
- `p_old_token_hash`: Hash of the token being rotated
- `p_new_token_hash`: Hash of the new token to issue
- `p_expires_in`: New token lifetime (default 30 days)

**Returns:** user_id, session_id, new_refresh_token_id, family_id, generation, expires_at Returns empty if token invalid, expired, or already used (reuse triggers family revocation)

**Example:**
```sql
SELECT * FROM authn.rotate_refresh_token('old_token_hash', 'new_token_hash');
```

*Source: authn/src/functions/025_refresh_tokens.sql:88*

---

### authn.validate_refresh_token

```sql
authn.validate_refresh_token(p_token_hash: text, p_namespace: text) -> table(user_id: uuid, session_id: uuid, family_id: uuid, generation: int4, expires_at: timestamptz, is_current: bool)
```

Check if a refresh token is valid WITHOUT rotating (for inspection only)

**Returns:** user_id, session_id, family_id, generation, expires_at, is_current if valid

**Example:**
```sql
SELECT * FROM authn.validate_refresh_token('a1b2c3...token_hash');
```

*Source: authn/src/functions/025_refresh_tokens.sql:250*

---

## Sessions

### authn.create_session

```sql
authn.create_session(p_user_id: uuid, p_token_hash: text, p_expires_in: interval, p_ip_address: inet, p_user_agent: text, p_namespace: text) -> uuid
```

Create a session after successful login

**Parameters:**
- `p_token_hash`: SHA-256 hash of the session token (you generate the token, hash it, store hash here, send raw token to client)
- `p_expires_in`: Session duration (default 7 days)

**Returns:** Session ID

**Example:**
```sql
-- After verifying password (token_hash is pre-computed SHA-256 hex string)
SELECT authn.create_session(user_id, 'a1b2c3...', '7 days', '1.2.3.4');
```

*Source: authn/src/functions/020_sessions.sql:1*

---

### authn.extend_session

```sql
authn.extend_session(p_token_hash: text, p_extend_by: interval, p_namespace: text) -> timestamptz
```

Extend session absolute timeout (for "remember me", not idle timeout)

**Returns:** New expires_at, or NULL if session invalid

**Example:**
```sql
SELECT authn.extend_session(token_hash, '30 days'); -- "remember me"
```

*Source: authn/src/functions/020_sessions.sql:156*

---

### authn.list_sessions

```sql
authn.list_sessions(p_user_id: uuid, p_namespace: text) -> table(session_id: uuid, created_at: timestamptz, expires_at: timestamptz, ip_address: inet, user_agent: text)
```

List active sessions for "manage devices" UI

**Returns:** Active sessions with IP, user agent, timestamps (no token hash)

**Example:**
```sql
SELECT * FROM authn.list_sessions(user_id);
```

*Source: authn/src/functions/020_sessions.sql:318*

---

### authn.revoke_all_sessions

```sql
authn.revoke_all_sessions(p_user_id: uuid, p_namespace: text) -> int4
```

Log out all sessions for a user (password change, security concern)

**Returns:** Count of sessions revoked

**Example:**
```sql
SELECT authn.revoke_all_sessions(user_id); -- "Log out everywhere"
```

*Source: authn/src/functions/020_sessions.sql:241*

---

### authn.revoke_other_sessions

```sql
authn.revoke_other_sessions(p_user_id: uuid, p_except_session_id: uuid, p_namespace: text) -> int4
```

Log out all sessions except the current one ("sign out other devices")

**Parameters:**
- `p_user_id`: User whose sessions to revoke
- `p_except_session_id`: Session ID to preserve (current session)

**Returns:** Count of sessions revoked (excludes the preserved session)

**Example:**
```sql
SELECT authn.revoke_other_sessions(user_id, current_session_id);
```

*Source: authn/src/functions/020_sessions.sql:276*

---

### authn.revoke_session

```sql
authn.revoke_session(p_token_hash: text, p_namespace: text) -> bool
```

Log out a specific session

**Example:**
```sql
SELECT authn.revoke_session(token_hash); -- User clicks "log out"
```

*Source: authn/src/functions/020_sessions.sql:203*

---

### authn.revoke_session_by_id

```sql
authn.revoke_session_by_id(p_session_id: uuid, p_user_id: uuid, p_namespace: text) -> bool
```

Revoke a specific session by ID (for "manage devices" UI)

**Parameters:**
- `p_session_id`: Session ID to revoke
- `p_user_id`: User ID (for ownership verification)

**Returns:** true if revoked, false if not found or not owned by user

**Example:**
```sql
SELECT authn.revoke_session_by_id(session_id, user_id);
```

*Source: authn/src/functions/020_sessions.sql:354*

---

### authn.validate_session

```sql
authn.validate_session(p_token_hash: text, p_namespace: text) -> table(user_id: uuid, email: text, session_id: uuid, is_impersonating: bool, impersonator_id: uuid, impersonator_email: text, impersonation_reason: text)
```

Check if session is valid and get user info (hot path, no logging)

**Returns:** user_id, email, session_id if valid. Empty if expired/revoked/disabled. Also returns impersonation context if this is an impersonation session. When impersonation is detected, automatically sets audit actor context. DESIGN NOTE: This function has a deliberate side effect for impersonation sessions. When an impersonation session is detected, it automatically calls set_actor() to configure the audit context. This is intentional for several reasons: 1. Convenience: Applications don't need to know about impersonation internals 2. Safety: Ensures all actions during impersonation are properly attributed in audit logs 3. Transparency: The impersonation context is always returned so apps can display it The function is marked VOLATILE due to this side effect. The side effect only triggers on the rare impersonation path (typically <0.01% of calls). For pure validation without side effects, check is_impersonating in the result and manage actor context manually. SECURITY NOTE: Token hash comparison uses PostgreSQL's = operator, which is not constant-time. Timing attacks are not practical here because: 1. Attacker must guess the SHA-256 hash (2^256 space), not the original token 2. Index lookup timing variance far exceeds string comparison variance 3. Network jitter (~1-10ms) drowns out comparison timing (~nanoseconds) 4. Even with perfect timing, reconstructing 256 bits via timing would require billions of precisely-timed queries Constant-time comparison would add overhead without meaningful security benefit. TRANSACTION NOTE: The auto-set actor context uses transaction-local settings (set_config with is_local=true). In autocommit mode, this context is lost when the implicit transaction commits. Callers using autocommit should use the returned impersonation context to set actor state at the application layer if needed for subsequent operations within the same request.

**Example:**
```sql
SELECT * FROM authn.validate_session('a1b2c3...token_hash');
```

*Source: authn/src/functions/020_sessions.sql:48*

---

## Tokens

### authn.consume_token

```sql
authn.consume_token(p_token_hash: text, p_token_type: text, p_namespace: text) -> table(user_id: uuid, email: text)
```

Use a one-time token (marks as used, can't be reused)

**Returns:** user_id, email if valid. Empty if expired, already used, or wrong type.

**Example:**
```sql
SELECT * FROM authn.consume_token('a1b2c3...token_hash', 'password_reset');
```

*Source: authn/src/functions/030_tokens.sql:58*

---

### authn.create_token

```sql
authn.create_token(p_user_id: uuid, p_token_hash: text, p_token_type: text, p_expires_in: interval, p_namespace: text) -> uuid
```

Create a one-time token for password reset, email verification, or magic link

**Parameters:**
- `p_token_hash`: SHA-256 hash of the token (send raw token to user via email)
- `p_token_type`: One of: 'password_reset', 'email_verify', 'magic_link'

**Returns:** Token ID

**Example:**
```sql
-- Send password reset email (token_hash is pre-computed SHA-256 hex string)
SELECT authn.create_token(user_id, 'a1b2c3...token_hash', 'password_reset');
```

*Source: authn/src/functions/030_tokens.sql:1*

---

### authn.invalidate_tokens

```sql
authn.invalidate_tokens(p_user_id: uuid, p_token_type: text, p_namespace: text) -> int4
```

Invalidate unused tokens (e.g., after password change, invalidate reset tokens)

**Returns:** Count of tokens invalidated

**Example:**
```sql
-- After password change, invalidate old reset tokens
SELECT authn.invalidate_tokens(user_id, 'password_reset');
```

*Source: authn/src/functions/030_tokens.sql:153*

---

### authn.verify_email

```sql
authn.verify_email(p_token_hash: text, p_namespace: text) -> table(user_id: uuid, email: text)
```

Verify email address using token from email link

**Returns:** user_id, email if valid. Sets email_verified_at automatically.

**Example:**
```sql
SELECT * FROM authn.verify_email('a1b2c3...token_hash');
```

*Source: authn/src/functions/030_tokens.sql:111*

---

## Users

### authn.create_user

```sql
authn.create_user(p_email: text, p_password_hash: text, p_namespace: text) -> uuid
```

Create a new user account

**Parameters:**
- `p_password_hash`: Argon2id hash from your app. NULL for SSO-only users.

**Returns:** User ID (UUID)

**Example:**
```sql
SELECT authn.create_user('alice@example.com', '$argon2id$...', 'default');
```

*Source: authn/src/functions/010_users.sql:1*

---

### authn.delete_user

```sql
authn.delete_user(p_user_id: uuid, p_namespace: text) -> bool
```

Permanently delete user and all their data (sessions, tokens, credentials)

**Returns:** True if user was found and deleted

**Example:**
```sql
SELECT authn.delete_user(user_id); -- Irreversible!
```

*Source: authn/src/functions/010_users.sql:256*

---

### authn.disable_user

```sql
authn.disable_user(p_user_id: uuid, p_namespace: text) -> bool
```

Disable user and revoke all credentials (sessions, API keys, refresh tokens, impersonations, tokens)

**Returns:** True if user was found and disabled

**Example:**
```sql
SELECT authn.disable_user(user_id);
```

*Source: authn/src/functions/010_users.sql:159*

---

### authn.enable_user

```sql
authn.enable_user(p_user_id: uuid, p_namespace: text) -> bool
```

Re-enable a disabled user account

**Example:**
```sql
SELECT authn.enable_user(user_id);
```

*Source: authn/src/functions/010_users.sql:222*

---

### authn.get_or_create_user

```sql
authn.get_or_create_user(p_email: text, p_password_hash: text, p_namespace: text) -> table(user_id: uuid, created: bool, disabled: bool)
```

Atomically get existing user or create new one (for SSO flows)

**Parameters:**
- `p_email`: User's email address (normalized to lowercase)
- `p_password_hash`: Optional password hash (NULL for SSO-only users)
- `p_namespace`: Namespace to use

**Returns:** user_id, created (true if new user), disabled (true if user is disabled) EDGE CASE: In an extremely rare race condition where: 1. INSERT fails because user exists (ON CONFLICT DO NOTHING) 2. Another transaction DELETEs that user before our SELECT 3. Our SELECT returns NULL This function will return (NULL, false, false). The SDK raises AuthnError in this case. This scenario requires user deletion during concurrent creation, which is operationally very unusual. If this is a concern for your use case, wrap the call in retry logic.

**Example:**
```sql
-- SSO callback: get or create user
SELECT * FROM authn.get_or_create_user('alice@example.com', NULL, 'default');
```

*Source: authn/src/functions/010_users.sql:381*

---

### authn.get_user

```sql
authn.get_user(p_user_id: uuid, p_namespace: text) -> table(user_id: uuid, email: text, email_verified_at: timestamptz, disabled_at: timestamptz, created_at: timestamptz, updated_at: timestamptz)
```

Get user by ID (does not return password hash)

**Example:**
```sql
SELECT * FROM authn.get_user('550e8400-e29b-41d4-a716-446655440000');
```

*Source: authn/src/functions/010_users.sql:37*

---

### authn.get_user_by_email

```sql
authn.get_user_by_email(p_email: text, p_namespace: text) -> table(user_id: uuid, email: text, email_verified_at: timestamptz, disabled_at: timestamptz, created_at: timestamptz, updated_at: timestamptz)
```

Look up user by email (normalized to lowercase)

**Example:**
```sql
SELECT * FROM authn.get_user_by_email('Alice@Example.com');
```

*Source: authn/src/functions/010_users.sql:71*

---

### authn.get_users_batch

```sql
authn.get_users_batch(p_user_ids: uuid[], p_namespace: text) -> table(user_id: uuid, email: text, email_verified_at: timestamptz, disabled_at: timestamptz, created_at: timestamptz, updated_at: timestamptz)
```

Get multiple users by ID in a single query

**Parameters:**
- `p_user_ids`: Array of user IDs to fetch
- `p_namespace`: Namespace to search in

**Returns:** User records for each found ID (missing IDs are silently omitted)

**Example:**
```sql
SELECT * FROM authn.get_users_batch(ARRAY['uuid1', 'uuid2']::uuid[], 'default');
```

*Source: authn/src/functions/010_users.sql:344*

---

### authn.list_users

```sql
authn.list_users(p_namespace: text, p_limit: int4, p_cursor: uuid) -> table(user_id: uuid, email: text, email_verified_at: timestamptz, disabled_at: timestamptz, created_at: timestamptz, updated_at: timestamptz)
```

List users with cursor-based pagination

**Parameters:**
- `p_limit`: Max users per page (default 100, max 1000)
- `p_cursor`: User ID to start after (for pagination)

**Example:**
```sql
SELECT * FROM authn.list_users('default', 50, NULL); -- First page
```

*Source: authn/src/functions/010_users.sql:300*

---

### authn.update_email

```sql
authn.update_email(p_user_id: uuid, p_new_email: text, p_namespace: text) -> bool
```

Change user's email address (clears email_verified_at)

**Returns:** True if user was found and updated

**Example:**
```sql
SELECT authn.update_email(user_id, 'new@example.com');
```

*Source: authn/src/functions/010_users.sql:108*

---
