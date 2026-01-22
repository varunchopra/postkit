-- =============================================================================
-- INDEXES FOR POSTKIT/AUTHN
-- =============================================================================
-- Optimized for authentication hot paths: session validation, credential
-- lookup, and lockout checks must be sub-millisecond.
-- =============================================================================

-- =============================================================================
-- USERS INDEXES
-- =============================================================================
-- Note: The unique constraint users_namespace_email_key already creates a B-tree
-- index on (namespace, email). Since email is stored lowercase, no additional
-- index is needed for case-insensitive lookups.

-- =============================================================================
-- SESSIONS INDEXES
-- =============================================================================

-- Session validation (hottest path) - covering index for validate_session
-- Includes all fields needed to validate without table lookup
CREATE INDEX sessions_token_lookup_idx ON authn.sessions (namespace, token_hash)
    INCLUDE (user_id, expires_at, revoked_at)
    WHERE revoked_at IS NULL;

-- Session listing - active sessions for a user, newest first
CREATE INDEX sessions_user_active_idx ON authn.sessions (namespace, user_id, created_at DESC)
    WHERE revoked_at IS NULL;

-- Cleanup queries - find expired sessions for deletion
CREATE INDEX sessions_expired_idx ON authn.sessions (namespace, expires_at)
    WHERE revoked_at IS NULL;

-- Cleanup queries - find revoked sessions for deletion
-- Note: cleanup_expired() deletes WHERE revoked_at IS NOT NULL, needs separate index
CREATE INDEX sessions_revoked_idx ON authn.sessions (namespace)
    WHERE revoked_at IS NOT NULL;

-- =============================================================================
-- REFRESH TOKENS INDEXES
-- =============================================================================

-- Refresh token validation (hot path) - covering index for rotate_refresh_token
CREATE INDEX refresh_tokens_lookup_idx ON authn.refresh_tokens (namespace, token_hash)
    INCLUDE (user_id, session_id, family_id, generation, expires_at, revoked_at, replaced_by)
    WHERE revoked_at IS NULL AND replaced_by IS NULL;

-- Family revocation - find all tokens in a family for breach response
CREATE INDEX refresh_tokens_family_idx ON authn.refresh_tokens (namespace, family_id)
    WHERE revoked_at IS NULL;

-- User tokens - list/revoke all refresh tokens for a user
CREATE INDEX refresh_tokens_user_idx ON authn.refresh_tokens (namespace, user_id, created_at DESC)
    WHERE revoked_at IS NULL AND replaced_by IS NULL;

-- Session cascade - find tokens when session is revoked
CREATE INDEX refresh_tokens_session_idx ON authn.refresh_tokens (session_id)
    WHERE revoked_at IS NULL;

-- Cleanup - find expired or replaced tokens for deletion
CREATE INDEX refresh_tokens_expired_idx ON authn.refresh_tokens (namespace, expires_at)
    WHERE revoked_at IS NULL;

-- Cleanup - find revoked or replaced tokens for batch deletion
-- This index supports cleanup_expired() which deletes tokens where replaced_by IS NOT NULL
-- or revoked_at IS NOT NULL. Without this index, cleanup could sequential scan on large tables.
-- The overhead is minimal since revocation/rotation are cold paths already doing writes.
CREATE INDEX refresh_tokens_cleanup_idx ON authn.refresh_tokens (namespace)
    WHERE replaced_by IS NOT NULL OR revoked_at IS NOT NULL;

-- =============================================================================
-- TOKENS INDEXES
-- =============================================================================

-- Token lookup - covering index for consume_token
-- Includes fields needed to validate and return user info
CREATE INDEX tokens_lookup_idx ON authn.tokens (namespace, token_hash, token_type)
    INCLUDE (user_id, expires_at, used_at)
    WHERE used_at IS NULL;

-- Cleanup queries - find expired/used tokens for deletion
CREATE INDEX tokens_expired_idx ON authn.tokens (namespace, expires_at)
    WHERE used_at IS NULL;

-- Invalidation - find all tokens of type for a user
CREATE INDEX tokens_user_type_idx ON authn.tokens (namespace, user_id, token_type)
    WHERE used_at IS NULL;

-- =============================================================================
-- CREDENTIALS INDEXES
-- =============================================================================

-- WebAuthn: credential_id globally unique per namespace (relying party)
-- WebAuthn spec requires globally unique credential_id per relying party
CREATE UNIQUE INDEX credentials_webauthn_lookup_idx
    ON authn.credentials (namespace, lookup_key)
    WHERE credential_type = 'webauthn' AND lookup_key IS NOT NULL;

-- Recovery codes: unique per user (prevents cross-user enumeration)
-- Without user_id, attacker could probe hashes via INSERT conflicts
CREATE UNIQUE INDEX credentials_recovery_lookup_idx
    ON authn.credentials (namespace, user_id, lookup_key)
    WHERE credential_type = 'recovery_code' AND lookup_key IS NOT NULL;

-- Hot path: list_credentials() for settings UI (covering index - no heap access)
-- Includes all fields needed for list display without table lookup
CREATE INDEX credentials_user_type_idx
    ON authn.credentials (namespace, user_id, credential_type, created_at DESC)
    INCLUDE (id, name, last_used_at, consumed_at)
    WHERE disabled_at IS NULL;

-- Auth flow: get_credentials() needs secret_data (not covering, but fast filter)
-- Filters out consumed/disabled credentials at index level
CREATE INDEX credentials_user_active_idx
    ON authn.credentials (namespace, user_id, credential_type)
    WHERE disabled_at IS NULL AND consumed_at IS NULL;

-- =============================================================================
-- LOGIN ATTEMPTS INDEXES
-- =============================================================================

-- Lockout check (must be fast) - count failed attempts in sliding window
-- Email is already stored lowercase (normalized by _validate_email)
CREATE INDEX login_attempts_lockout_idx ON authn.login_attempts (namespace, email, attempted_at DESC)
    WHERE success = false;

-- Cleanup queries - delete old attempts
CREATE INDEX login_attempts_cleanup_idx ON authn.login_attempts (attempted_at);

-- =============================================================================
-- API KEYS INDEXES
-- =============================================================================

-- API key validation (hot path) - covering index for validate_api_key
-- Includes all fields needed to validate without table lookup
CREATE INDEX api_keys_lookup_idx ON authn.api_keys (namespace, key_hash)
    INCLUDE (user_id, name, expires_at, revoked_at)
    WHERE revoked_at IS NULL;

-- API key listing - active keys for a user, newest first
CREATE INDEX api_keys_user_active_idx ON authn.api_keys (namespace, user_id, created_at DESC)
    WHERE revoked_at IS NULL;

-- Cleanup queries - find expired keys (optional cleanup)
CREATE INDEX api_keys_expired_idx ON authn.api_keys (namespace, expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;

-- =============================================================================
-- IMPERSONATION SESSIONS INDEXES
-- =============================================================================

-- Context lookup (hot path) - get impersonation context from session id
-- Used by validate_session LEFT JOIN for every impersonation session check
CREATE INDEX impersonation_sessions_session_idx
    ON authn.impersonation_sessions (namespace, impersonation_session_id)
    INCLUDE (actor_id, target_user_id, reason)
    WHERE ended_at IS NULL;

-- Active impersonations by actor (admin dashboard)
CREATE INDEX impersonation_sessions_actor_active_idx
    ON authn.impersonation_sessions (namespace, actor_id, started_at DESC)
    WHERE ended_at IS NULL;

-- Active impersonations for target user (security auditing)
CREATE INDEX impersonation_sessions_target_idx
    ON authn.impersonation_sessions (namespace, target_user_id, started_at DESC)
    WHERE ended_at IS NULL;

-- Cleanup expired impersonations
CREATE INDEX impersonation_sessions_expired_idx
    ON authn.impersonation_sessions (namespace, expires_at)
    WHERE ended_at IS NULL;

-- =============================================================================
-- FK CASCADE DELETE INDEXES
-- =============================================================================
-- Non-partial indexes on FK columns to support efficient CASCADE deletes.
-- When a user is deleted, PostgreSQL must find all child records - partial
-- indexes (WHERE revoked_at IS NULL) don't cover revoked/expired records.

-- Sessions: efficient cascade when user is deleted
CREATE INDEX sessions_user_id_idx ON authn.sessions (user_id);

-- Refresh tokens: efficient cascade when user or session is deleted
CREATE INDEX refresh_tokens_user_id_idx ON authn.refresh_tokens (user_id);

-- Tokens: efficient cascade when user is deleted
CREATE INDEX tokens_user_id_idx ON authn.tokens (user_id);

-- Credentials: efficient cascade when user is deleted
CREATE INDEX credentials_user_id_idx ON authn.credentials (user_id);

-- API keys: efficient cascade when user is deleted
CREATE INDEX api_keys_user_id_idx ON authn.api_keys (user_id);

-- Impersonation sessions: efficient cascade when user or session is deleted
CREATE INDEX impersonation_sessions_actor_id_idx ON authn.impersonation_sessions (actor_id);
CREATE INDEX impersonation_sessions_target_user_id_idx ON authn.impersonation_sessions (target_user_id);
CREATE INDEX impersonation_sessions_original_session_id_idx ON authn.impersonation_sessions (original_session_id);
