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
-- MFA SECRETS INDEXES
-- =============================================================================

-- MFA lookup - get secrets for verification
CREATE INDEX mfa_secrets_user_idx ON authn.mfa_secrets (namespace, user_id, mfa_type);

-- =============================================================================
-- LOGIN ATTEMPTS INDEXES
-- =============================================================================

-- Lockout check (must be fast) - count failed attempts in sliding window
-- Email is already stored lowercase (normalized by _validate_email)
CREATE INDEX login_attempts_lockout_idx ON authn.login_attempts (namespace, email, attempted_at DESC)
    WHERE success = false;

-- Cleanup queries - delete old attempts
CREATE INDEX login_attempts_cleanup_idx ON authn.login_attempts (attempted_at);
