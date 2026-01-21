-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/AUTHN
-- =============================================================================
-- PostgreSQL-native authentication module.
-- Stores users, sessions, tokens, MFA secrets, and login attempts.
-- No crypto: caller provides pre-hashed passwords and tokens.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS authn;

-- =============================================================================
-- USERS TABLE
-- =============================================================================
-- Core user identity. Password hash is optional for SSO-only users.
-- Email is unique per namespace and stored lowercase.
CREATE TABLE authn.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    email text NOT NULL,
    password_hash text,  -- NULL for SSO-only users
    email_verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_namespace_email_key UNIQUE (namespace, email),
    CONSTRAINT users_email_format CHECK (email ~* '^[^@\s]+@[^@\s]+$'),
    CONSTRAINT users_password_hash_not_empty CHECK (
        password_hash IS NULL OR length(trim(password_hash)) > 0
    )
);

-- =============================================================================
-- SESSIONS TABLE
-- =============================================================================
-- Active login sessions. Token hash is SHA-256 of the actual token.
-- Caller generates token, hashes it, stores hash. Validates by re-hashing.
CREATE TABLE authn.sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    ip_address inet,
    user_agent text,

    CONSTRAINT sessions_namespace_token_hash_key UNIQUE (namespace, token_hash),
    CONSTRAINT sessions_token_hash_not_empty CHECK (length(trim(token_hash)) > 0)
);

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================
-- Implements refresh token rotation per OAuth 2.0 Security BCP.
-- Each rotation creates a new token and marks the old one as replaced.
-- Reuse of a replaced token indicates theft - entire family is revoked.
CREATE TABLE authn.refresh_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES authn.sessions(id) ON DELETE CASCADE,
    token_hash text NOT NULL,
    family_id uuid NOT NULL,              -- Groups all tokens from same login
    generation int NOT NULL DEFAULT 1,    -- Increments on each rotation
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    replaced_by uuid REFERENCES authn.refresh_tokens(id),

    CONSTRAINT refresh_tokens_namespace_token_hash_key UNIQUE (namespace, token_hash),
    CONSTRAINT refresh_tokens_token_hash_not_empty CHECK (length(trim(token_hash)) > 0),
    CONSTRAINT refresh_tokens_generation_positive CHECK (generation > 0),
    CONSTRAINT refresh_tokens_not_self_replaced CHECK (id != replaced_by)
);

-- =============================================================================
-- TOKENS TABLE
-- =============================================================================
-- One-time tokens for password reset, email verification, magic links.
-- Consumed once via consume_token(), which sets used_at.
CREATE TABLE authn.tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    token_hash text NOT NULL,
    token_type text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz,

    CONSTRAINT tokens_namespace_token_hash_key UNIQUE (namespace, token_hash),
    CONSTRAINT tokens_token_hash_not_empty CHECK (length(trim(token_hash)) > 0),
    CONSTRAINT tokens_type_valid CHECK (
        token_type IN ('password_reset', 'email_verify', 'magic_link')
    )
);

-- =============================================================================
-- MFA SECRETS TABLE
-- =============================================================================
-- Multi-factor authentication methods. Secret is stored for caller to verify.
-- Supports TOTP, WebAuthn, and recovery codes.
CREATE TABLE authn.mfa_secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    mfa_type text NOT NULL,
    secret text NOT NULL,
    name text,  -- User-friendly name like "Work Yubikey"
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,

    CONSTRAINT mfa_secrets_type_valid CHECK (
        mfa_type IN ('totp', 'webauthn', 'recovery_codes')
    ),
    CONSTRAINT mfa_secrets_secret_not_empty CHECK (length(trim(secret)) > 0)
);

-- =============================================================================
-- LOGIN ATTEMPTS TABLE
-- =============================================================================
-- Records login attempts for lockout detection.
-- Uses bigint identity (not UUID) for high-volume, append-only data.
CREATE TABLE authn.login_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL DEFAULT 'default',
    email text NOT NULL,
    success boolean NOT NULL,
    ip_address inet,
    attempted_at timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- API KEYS TABLE
-- =============================================================================
-- Long-lived credentials for programmatic access (like Stripe API keys).
-- Caller generates key, hashes it, stores hash. Validates by re-hashing.
CREATE TABLE authn.api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    key_hash text NOT NULL,  -- SHA-256 of the actual key
    name text,               -- User-friendly name: "Production", "CI/CD"
    expires_at timestamptz,  -- NULL = never expires
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT api_keys_namespace_key_hash_key UNIQUE (namespace, key_hash),
    CONSTRAINT api_keys_key_hash_not_empty CHECK (length(trim(key_hash)) > 0)
);

-- =============================================================================
-- IMPERSONATION SESSIONS TABLE
-- =============================================================================
-- Tracks admin impersonation of users for support. Fully audited, time-limited.
-- Each impersonation creates a real session that acts as the target user,
-- but the original actor and reason are preserved for audit.
CREATE TABLE authn.impersonation_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL DEFAULT 'default',
    actor_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    target_user_id uuid NOT NULL REFERENCES authn.users(id) ON DELETE CASCADE,
    original_session_id uuid NOT NULL REFERENCES authn.sessions(id) ON DELETE CASCADE,
    impersonation_session_id uuid REFERENCES authn.sessions(id) ON DELETE SET NULL,
    reason text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ended_at timestamptz,

    -- Prevent self-impersonation
    CONSTRAINT impersonation_no_self CHECK (actor_id != target_user_id),
    -- Reason cannot be empty or whitespace-only
    CONSTRAINT impersonation_reason_not_empty CHECK (length(trim(reason)) > 0)
);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Tenant isolation using session variable authn.tenant_id
-- Note: current_setting(..., TRUE) returns '' when not set.
-- We explicitly check for non-empty to fail-closed when tenant context is missing.

ALTER TABLE authn.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.users FORCE ROW LEVEL SECURITY;

CREATE POLICY users_tenant_isolation ON authn.users
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY sessions_tenant_isolation ON authn.sessions
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.refresh_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY refresh_tokens_tenant_isolation ON authn.refresh_tokens
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY tokens_tenant_isolation ON authn.tokens
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.mfa_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.mfa_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY mfa_secrets_tenant_isolation ON authn.mfa_secrets
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.login_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY login_attempts_tenant_isolation ON authn.login_attempts
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.api_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON authn.api_keys
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

ALTER TABLE authn.impersonation_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.impersonation_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY impersonation_sessions_tenant_isolation ON authn.impersonation_sessions
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Cascade session revocation to refresh tokens
-- When a session is revoked, automatically revoke its refresh tokens
CREATE OR REPLACE FUNCTION authn._cascade_session_revocation()
RETURNS trigger AS $$
BEGIN
    UPDATE authn.refresh_tokens
    SET revoked_at = NEW.revoked_at
    WHERE session_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER session_revoked_cascade
    AFTER UPDATE OF revoked_at ON authn.sessions
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION authn._cascade_session_revocation();

-- Revoke impersonation session when impersonation record is deleted
-- This prevents orphaned sessions when original_session_id is cascade deleted
CREATE OR REPLACE FUNCTION authn._revoke_impersonation_session_on_delete()
RETURNS trigger AS $$
BEGIN
    IF OLD.impersonation_session_id IS NOT NULL THEN
        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE id = OLD.impersonation_session_id
          AND revoked_at IS NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER impersonation_deleted_revoke_session
    BEFORE DELETE ON authn.impersonation_sessions
    FOR EACH ROW
    EXECUTE FUNCTION authn._revoke_impersonation_session_on_delete();
