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
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Tenant isolation using session variable authn.tenant_id

ALTER TABLE authn.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.users FORCE ROW LEVEL SECURITY;

CREATE POLICY users_tenant_isolation ON authn.users
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));

ALTER TABLE authn.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY sessions_tenant_isolation ON authn.sessions
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));

ALTER TABLE authn.tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY tokens_tenant_isolation ON authn.tokens
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));

ALTER TABLE authn.mfa_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.mfa_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY mfa_secrets_tenant_isolation ON authn.mfa_secrets
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));

ALTER TABLE authn.login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.login_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY login_attempts_tenant_isolation ON authn.login_attempts
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));
