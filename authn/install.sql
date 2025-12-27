-- =============================================================================
-- POSTKIT/AUTHN INSTALLATION SCRIPT
-- =============================================================================
-- PostgreSQL-native authentication module.
-- https://github.com/varunchopra/postkit
--
-- This file lists all SQL files in dependency order for the build script.
-- Run `make build` to generate dist/authn.sql
-- =============================================================================

-- Schema and tables
\ir src/schema/001_tables.sql
\ir src/schema/002_indexes.sql
\ir src/schema/003_audit.sql

-- Layer 0: Configuration and validation
\ir src/functions/000_config.sql
\ir src/functions/001_validation.sql
\ir src/functions/002_audit_helpers.sql

-- Layer 1: Users and credentials
\ir src/functions/010_users.sql
\ir src/functions/011_credentials.sql

-- Layer 2: Sessions, tokens, MFA, lockout
\ir src/functions/020_sessions.sql
\ir src/functions/030_tokens.sql
\ir src/functions/040_mfa.sql
\ir src/functions/050_lockout.sql

-- Layer 3: Maintenance, audit, RLS
\ir src/functions/060_maintenance.sql
\ir src/functions/070_audit.sql
\ir src/functions/080_rls.sql
