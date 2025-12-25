-- =============================================================================
-- CONFIGURATION
-- =============================================================================
-- Configurable defaults extracted as functions for maintainability.

-- Default relation used for group membership when subject_relation is NULL
-- Used in: recompute (group expansion), explain (group path detection)
CREATE OR REPLACE FUNCTION authz.default_membership_relation()
RETURNS TEXT AS $$ SELECT 'member'::TEXT; $$
LANGUAGE sql IMMUTABLE PARALLEL SAFE;

-- =============================================================================
-- INPUT VALIDATION FUNCTIONS
-- =============================================================================
--
-- WHY VALIDATE?
-- =============
-- Authorization data is security-critical. Bad data causes:
--   1. Silent failures - empty strings match nothing, permissions seem missing
--   2. Hard debugging - "why doesn't this work?" hours later
--   3. Injection risks - control characters, null bytes
--   4. Performance issues - very long strings bloat indexes
--
-- FAIL FAST PRINCIPLE
-- ===================
-- It's better to reject bad data immediately with a clear error than to
-- accept it and discover problems later during a 3am incident.
--
-- Enterprise systems often have data flowing from many sources (APIs, imports,
-- migrations). Validation at the database level is the last line of defense.
--
-- WHAT WE VALIDATE
-- ================
-- Two categories of fields:
--
-- 1. IDENTIFIERS (resource_type, subject_type, relation)
--    These are "schema-like" - they define the structure of your permission model.
--    Strict format: lowercase alphanumeric, underscores, hyphens.
--    Examples: "repo", "team", "user", "member", "admin"
--
-- 2. IDS (resource_id, subject_id)
--    These are "data" - they reference actual entities in your system.
--    Flexible format: allows slashes, colons, @ symbols for paths/URIs.
--    Examples: "acme/api", "user:alice@example.com", "org/team/repo"
--
-- Both have:
--   - Non-empty requirement
--   - Maximum length (1024 chars)
--   - No null bytes or control characters

-- Validate an identifier (resource_type, subject_type, relation)
-- Strict format: lowercase letters, numbers, underscores, hyphens
CREATE OR REPLACE FUNCTION authz.validate_identifier(
    p_value TEXT,
    p_field_name TEXT
) RETURNS VOID AS $$
BEGIN
    -- Check for NULL
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name;
    END IF;

    -- Check for empty or whitespace-only
    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name;
    END IF;

    -- Check length (1024 is generous but prevents abuse)
    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name;
    END IF;

    -- Note: Null bytes are rejected by PostgreSQL at the protocol level,
    -- so we don't need to check for them explicitly.

    -- Check format: lowercase alphanumeric, underscore, hyphen only
    -- This ensures identifiers are "clean" and predictable
    IF p_value !~ '^[a-z][a-z0-9_-]*$' THEN
        RAISE EXCEPTION '% must start with lowercase letter and contain only lowercase letters, numbers, underscores, and hyphens (got: %)',
            p_field_name, p_value;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- Validate an ID (resource_id, subject_id)
-- Flexible format: allows paths, URIs, email-like strings
CREATE OR REPLACE FUNCTION authz.validate_id(
    p_value TEXT,
    p_field_name TEXT
) RETURNS VOID AS $$
BEGIN
    -- Check for NULL
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name;
    END IF;

    -- Check for empty or whitespace-only
    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name;
    END IF;

    -- Check length
    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name;
    END IF;

    -- Reject control characters (except tab, newline, carriage return which some systems use)
    -- Null bytes are rejected by PostgreSQL at the protocol level
    IF p_value ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
        RAISE EXCEPTION '% contains invalid control characters', p_field_name;
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION '% cannot have leading or trailing whitespace', p_field_name;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- Validate namespace
-- More flexible than identifiers: allows UUIDs, numeric tenant IDs, etc.
CREATE OR REPLACE FUNCTION authz.validate_namespace(
    p_value TEXT
) RETURNS VOID AS $$
BEGIN
    -- Check for NULL
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'namespace cannot be null';
    END IF;

    -- Check for empty or whitespace-only
    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'namespace cannot be empty';
    END IF;

    -- Check length
    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'namespace exceeds maximum length of 1024 characters';
    END IF;

    -- Format: alphanumeric (can start with number), underscores, hyphens
    -- Allows: "default", "tenant_123", "550e8400-e29b-41d4-a716-446655440000"
    IF p_value !~ '^[a-z0-9][a-z0-9_-]*$' THEN
        RAISE EXCEPTION 'namespace must be alphanumeric with underscores/hyphens (got: %)', p_value;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- =============================================================================
-- COMPOSITE VALIDATION
-- =============================================================================
-- Validates all tuple fields in one call. Reduces code duplication in
-- write_tuple, delete_tuple, etc.

CREATE OR REPLACE FUNCTION authz.validate_tuple_fields(
    p_namespace TEXT,
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_subject_relation TEXT DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    PERFORM authz.validate_namespace(p_namespace);
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_id(p_resource_id, 'resource_id');
    PERFORM authz.validate_identifier(p_relation, 'relation');
    PERFORM authz.validate_identifier(p_subject_type, 'subject_type');
    PERFORM authz.validate_id(p_subject_id, 'subject_id');

    IF p_subject_relation IS NOT NULL THEN
        PERFORM authz.validate_identifier(p_subject_relation, 'subject_relation');
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- =============================================================================
-- EXPIRATION HELPERS
-- =============================================================================
-- Utility function for computing minimum expiration in permission chains.
-- NULL is treated as "never expires" (infinity).

-- Returns the minimum of two expiration timestamps, treating NULL as infinity.
-- Used when propagating expiration through group memberships and permission chains.
-- Example: If membership expires in 7 days and grant expires in 30 days,
-- the computed permission expires in 7 days (the minimum).
CREATE OR REPLACE FUNCTION authz.min_expiration(a TIMESTAMPTZ, b TIMESTAMPTZ)
RETURNS TIMESTAMPTZ AS $$
    SELECT CASE
        WHEN a IS NULL THEN b
        WHEN b IS NULL THEN a
        ELSE LEAST(a, b)
    END;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;
