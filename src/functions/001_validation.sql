-- =============================================================================
-- INPUT VALIDATION
-- =============================================================================
--
-- Authorization data is security-critical. Bad data causes:
--   - Silent failures (empty strings match nothing)
--   - Hard debugging ("why doesn't this permission work?")
--   - Injection risks (control characters, null bytes)
--   - Performance issues (very long strings bloat indexes)
--
-- We validate at the database level as the last line of defense. It's better
-- to reject bad data with a clear error than to debug weird behavior later.
--
-- Two categories of fields:
--
-- IDENTIFIERS (resource_type, subject_type, relation)
--   Schema-like fields that define permission model structure.
--   Strict: lowercase alphanumeric, underscores, hyphens only.
--   Examples: "repo", "team", "admin", "member"
--
-- IDS (resource_id, subject_id)
--   Data fields that reference entities in your system.
--   Flexible: allows paths, URIs, emails, UUIDs.
--   Examples: "acme/api", "user@example.com", "550e8400-e29b-41d4"


-- Validate an identifier (resource_type, subject_type, relation)
CREATE OR REPLACE FUNCTION authz._validate_identifier(p_value text, p_field_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Must start with letter, then lowercase alphanumeric/underscore/hyphen
    IF p_value !~ '^[a-z][a-z0-9_-]*$' THEN
        RAISE EXCEPTION '% must start with lowercase letter and contain only lowercase letters, numbers, underscores, and hyphens (got: %)', p_field_name, p_value
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- Validate an ID (resource_id, subject_id)
CREATE OR REPLACE FUNCTION authz._validate_id(p_value text, p_field_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Reject control characters (except tab, newline, carriage return)
    IF p_value ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
        RAISE EXCEPTION '% contains invalid control characters', p_field_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION '% cannot have leading or trailing whitespace', p_field_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- Validate an array of IDs (for bulk operations)
-- Applies the same rules as _validate_id to each element
CREATE OR REPLACE FUNCTION authz._validate_id_array(p_values text[], p_field_name text)
RETURNS void AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM unnest(p_values) AS id
        WHERE id IS NULL
           OR trim(id) = ''
           OR length(id) > 1024
           OR id ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'
           OR id != trim(id)
    ) THEN
        RAISE EXCEPTION '% contains invalid values (null, empty, too long, or invalid characters)', p_field_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- Validate namespace
-- More flexible than identifiers: allows UUIDs, numeric tenant IDs
CREATE OR REPLACE FUNCTION authz._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Alphanumeric (can start with number), underscores, hyphens
    -- Allows: "default", "tenant_123", "550e8400-e29b-41d4-a716-446655440000"
    IF p_value !~ '^[a-z0-9][a-z0-9_-]*$' THEN
        RAISE EXCEPTION 'namespace must be alphanumeric with underscores/hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authz, pg_temp;
