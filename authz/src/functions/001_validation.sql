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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- Validate an array of IDs (for bulk operations)
-- Applies the same rules as _validate_id to each element
-- Reports the index of the first invalid element for easier debugging
CREATE OR REPLACE FUNCTION authz._validate_id_array(p_values text[], p_field_name text)
RETURNS void AS $$
DECLARE
    v_idx int;
    v_id text;
    v_reason text;
BEGIN
    FOR v_idx IN 1..COALESCE(array_length(p_values, 1), 0) LOOP
        v_id := p_values[v_idx];
        IF v_id IS NULL THEN
            v_reason := 'is null';
        ELSIF trim(v_id) = '' THEN
            v_reason := 'is empty';
        ELSIF length(v_id) > 1024 THEN
            v_reason := 'exceeds 1024 characters';
        ELSIF v_id ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
            v_reason := 'contains invalid control characters';
        ELSIF v_id != trim(v_id) THEN
            v_reason := 'has leading or trailing whitespace';
        ELSE
            CONTINUE;  -- Valid, check next
        END IF;
        RAISE EXCEPTION '%[%] %', p_field_name, v_idx, v_reason
            USING ERRCODE = 'invalid_parameter_value';
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- Warn if namespace doesn't match RLS tenant context
-- Called at the start of query functions to alert developers of likely misconfiguration
CREATE OR REPLACE FUNCTION authz._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('authz.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
