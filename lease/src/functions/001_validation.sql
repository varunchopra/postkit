-- @group Internal

-- @function lease._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION lease._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:lease:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:lease:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:lease:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_lease_name
-- @brief Validate lease name format.
-- @param p_value Lease name to validate
-- Permissive like namespaces (not the queue-name charset): lease names commonly
-- encode resource identity with separators, e.g. 'exporter:cust_42'. Rejects
-- only control characters, leading/trailing whitespace, and length > 1024.
CREATE OR REPLACE FUNCTION lease._validate_lease_name(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Lease name cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:lease:VAL_LEASE_NAME_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Lease name cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:lease:VAL_LEASE_NAME_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Lease name exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:lease:VAL_LEASE_NAME_TOO_LONG';
    END IF;

    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Lease name contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_LEASE_NAME_INVALID_CHARS';
    END IF;

    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Lease name cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_LEASE_NAME_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_holder
-- @brief Validate holder identifier format.
-- @param p_value Holder ID to validate
-- Same permissive rules as lease names: holder IDs are opaque caller identity
-- (hostnames, pod names, UUIDs) and may contain separators.
CREATE OR REPLACE FUNCTION lease._validate_holder(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Holder ID cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:lease:VAL_HOLDER_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Holder ID cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:lease:VAL_HOLDER_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Holder ID exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:lease:VAL_HOLDER_TOO_LONG';
    END IF;

    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Holder ID contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_HOLDER_INVALID_CHARS';
    END IF;

    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Holder ID cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_HOLDER_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_ttl
-- @brief Validate a requested TTL against the configured maximum.
-- @param p_ttl Requested TTL (NULL is OK, caller uses the configured default)
-- @param p_max Maximum allowed TTL from config
CREATE OR REPLACE FUNCTION lease._validate_ttl(p_ttl interval, p_max interval)
RETURNS void AS $$
BEGIN
    IF p_ttl IS NULL THEN
        -- NULL is OK, will use default
        RETURN;
    END IF;

    IF p_ttl <= interval '0 seconds' THEN
        RAISE EXCEPTION 'TTL must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_TTL_NOT_POSITIVE';
    END IF;

    IF p_ttl > p_max THEN
        RAISE EXCEPTION 'TTL % exceeds maximum allowed TTL %', p_ttl, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_TTL_EXCEEDS_MAX';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_fence
-- @brief Validate that a fence token is not null.
-- @param p_value Fence token to validate
CREATE OR REPLACE FUNCTION lease._validate_fence(p_value bigint)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Fence token cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:lease:VAL_FENCE_NULL';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_name Name of the parameter for error message
CREATE OR REPLACE FUNCTION lease._validate_positive_int(p_value int, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION lease._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('lease.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;
