-- @group Maintenance

-- @function config.cleanup_old_versions
-- @brief Delete old inactive versions, keeping N most recent per key
-- @param p_keep_versions Number of inactive versions to keep per key (default 10)
-- @returns Count of versions deleted
-- @example SELECT config.cleanup_old_versions(5);
CREATE OR REPLACE FUNCTION config.cleanup_old_versions(
    p_keep_versions int DEFAULT 10,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM config._validate_namespace(p_namespace);

    IF p_keep_versions < 0 THEN
        RAISE EXCEPTION 'keep_versions must be non-negative'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:VAL_KEEP_VERSIONS_NEGATIVE';
    END IF;

    -- Rank only inactive versions to handle case where active isn't newest
    WITH inactive_ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY key ORDER BY version DESC) as rn
        FROM config.entries
        WHERE namespace = p_namespace AND is_active = false
    )
    DELETE FROM config.entries
    WHERE id IN (SELECT id FROM inactive_ranked WHERE rn > p_keep_versions);

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.get_stats
-- @brief Get namespace statistics
-- @example SELECT * FROM config.get_stats();
CREATE OR REPLACE FUNCTION config.get_stats(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    total_keys bigint,
    total_versions bigint,
    keys_by_prefix jsonb
)
AS $$
BEGIN
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    -- Single-pass aggregation
    RETURN QUERY
    WITH base AS (
        SELECT key, is_active, split_part(key, '/', 1) as prefix
        FROM config.entries
        WHERE namespace = p_namespace
    )
    SELECT
        COUNT(DISTINCT key)::bigint,
        COUNT(*)::bigint,
        (
            SELECT jsonb_object_agg(prefix, cnt)
            FROM (
                SELECT prefix, COUNT(DISTINCT key) as cnt
                FROM base WHERE is_active = true
                GROUP BY prefix
            ) sub
        )
    FROM base;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;
