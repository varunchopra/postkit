-- @group Internal

-- All single-key mutations acquire this lock before touching config.entries.
CREATE OR REPLACE FUNCTION config._lock_key(p_namespace text, p_key text)
RETURNS void
AS $$
BEGIN
    INSERT INTO config.version_counters (namespace, key, max_version)
    VALUES (p_namespace, p_key, 0)
    ON CONFLICT (namespace, key) DO NOTHING;

    PERFORM 1
    FROM config.version_counters
    WHERE namespace = p_namespace AND key = p_key
    FOR UPDATE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = config, pg_temp;


CREATE OR REPLACE FUNCTION config._escape_like_prefix(p_prefix text)
RETURNS text
AS $$
    SELECT replace(
        replace(
            replace(p_prefix, E'\\', E'\\\\'),
            '%', E'\\%'
        ),
        '_', E'\\_'
    );
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = config, pg_temp;
