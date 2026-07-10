-- @group Notifications

-- @function presence.channel_name
-- @brief NOTIFY channel for a kind; LISTEN on this to receive status transitions.
-- @param p_namespace Tenant namespace
-- @param p_kind Entity kind
-- @returns Channel name
-- The namespace and kind are joined with the control character U+001F
-- before hashing. Names and namespaces can never contain control
-- characters, so two different (namespace, kind) pairs can never produce
-- the same channel. md5 keeps the channel inside PostgreSQL's 63-byte
-- identifier limit and is not used for security; replace it with pgcrypto
-- where md5 is prohibited.
-- @example SELECT presence.channel_name('default', 'worker');
CREATE OR REPLACE FUNCTION presence.channel_name(p_namespace text, p_kind text)
RETURNS text AS $$
    SELECT 'presence_' || md5(p_namespace || E'\x1F' || p_kind);
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;
