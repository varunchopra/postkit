-- @group Notifications

-- @function outbox.channel_name
-- @brief NOTIFY channel for a topic; LISTEN on this to receive emit wake-ups.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @returns Channel name
-- The namespace and topic are joined with the control character U+001F
-- before hashing. Names and namespaces can never contain control
-- characters, so two different (namespace, topic) pairs can never produce
-- the same channel. md5 keeps the channel inside PostgreSQL's 63-byte
-- identifier limit and is not used for security; replace it with pgcrypto
-- where md5 is prohibited.
-- @example SELECT outbox.channel_name('default', 'orders');
CREATE OR REPLACE FUNCTION outbox.channel_name(p_namespace text, p_topic text)
RETURNS text AS $$
    SELECT 'outbox_' || md5(p_namespace || E'\x1F' || p_topic);
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;
