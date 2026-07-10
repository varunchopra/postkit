-- @group Notifications

-- @function queue.channel_name
-- @brief NOTIFY channel for a queue; LISTEN on this to receive push wake-ups.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @returns Channel name
-- The namespace and queue are joined with the control character U+001F
-- before hashing. Names and namespaces can never contain control
-- characters, so two different (namespace, queue) pairs can never produce
-- the same channel. md5 keeps the channel inside PostgreSQL's 63-byte
-- identifier limit and is not used for security; replace it with pgcrypto
-- where md5 is prohibited.
-- @example SELECT queue.channel_name('default', 'emails');
CREATE OR REPLACE FUNCTION queue.channel_name(p_namespace text, p_queue text)
RETURNS text AS $$
    SELECT 'q_' || md5(p_namespace || E'\x1F' || p_queue);
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;
