-- @group Notifications

-- @function lease.channel_name
-- @brief NOTIFY channel for a lease; LISTEN on this to receive release wake-ups.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @returns Channel name
-- The namespace and name are joined with the control character U+001F
-- before hashing. Names and namespaces can never contain control
-- characters, so two different (namespace, name) pairs can never produce
-- the same channel. md5 keeps the channel inside PostgreSQL's 63-byte
-- identifier limit and is not used for security; replace it with pgcrypto
-- where md5 is prohibited.
-- @example SELECT lease.channel_name('default', 'daily-report');
CREATE OR REPLACE FUNCTION lease.channel_name(p_namespace text, p_name text)
RETURNS text AS $$
    SELECT 'lease_' || md5(p_namespace || E'\x1F' || p_name);
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;
