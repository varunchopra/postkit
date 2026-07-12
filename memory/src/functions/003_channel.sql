-- @group Notifications

-- @function memory.channel_name
-- @brief NOTIFY channel for a namespace; LISTEN on this to receive record wake-ups.
-- @param p_namespace Tenant namespace
-- @returns Channel name
-- md5 keeps the channel inside PostgreSQL's 63-byte identifier limit and is
-- not used for security; replace it with pgcrypto where md5 is prohibited.
-- record() notifies this channel when the namespace config has
-- notify_on_record enabled, so a consolidation worker can wake instead of
-- polling; consolidation_due() remains the source of truth for what is due.
-- @example SELECT memory.channel_name('default');
CREATE OR REPLACE FUNCTION memory.channel_name(p_namespace text)
RETURNS text AS $$
    SELECT 'memory_' || md5(p_namespace);
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;
