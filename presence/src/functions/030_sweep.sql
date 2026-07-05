-- @group Sweep

-- @function presence.sweep
-- @brief Mark overdue entities dead and deliver deferred death alerts.
-- @param p_namespace Tenant namespace (NULL = all namespaces, requires RLS bypass)
-- @param p_limit Maximum entities to process per call
-- @returns The death transitions emitted by this call
-- @example SELECT * FROM presence.sweep('default');
--
-- Call from cron or a maintenance loop; nothing runs on its own. Sweep
-- cadence is detection latency: a death is noticed no faster than the
-- tick, so death detection lags by up to dead_after plus the sweep
-- interval. Run with dead_after at least 3x the heartbeat interval and a
-- sweep cadence of at most dead_after / 2 (P2, see 001_tables.sql).
--
-- Death is the only edge sweep emits; revival belongs to heartbeat. A
-- sweep and a concurrent heartbeat can never both win on one entity: the
-- entity row lock serializes them, the overdue condition is re-checked
-- under the lock, and FOR UPDATE SKIP LOCKED means a row being heartbeated
-- right now is simply skipped - it is alive, or the next tick gets it
-- (P1, see 001_tables.sql).
--
-- An entity's timeout_override REPLACES its kind's dead_after - the two
-- are never combined, or the one slow-heartbeat entity in a fast fleet
-- (the override's whole use case) would be falsely killed at the kind's
-- cutoff.
--
-- Sweep scans the alive set every tick through the (namespace, kind,
-- status) index; there is deliberately no last_seen index (see the
-- entities table comment for the trade-off). Config is resolved once per
-- (namespace, kind) group, not per row.
--
-- Second duty: deaths whose hook was suppressed by flap damping get the
-- deferred alert once the flap window expires and the entity is still
-- dead - suppression defers terminal alerts, never drops them (P5). The
-- deferred job carries the REAL death time (dead_since), not this sweep's
-- time, and arrives up to flap_window after the death - inherent to
-- damping, not a bug. No new transitions row is emitted, so deferred
-- deliveries do not appear in the return set.
CREATE OR REPLACE FUNCTION presence.sweep(
    p_namespace text DEFAULT NULL,
    p_limit int DEFAULT 1000
)
RETURNS SETOF presence.transitions AS $$
DECLARE
    v_remaining int;
    v_group record;
    v_config presence.config;
    v_cutoff timestamptz;
    v_entity presence.entities;
    v_now timestamptz;
    v_flap record;
    v_transition presence.transitions;
BEGIN
    -- Validate inputs
    IF p_namespace IS NOT NULL THEN
        PERFORM presence._validate_namespace(p_namespace);
        PERFORM presence._warn_namespace_mismatch(p_namespace);
    ELSIF NOT presence._rls_bypassed() THEN
        RAISE EXCEPTION 'All-namespaces mode requires a role that bypasses RLS; pass an explicit namespace or run as a BYPASSRLS role'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'postkit:presence:BIZ_ALL_NAMESPACES_REQUIRES_BYPASS';
    END IF;
    PERFORM presence._validate_positive_int(p_limit, 'limit');

    v_remaining := p_limit;

    FOR v_group IN
        SELECT DISTINCT e.namespace AS ns, e.kind
        FROM presence.entities e
        WHERE (p_namespace IS NULL OR e.namespace = p_namespace)
          AND (e.status = 'alive' OR (e.status = 'dead' AND e.hook_suppressed))
        ORDER BY 1, 2
    LOOP
        EXIT WHEN v_remaining <= 0;
        v_config := presence._get_config(v_group.ns, v_group.kind);
        v_cutoff := clock_timestamp() - v_config.dead_after;

        FOR v_entity IN
            SELECT e.*
            FROM presence.entities e
            WHERE e.namespace = v_group.ns
              AND e.kind = v_group.kind
              AND e.status = 'alive'
              AND (
                  (e.timeout_override IS NULL AND e.last_seen < v_cutoff)
                  OR (e.timeout_override IS NOT NULL
                      AND e.last_seen < clock_timestamp() - e.timeout_override)
              )
            ORDER BY e.last_seen
            FOR UPDATE SKIP LOCKED
            LIMIT v_remaining
        LOOP
            -- Re-check under the lock on a fresh clock: time passed while
            -- waiting, and a heartbeat may have committed (the loop row is
            -- the current version).
            v_now := clock_timestamp();
            CONTINUE WHEN NOT (
                v_entity.status = 'alive'
                AND (
                    (v_entity.timeout_override IS NULL
                     AND v_entity.last_seen < v_now - v_config.dead_after)
                    OR (v_entity.timeout_override IS NOT NULL
                        AND v_entity.last_seen < v_now - v_entity.timeout_override)
                )
            );

            v_flap := presence._advance_flap(v_entity, v_config);
            v_transition := presence._record_transition(
                v_entity, 'dead', v_flap.flapping, v_now - v_entity.last_seen
            );

            UPDATE presence.entities e
            SET status = 'dead',
                dead_since = v_now,
                -- The flag means "a death alert is owed": set only when
                -- damping suppressed a hook that was actually configured
                hook_suppressed = v_flap.flapping
                                  AND v_config.on_death_queue IS NOT NULL,
                flap_count = v_flap.flap_count,
                flap_window_started = v_flap.flap_window_started,
                updated_at = v_now
            WHERE e.namespace = v_entity.namespace
              AND e.entity_id = v_entity.entity_id;

            PERFORM presence._notify_if_enabled(v_config, v_transition);
            IF NOT v_transition.flapping THEN
                PERFORM presence._fire_hooks(
                    v_config, v_entity.namespace, v_entity.entity_id,
                    v_entity.kind, 'alive', 'dead',
                    v_transition.at, v_transition.silent_for
                );
            END IF;

            v_remaining := v_remaining - 1;
            RETURN NEXT v_transition;
            EXIT WHEN v_remaining <= 0;
        END LOOP;

        EXIT WHEN v_remaining <= 0;

        FOR v_entity IN
            SELECT e.*
            FROM presence.entities e
            WHERE e.namespace = v_group.ns
              AND e.kind = v_group.kind
              AND e.status = 'dead'
              AND e.hook_suppressed
              AND e.flap_window_started < clock_timestamp() - v_config.flap_window
            FOR UPDATE SKIP LOCKED
            LIMIT v_remaining
        LOOP
            CONTINUE WHEN NOT (
                v_entity.status = 'dead'
                AND v_entity.hook_suppressed
                AND v_entity.flap_window_started
                    < clock_timestamp() - v_config.flap_window
            );

            -- The deferred terminal alert (P5): payload reconstructed from
            -- the entity row - dead_since is the real death time, and
            -- dead_since - last_seen recovers the original silent_for
            -- exactly (dead_since was the clock at death).
            PERFORM presence._fire_hooks(
                v_config, v_entity.namespace, v_entity.entity_id,
                v_entity.kind, 'alive', 'dead',
                v_entity.dead_since, v_entity.dead_since - v_entity.last_seen
            );

            UPDATE presence.entities e
            SET hook_suppressed = false,
                updated_at = clock_timestamp()
            WHERE e.namespace = v_entity.namespace
              AND e.entity_id = v_entity.entity_id;

            v_remaining := v_remaining - 1;
            EXIT WHEN v_remaining <= 0;
        END LOOP;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
