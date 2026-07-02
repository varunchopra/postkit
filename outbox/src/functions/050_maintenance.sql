-- @group Maintenance

-- @function outbox.trim
-- @brief Delete old events, keeping deletions a contiguous (xid, id) prefix.
-- @param p_older_than Delete events older than this interval (required)
-- @param p_namespace Tenant namespace (NULL = all namespaces, requires RLS bypass)
-- @param p_topic Topic filter (NULL = all topics)
-- @param p_limit Maximum events to delete per topic per call
-- @returns One row per topic touched: (namespace, topic, deleted count)
-- @example SELECT * FROM outbox.trim('30 days', 'default');
--
-- Call from cron or a maintenance loop; nothing runs on its own.
-- p_older_than has no default on purpose: event retention is a deployment
-- policy decision. It precedes p_namespace because a parameter with a
-- default cannot come before one without, and the all-namespaces mode
-- (p_namespace NULL, one cron across tenants) must keep its default.
--
-- Deletions are always a contiguous prefix of the topic's (xid, id) order,
-- never a per-row age filter. created_at is transaction-start time, so age
-- order and delivery order can disagree; deleting by age alone could
-- remove a later-ordered row while keeping an earlier one, and the trimmed
-- pair would then point past surviving events, turning them unreachable
-- and making poll raise CURSOR_LOST for data that still exists (O5, see
-- 001_tables.sql). The honest consequence: a row slightly younger than
-- p_older_than is deleted if an older row outranks it in delivery order.
-- The skew is bounded by the emitting transaction's duration.
--
-- The prefix boundary is the smallest (xid, id) pair of:
--   - the newest event older than the cutoff
--   - the slowest consumer's cursor, when protect_cursors is on; a topic
--     with protect_cursors and NO consumers is skipped entirely (a topic
--     nobody consumes yet must not be silently emptied)
--   - the pair that leaves retain_min_rows readable rows in place (found
--     by position, not id arithmetic: ids are sparse within a topic)
--   - the readable head: an event above the horizon may be committed but
--     not yet readable, and deleting it before any poll could see it is
--     silent permanent loss
--
-- Topics consumed only through read_from (external cursor holders) have no
-- cursor rows, so protect_cursors cannot protect them and, via the skip
-- rule, makes their topics untrimmable. Run such topics with
-- protect_cursors = false and a deliberate p_older_than; CURSOR_LOST from
-- read_from is the external consumers' safety net.
CREATE OR REPLACE FUNCTION outbox.trim(
    p_older_than interval,
    p_namespace text DEFAULT NULL,
    p_topic text DEFAULT NULL,
    p_limit int DEFAULT 10000
)
RETURNS TABLE(
    namespace text,
    topic text,
    deleted int
) AS $$
DECLARE
    v_topic outbox.topics;
    v_config outbox.config;
    v_head_xid xid8;
    v_head_id bigint;
    v_boundary_xid xid8;
    v_boundary_id bigint;
    v_floor_xid xid8;
    v_floor_id bigint;
    v_deleted int;
    v_new_xid xid8;
    v_new_id bigint;
BEGIN
    IF p_older_than IS NULL OR p_older_than <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Trim interval must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_TRIM_INTERVAL_NOT_POSITIVE';
    END IF;

    IF p_namespace IS NOT NULL THEN
        PERFORM outbox._validate_namespace(p_namespace);
        PERFORM outbox._warn_namespace_mismatch(p_namespace);
    END IF;
    IF p_topic IS NOT NULL THEN
        PERFORM outbox._validate_topic(p_topic);
    END IF;
    PERFORM outbox._validate_positive_int(p_limit, 'limit');

    FOR v_topic IN
        SELECT t.*
        FROM outbox.topics t
        WHERE (p_namespace IS NULL OR t.namespace = p_namespace)
          AND (p_topic IS NULL OR t.topic = p_topic)
        ORDER BY t.namespace, t.topic
        FOR UPDATE SKIP LOCKED
    LOOP
        v_config := outbox._get_config(v_topic.namespace, v_topic.topic);

        -- Boundary candidate 1: the newest event older than the cutoff.
        -- The MATERIALIZED fence is load-bearing: it forces an
        -- events_trim_idx scan of the rows older than the cutoff, a
        -- transient set this call is about to delete, followed by a top-1
        -- sort. Written as one ORDER BY .. LIMIT 1 query, the planner
        -- prefers a backward walk of the order index that heap-checks
        -- created_at across the ENTIRE retained set every tick.
        WITH old_rows AS MATERIALIZED (
            SELECT e.xid, e.id
            FROM outbox.events e
            WHERE e.namespace = v_topic.namespace AND e.topic = v_topic.topic
              AND e.created_at < now() - p_older_than
              AND e.xid < outbox._horizon()
        )
        SELECT o.xid, o.id INTO v_boundary_xid, v_boundary_id
        FROM old_rows o
        ORDER BY o.xid DESC, o.id DESC
        LIMIT 1;

        IF v_boundary_xid IS NULL THEN
            CONTINUE;
        END IF;

        -- Candidate 2: slowest cursor, or skip when nothing is protectable
        IF v_config.protect_cursors THEN
            SELECT c.position_xid, c.position_id INTO v_floor_xid, v_floor_id
            FROM outbox.cursors c
            WHERE c.namespace = v_topic.namespace AND c.topic = v_topic.topic
            ORDER BY c.position_xid, c.position_id
            LIMIT 1;

            IF v_floor_xid IS NULL THEN
                CONTINUE;
            END IF;
            IF (v_floor_xid, v_floor_id) < (v_boundary_xid, v_boundary_id) THEN
                v_boundary_xid := v_floor_xid;
                v_boundary_id := v_floor_id;
            END IF;
        END IF;

        -- Candidate 3: the pair that leaves retain_min_rows readable rows
        IF v_config.retain_min_rows > 0 THEN
            SELECT e.xid, e.id INTO v_floor_xid, v_floor_id
            FROM outbox.events e
            WHERE e.namespace = v_topic.namespace AND e.topic = v_topic.topic
              AND e.xid < outbox._horizon()
            ORDER BY e.xid DESC, e.id DESC
            OFFSET v_config.retain_min_rows
            LIMIT 1;

            IF v_floor_xid IS NULL THEN
                CONTINUE;
            END IF;
            IF (v_floor_xid, v_floor_id) < (v_boundary_xid, v_boundary_id) THEN
                v_boundary_xid := v_floor_xid;
                v_boundary_id := v_floor_id;
            END IF;
        END IF;

        -- Candidate 4: the readable head
        SELECT h.head_xid, h.head_id INTO v_head_xid, v_head_id
        FROM outbox._gated_head(v_topic.namespace, v_topic.topic) h;
        IF (v_head_xid, v_head_id) < (v_boundary_xid, v_boundary_id) THEN
            v_boundary_xid := v_head_xid;
            v_boundary_id := v_head_id;
        END IF;

        IF (v_boundary_xid, v_boundary_id) <= (v_topic.trimmed_xid, v_topic.trimmed_id) THEN
            CONTINUE;
        END IF;

        -- Ascending batch keeps each partial delete a contiguous prefix
        WITH batch AS (
            SELECT e.xid, e.id
            FROM outbox.events e
            WHERE e.namespace = v_topic.namespace AND e.topic = v_topic.topic
              AND (e.xid, e.id) <= (v_boundary_xid, v_boundary_id)
            ORDER BY e.xid, e.id
            LIMIT p_limit
        ),
        removed AS (
            DELETE FROM outbox.events e
            USING batch
            WHERE e.namespace = v_topic.namespace AND e.topic = v_topic.topic
              AND e.xid = batch.xid AND e.id = batch.id
            RETURNING e.xid, e.id
        )
        SELECT COUNT(*),
               (ARRAY_AGG(r.xid ORDER BY r.xid DESC, r.id DESC))[1],
               (ARRAY_AGG(r.id ORDER BY r.xid DESC, r.id DESC))[1]
        INTO v_deleted, v_new_xid, v_new_id
        FROM removed r;

        IF v_deleted = 0 THEN
            CONTINUE;
        END IF;

        UPDATE outbox.topics t
        SET trimmed_xid = v_new_xid,
            trimmed_id = v_new_id,
            updated_at = now()
        WHERE t.namespace = v_topic.namespace AND t.topic = v_topic.topic
          AND (t.trimmed_xid, t.trimmed_id) < (v_new_xid, v_new_id);

        namespace := v_topic.namespace;
        topic := v_topic.topic;
        deleted := v_deleted;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;
