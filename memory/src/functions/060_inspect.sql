-- @group Inspection

-- @function memory.get_stats
-- @brief Namespace-wide memory counts.
-- @param p_namespace Tenant namespace
-- @returns total_episodes, unconsolidated_episodes, total_nodes, live_nodes, total_edges, embedding_dim
-- @example SELECT * FROM memory.get_stats('default');
CREATE OR REPLACE FUNCTION memory.get_stats(p_namespace text)
RETURNS TABLE (
    total_episodes bigint,
    unconsolidated_episodes bigint,
    total_nodes bigint,
    live_nodes bigint,
    total_edges bigint,
    embedding_dim int
) AS $$
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        ep.total, ep.unconsolidated, nd.total, nd.live,
        (SELECT count(*) FROM memory.edges ed WHERE ed.namespace = p_namespace),
        memory._embedding_dim()
    FROM (
        SELECT count(*) AS total,
               count(*) FILTER (WHERE e.consolidated_at IS NULL) AS unconsolidated
        FROM memory.episodes e WHERE e.namespace = p_namespace
    ) ep, (
        SELECT count(*) AS total,
               count(*) FILTER (WHERE n.invalidated_at IS NULL) AS live
        FROM memory.nodes n WHERE n.namespace = p_namespace
    ) nd;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory.list_episodes
-- @brief List episodes newest first, with keyset pagination.
-- @param p_namespace Tenant namespace
-- @param p_session Optional session filter
-- @param p_limit Maximum rows to return
-- @param p_before_at Keyset cursor: occurred_at of the last row seen
-- @param p_before_id Keyset cursor: id of the last row seen
-- @returns Episode rows (embedding omitted), ordered by (occurred_at, id) descending
-- @example SELECT * FROM memory.list_episodes('default');
-- The cursor pair (p_before_at, p_before_id) is applied as
-- (occurred_at, id) < (p_before_at, p_before_id); the SDK encodes and decodes it.
CREATE OR REPLACE FUNCTION memory.list_episodes(
    p_namespace text,
    p_session text DEFAULT NULL,
    p_limit int DEFAULT 100,
    p_before_at timestamptz DEFAULT NULL,
    p_before_id bigint DEFAULT NULL
)
RETURNS TABLE (
    id bigint,
    session_id text,
    role text,
    content text,
    embed_model text,
    keywords text[],
    occurred_at timestamptz,
    consolidated_at timestamptz,
    metadata jsonb,
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,
    created_at timestamptz
) AS $$
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);
    PERFORM memory._validate_limit(p_limit, 'limit', 1000);

    RETURN QUERY
    SELECT e.id, e.session_id, e.role, e.content, e.embed_model, e.keywords,
           e.occurred_at, e.consolidated_at, e.metadata,
           e.actor_id, e.request_id, e.on_behalf_of, e.reason, e.created_at
    FROM memory.episodes e
    WHERE e.namespace = p_namespace
      AND (p_session IS NULL OR e.session_id = p_session)
      AND (p_before_at IS NULL OR (e.occurred_at, e.id) < (p_before_at, p_before_id))
    ORDER BY e.occurred_at DESC, e.id DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory.list_nodes
-- @brief List nodes newest first, with keyset pagination.
-- @param p_namespace Tenant namespace
-- @param p_kind Optional kind filter ('fact' or 'entity')
-- @param p_include_superseded Include invalidated/superseded nodes (default false)
-- @param p_limit Maximum rows to return
-- @param p_before_at Keyset cursor: recorded_at of the last row seen
-- @param p_before_id Keyset cursor: id of the last row seen
-- @returns Node rows (embedding omitted), ordered by (recorded_at, id) descending
-- @example SELECT * FROM memory.list_nodes('default');
CREATE OR REPLACE FUNCTION memory.list_nodes(
    p_namespace text,
    p_kind text DEFAULT NULL,
    p_include_superseded boolean DEFAULT false,
    p_limit int DEFAULT 100,
    p_before_at timestamptz DEFAULT NULL,
    p_before_id bigint DEFAULT NULL
)
RETURNS TABLE (
    id bigint,
    kind text,
    content text,
    embed_model text,
    confidence real,
    valid_from timestamptz,
    valid_until timestamptz,
    recorded_at timestamptz,
    invalidated_at timestamptz,
    superseded_by bigint,
    evidence bigint[],
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,
    created_at timestamptz
) AS $$
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);
    PERFORM memory._validate_limit(p_limit, 'limit', 1000);
    IF p_kind IS NOT NULL THEN
        PERFORM memory._validate_kind(p_kind);
    END IF;

    RETURN QUERY
    SELECT n.id, n.kind, n.content, n.embed_model, n.confidence,
           n.valid_from, n.valid_until, n.recorded_at, n.invalidated_at,
           n.superseded_by, n.evidence,
           n.actor_id, n.request_id, n.on_behalf_of, n.reason, n.created_at
    FROM memory.nodes n
    WHERE n.namespace = p_namespace
      AND (p_kind IS NULL OR n.kind = p_kind)
      AND (p_include_superseded OR n.invalidated_at IS NULL)
      AND (p_before_at IS NULL OR (n.recorded_at, n.id) < (p_before_at, p_before_id))
    ORDER BY n.recorded_at DESC, n.id DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory.get_node
-- @brief Fetch a single node including its evidence episode ids.
-- @param p_namespace Tenant namespace
-- @param p_id Node id
-- @returns The node row (embedding omitted)
-- @example SELECT * FROM memory.get_node('default', 42);
CREATE OR REPLACE FUNCTION memory.get_node(
    p_namespace text,
    p_id bigint
)
RETURNS TABLE (
    id bigint,
    kind text,
    content text,
    embed_model text,
    confidence real,
    valid_from timestamptz,
    valid_until timestamptz,
    recorded_at timestamptz,
    invalidated_at timestamptz,
    superseded_by bigint,
    evidence bigint[],
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,
    created_at timestamptz
) AS $$
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);

    IF NOT EXISTS (
        SELECT 1 FROM memory.nodes n
        WHERE n.namespace = p_namespace AND n.id = p_id
    ) THEN
        RAISE EXCEPTION 'Node % not found', p_id
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:memory:DATA_NODE_NOT_FOUND';
    END IF;

    RETURN QUERY
    SELECT n.id, n.kind, n.content, n.embed_model, n.confidence,
           n.valid_from, n.valid_until, n.recorded_at, n.invalidated_at,
           n.superseded_by, n.evidence,
           n.actor_id, n.request_id, n.on_behalf_of, n.reason, n.created_at
    FROM memory.nodes n
    WHERE n.namespace = p_namespace AND n.id = p_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;
