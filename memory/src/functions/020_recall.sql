-- @group Recall

-- @function memory.recall
-- @brief Find memories relevant to a query by meaning, keywords, and connection.
-- @param p_namespace Tenant namespace
-- @param p_query_embedding Optional query embedding for the vector arm
-- @param p_keywords Optional keyword array for the lexical arm
-- @param p_k Maximum rows to return (positive)
-- @param p_hops Graph expansion depth (defaults to and capped by config.recall_max_hops)
-- @returns Scored episodes and nodes: source, id, kind, content, score, hops, occurred_at
-- @example SELECT * FROM memory.recall('default', NULL, ARRAY['hello']);
--
-- Recall never writes. Entry points come from two arms fused by max
-- similarity: cosine similarity over embeddings (HNSW, pgvector's
-- approximate nearest-neighbor index) and full-text ranking over the
-- generated search column (a GIN text-search index, ranked by ts_rank). Node
-- entry points then expand over stored edges one hop at a time, inherited
-- score decaying by weight * 0.5 per hop; every hop keeps one row per node
-- (best score wins) and at most config.recall_max_nodes nodes, so a
-- hub-heavy graph cannot blow up the traversal. Final scoring multiplies
-- similarity by recency decay that halves every config.recall_halflife
-- (occurred_at for episodes, recorded_at for nodes) and, for nodes,
-- confidence. Superseded, invalidated, and expired nodes are never
-- returned. At least one of embedding or keywords must be given.
CREATE OR REPLACE FUNCTION memory.recall(
    p_namespace text,
    p_query_embedding vector DEFAULT NULL,
    p_keywords text[] DEFAULT NULL,
    p_k int DEFAULT 12,
    p_hops int DEFAULT NULL
)
RETURNS TABLE (
    source text,
    id bigint,
    kind text,
    content text,
    score double precision,
    hops int,
    occurred_at timestamptz
) AS $$
DECLARE
    v_config memory.config;
    v_dim int;
    v_hops int;
    v_max_nodes int;
    v_halflife double precision;
    v_entry int;
    v_tsq tsquery;
    v_frontier_ids bigint[];
    v_frontier_scores double precision[];
    v_acc_ids bigint[];
    v_acc_scores double precision[];
    v_acc_hops int[];
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);

    IF p_query_embedding IS NULL AND p_keywords IS NULL THEN
        RAISE EXCEPTION 'recall requires a query embedding or keywords'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_RECALL_NO_QUERY';
    END IF;

    PERFORM memory._validate_positive_int(p_k, 'k');

    v_dim := memory._embedding_dim();
    IF p_query_embedding IS NOT NULL
       AND (v_dim IS NULL OR vector_dims(p_query_embedding) != v_dim) THEN
        RAISE EXCEPTION 'Query embedding does not match the store dimension'
            USING ERRCODE = 'data_exception',
                  HINT = 'postkit:memory:BIZ_EMBEDDING_DIMENSION_MISMATCH';
    END IF;

    v_config := memory._get_config(p_namespace);
    v_hops := LEAST(COALESCE(p_hops, v_config.recall_max_hops), v_config.recall_max_hops);
    IF v_hops < 0 THEN
        v_hops := 0;
    END IF;
    v_max_nodes := v_config.recall_max_nodes;
    v_halflife := extract(epoch FROM v_config.recall_halflife);
    IF p_keywords IS NOT NULL THEN
        v_tsq := websearch_to_tsquery('simple', array_to_string(p_keywords, ' or '));
    END IF;
    -- Pull a few times k candidates per arm so fusion and decay have room to
    -- reorder before the final p_k cut.
    v_entry := p_k * 4;

    -- Node entry points (hop 0): vector and lexical arms fused by max
    -- similarity, scored by similarity * recency * confidence.
    SELECT COALESCE(array_agg(t.id), '{}'), COALESCE(array_agg(t.score), '{}')
    INTO v_acc_ids, v_acc_scores
    FROM (
        SELECT u.id,
               (max(u.sim)
                * exp(-ln(2) * extract(epoch FROM (now() - u.recorded_at)) / v_halflife)
                * COALESCE(u.confidence, 1.0))::double precision AS score
        FROM (
            (SELECT n.id, n.recorded_at, n.confidence,
                    (1 - (n.embedding <=> p_query_embedding))::double precision AS sim
             FROM memory.nodes n
             WHERE n.namespace = p_namespace
               AND p_query_embedding IS NOT NULL AND n.embedding IS NOT NULL
               AND n.invalidated_at IS NULL
               AND (n.valid_until IS NULL OR n.valid_until > now())
             ORDER BY n.embedding <=> p_query_embedding
             LIMIT v_entry)
            UNION ALL
            (SELECT n.id, n.recorded_at, n.confidence,
                    ts_rank(n.search, v_tsq)::double precision AS sim
             FROM memory.nodes n
             WHERE n.namespace = p_namespace
               AND p_keywords IS NOT NULL
               AND n.invalidated_at IS NULL
               AND (n.valid_until IS NULL OR n.valid_until > now())
               AND n.search @@ v_tsq
             ORDER BY sim DESC
             LIMIT v_entry)
        ) u
        GROUP BY u.id, u.recorded_at, u.confidence
    ) t;
    v_acc_hops := array_fill(0, ARRAY[cardinality(v_acc_ids)]);

    -- Expand over stored edges one hop at a time. Each hop groups the
    -- reachable nodes to one row each and keeps the v_max_nodes best, so a
    -- node expands at most once per hop no matter how many paths reach it.
    -- The per-node max is the true best-path score: every per-hop factor is
    -- positive, so max distributes over the product.
    v_frontier_ids := v_acc_ids;
    v_frontier_scores := v_acc_scores;
    FOR v_hop IN 1..v_hops LOOP
        EXIT WHEN cardinality(v_frontier_ids) = 0;

        SELECT COALESCE(array_agg(s.node_id), '{}'), COALESCE(array_agg(s.score), '{}')
        INTO v_frontier_ids, v_frontier_scores
        FROM (
            SELECT ed.to_node AS node_id,
                   max(f.score * ed.weight * 0.5)::double precision AS score
            FROM unnest(v_frontier_ids, v_frontier_scores) AS f(node_id, score)
            JOIN memory.edges ed
              ON ed.namespace = p_namespace AND ed.from_node = f.node_id
            JOIN memory.nodes n2
              ON n2.namespace = p_namespace AND n2.id = ed.to_node
             AND n2.invalidated_at IS NULL
             AND (n2.valid_until IS NULL OR n2.valid_until > now())
            GROUP BY ed.to_node
            ORDER BY max(f.score * ed.weight * 0.5) DESC
            LIMIT v_max_nodes
        ) s;

        v_acc_ids := v_acc_ids || v_frontier_ids;
        v_acc_scores := v_acc_scores || v_frontier_scores;
        v_acc_hops := v_acc_hops || array_fill(v_hop, ARRAY[cardinality(v_frontier_ids)]);
    END LOOP;

    RETURN QUERY
    WITH ep_entry AS (
        SELECT u.id, u.content, u.occurred_at, max(u.sim) AS sim
        FROM (
            (SELECT e.id, e.content, e.occurred_at,
                    (1 - (e.embedding <=> p_query_embedding))::double precision AS sim
             FROM memory.episodes e
             WHERE e.namespace = p_namespace
               AND p_query_embedding IS NOT NULL AND e.embedding IS NOT NULL
             ORDER BY e.embedding <=> p_query_embedding
             LIMIT v_entry)
            UNION ALL
            (SELECT e.id, e.content, e.occurred_at,
                    (ts_rank(e.search, v_tsq)
                     + CASE WHEN e.keywords && p_keywords THEN 0.5 ELSE 0 END)::double precision AS sim
             FROM memory.episodes e
             WHERE e.namespace = p_namespace
               AND p_keywords IS NOT NULL
               AND e.search @@ v_tsq
             ORDER BY sim DESC
             LIMIT v_entry)
        ) u
        GROUP BY u.id, u.content, u.occurred_at
    ),
    ep_scored AS (
        SELECT e.id, e.content, e.occurred_at,
               (e.sim * exp(-ln(2) * extract(epoch FROM (now() - e.occurred_at)) / v_halflife))::double precision AS score
        FROM ep_entry e
    ),
    nodes_ranked AS (
        SELECT a.node_id, max(a.score) AS score, min(a.hop) AS hops
        FROM unnest(v_acc_ids, v_acc_scores, v_acc_hops) AS a(node_id, score, hop)
        GROUP BY a.node_id
        ORDER BY max(a.score) DESC
        LIMIT v_max_nodes
    ),
    nodes_final AS (
        SELECT nr.node_id, n.kind, n.content, nr.score, nr.hops, n.recorded_at
        FROM nodes_ranked nr
        JOIN memory.nodes n
          ON n.namespace = p_namespace AND n.id = nr.node_id
    )
    SELECT h.source, h.id, h.kind, h.content, h.score, h.hops, h.occurred_at
    FROM (
        SELECT 'episode'::text AS source, e.id, NULL::text AS kind, e.content,
               e.score, 0 AS hops, e.occurred_at
        FROM ep_scored e
        UNION ALL
        SELECT 'node'::text, nf.node_id, nf.kind, nf.content,
               nf.score, nf.hops, nf.recorded_at
        FROM nodes_final nf
    ) h
    ORDER BY h.score DESC NULLS LAST, h.id
    LIMIT p_k;
END;
-- public is on the path so pgvector's type and operators resolve (see record).
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, public, pg_temp;


-- @function memory.neighbors
-- @brief Return the nodes one edge away from a node, in either direction.
-- @param p_namespace Tenant namespace
-- @param p_node Node whose neighbors to list
-- @param p_relation Optional relation filter ('entity', 'causal', 'assoc')
-- @returns node_id, relation, weight, direction ('out'|'in'), kind, content
-- @example SELECT * FROM memory.neighbors('default', 42);
--
-- One indexed pass over edges in both directions, joined to the neighbor node.
-- An application that wants iterative recall, where a model decides which
-- neighbor to follow next, calls this in a loop; the module embeds no
-- traversal policy.
CREATE OR REPLACE FUNCTION memory.neighbors(
    p_namespace text,
    p_node bigint,
    p_relation text DEFAULT NULL
)
RETURNS TABLE (
    node_id bigint,
    relation text,
    weight real,
    direction text,
    kind text,
    content text
) AS $$
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);
    IF p_relation IS NOT NULL THEN
        PERFORM memory._validate_relation(p_relation);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM memory.nodes n
        WHERE n.namespace = p_namespace AND n.id = p_node
          AND n.invalidated_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Node % not found', p_node
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:memory:DATA_NODE_NOT_FOUND';
    END IF;

    RETURN QUERY
    SELECT ed.to_node, ed.relation, ed.weight, 'out'::text, n.kind, n.content
    FROM memory.edges ed
    JOIN memory.nodes n ON n.namespace = p_namespace AND n.id = ed.to_node
    WHERE ed.namespace = p_namespace AND ed.from_node = p_node
      AND (p_relation IS NULL OR ed.relation = p_relation)
    UNION ALL
    SELECT ed.from_node, ed.relation, ed.weight, 'in'::text, n.kind, n.content
    FROM memory.edges ed
    JOIN memory.nodes n ON n.namespace = p_namespace AND n.id = ed.from_node
    WHERE ed.namespace = p_namespace AND ed.to_node = p_node
      AND (p_relation IS NULL OR ed.relation = p_relation);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;
