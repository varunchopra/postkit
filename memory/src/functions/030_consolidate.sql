-- @group Consolidation

-- @function memory.consolidation_due
-- @brief Surface unconsolidated episodes for a distillation worker to process.
-- @param p_namespace Tenant namespace
-- @param p_batch_size Maximum episodes to return (defaults to config.consolidation_batch_size)
-- @returns id, session_id, role, content, occurred_at for each due episode, oldest first
-- @example SELECT * FROM memory.consolidation_due('default');
--
-- Read-only, served by episodes_unconsolidated_idx. Claiming and serialization
-- are the worker's job (hold a lease and heartbeat through presence); this
-- function only reports what is due and never mutates. The LLM distillation
-- runs in the application; its output comes back through memory.consolidate.
CREATE OR REPLACE FUNCTION memory.consolidation_due(
    p_namespace text,
    p_batch_size int DEFAULT NULL
)
RETURNS TABLE (
    id bigint,
    session_id text,
    role text,
    content text,
    occurred_at timestamptz
) AS $$
DECLARE
    v_config memory.config;
    v_limit int;
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);
    IF p_batch_size IS NOT NULL THEN
        PERFORM memory._validate_positive_int(p_batch_size, 'batch_size');
    END IF;

    v_config := memory._get_config(p_namespace);
    v_limit := COALESCE(p_batch_size, v_config.consolidation_batch_size);

    RETURN QUERY
    SELECT e.id, e.session_id, e.role, e.content, e.occurred_at
    FROM memory.episodes e
    WHERE e.namespace = p_namespace AND e.consolidated_at IS NULL
    ORDER BY e.id
    LIMIT v_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory.consolidate
-- @brief Apply a distillation batch: insert facts and entities, link edges, mark episodes.
-- @param p_namespace Tenant namespace
-- @param p_facts JSON array of fact elements (see below)
-- @param p_edges JSON array of edge elements (see below)
-- @param p_source_episodes Episode ids the batch was distilled from
-- @param p_idempotency_key Optional replay key; a repeat with the same key is a no-op (M3)
-- @returns node_ids (inserted or matched, in fact order) and skipped (true on replay)
--
-- Everything happens in one transaction. Fact element:
--   {"content": text (required), "kind": 'fact'|'entity' (default 'fact'),
--    "embedding": [floats] (optional), "embed_model": text (required iff
--    embedding present), "confidence": float (optional), "valid_from":
--    timestamptz (optional), "valid_until": timestamptz (optional),
--    "evidence": [episode ids] (optional; defaults to p_source_episodes)}.
-- Entities dedup by content (upsert on the live-entity unique index), so the
-- same entity across batches resolves to one node id. Edge element:
--   {"from": <node id | "n<i>" referencing the i-th fact, 0-based>,
--    "to": <same>, "relation": 'entity'|'causal'|'assoc',
--    "weight": float (optional, default 1.0)}.
-- Edge upserts keep the greater weight on conflict. M3: an idempotency key that
-- already has a consolidations row short-circuits to (ARRAY[], true).
CREATE OR REPLACE FUNCTION memory.consolidate(
    p_namespace text,
    p_facts jsonb,
    p_edges jsonb,
    p_source_episodes bigint[],
    p_idempotency_key text DEFAULT NULL
)
RETURNS TABLE (node_ids bigint[], skipped boolean) AS $$
DECLARE
    v_dim int;
    v_actor record;
    v_fact jsonb;
    v_edge jsonb;
    v_kind text;
    v_content text;
    v_embedding vector;
    v_embed_model text;
    v_confidence real;
    v_valid_from timestamptz;
    v_valid_until timestamptz;
    v_evidence bigint[];
    v_node_id bigint;
    v_node_ids bigint[] := '{}';
    v_from bigint;
    v_to bigint;
    v_relation text;
    v_weight real;
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);

    -- M3: a replay with a seen key is a no-op.
    IF p_idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM memory.consolidations c
        WHERE c.namespace = p_namespace AND c.idempotency_key = p_idempotency_key
    ) THEN
        RETURN QUERY SELECT ARRAY[]::bigint[], true;
        RETURN;
    END IF;

    -- Every source episode must exist in this namespace.
    IF p_source_episodes IS NOT NULL AND EXISTS (
        SELECT 1 FROM unnest(p_source_episodes) AS s(eid)
        WHERE NOT EXISTS (
            SELECT 1 FROM memory.episodes e
            WHERE e.namespace = p_namespace AND e.id = s.eid
        )
    ) THEN
        RAISE EXCEPTION 'One or more source episodes not found in namespace'
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:memory:DATA_EPISODE_NOT_FOUND';
    END IF;

    v_dim := memory._embedding_dim();
    SELECT * INTO v_actor FROM memory._get_actor_context();

    -- Insert facts in order, recording the resulting node id for each so edge
    -- "n<i>" references can resolve against fact position.
    FOR v_fact IN SELECT * FROM jsonb_array_elements(COALESCE(p_facts, '[]'::jsonb))
    LOOP
        v_kind := COALESCE(v_fact->>'kind', 'fact');
        v_content := v_fact->>'content';

        IF v_content IS NULL OR trim(v_content) = '' THEN
            RAISE EXCEPTION 'Fact element missing content'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_FACT_MALFORMED';
        END IF;
        PERFORM memory._validate_kind(v_kind);

        v_embed_model := v_fact->>'embed_model';
        IF v_fact ? 'embedding' AND jsonb_typeof(v_fact->'embedding') = 'array' THEN
            v_embedding := (v_fact->>'embedding')::vector;
        ELSE
            v_embedding := NULL;
        END IF;

        IF (v_embedding IS NULL) != (v_embed_model IS NULL) THEN
            RAISE EXCEPTION 'Fact embedding and embed_model must be provided together'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_FACT_MALFORMED';
        END IF;
        IF v_embedding IS NOT NULL AND v_dim IS NOT NULL
           AND vector_dims(v_embedding) != v_dim THEN
            RAISE EXCEPTION 'Fact embedding has % dimensions but the store is fixed at %',
                vector_dims(v_embedding), v_dim
                USING ERRCODE = 'data_exception',
                      HINT = 'postkit:memory:BIZ_EMBEDDING_DIMENSION_MISMATCH';
        END IF;

        v_confidence := (v_fact->>'confidence')::real;
        v_valid_from := COALESCE((v_fact->>'valid_from')::timestamptz, now());
        v_valid_until := (v_fact->>'valid_until')::timestamptz;
        IF v_fact ? 'evidence' AND jsonb_typeof(v_fact->'evidence') = 'array' THEN
            v_evidence := ARRAY(SELECT jsonb_array_elements_text(v_fact->'evidence')::bigint);
        ELSE
            v_evidence := COALESCE(p_source_episodes, '{}');
        END IF;

        -- One INSERT serves both kinds: the conflict target is the
        -- live-entity partial unique index, which fact rows never enter, so
        -- only entities dedup by content. The no-op SET returns the existing
        -- id for a duplicate entity.
        INSERT INTO memory.nodes (
            namespace, kind, content, embedding, embed_model, confidence,
            valid_from, valid_until, evidence,
            actor_id, request_id, on_behalf_of, reason
        )
        VALUES (
            p_namespace, v_kind, v_content, v_embedding, v_embed_model, v_confidence,
            v_valid_from, v_valid_until, v_evidence,
            v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
        )
        ON CONFLICT (namespace, content) WHERE kind = 'entity' AND invalidated_at IS NULL
        DO UPDATE SET recorded_at = memory.nodes.recorded_at
        RETURNING id INTO v_node_id;

        v_node_ids := v_node_ids || v_node_id;
    END LOOP;

    FOR v_edge IN SELECT * FROM jsonb_array_elements(COALESCE(p_edges, '[]'::jsonb))
    LOOP
        v_from := memory._resolve_edge_ref(p_namespace, v_edge->'from', v_node_ids);
        v_to := memory._resolve_edge_ref(p_namespace, v_edge->'to', v_node_ids);
        v_relation := v_edge->>'relation';
        PERFORM memory._validate_relation(v_relation);
        v_weight := COALESCE((v_edge->>'weight')::real, 1.0);

        INSERT INTO memory.edges (namespace, from_node, to_node, relation, weight)
        VALUES (p_namespace, v_from, v_to, v_relation, v_weight)
        ON CONFLICT (namespace, from_node, to_node, relation)
        DO UPDATE SET weight = GREATEST(memory.edges.weight, EXCLUDED.weight);
    END LOOP;

    -- Mark the source episodes consolidated (legal under M1: NULL -> now()).
    UPDATE memory.episodes
    SET consolidated_at = now()
    WHERE namespace = p_namespace
      AND id = ANY(COALESCE(p_source_episodes, '{}'))
      AND consolidated_at IS NULL;

    IF p_idempotency_key IS NOT NULL THEN
        INSERT INTO memory.consolidations (namespace, idempotency_key)
        VALUES (p_namespace, p_idempotency_key);
    END IF;

    RETURN QUERY SELECT v_node_ids, false;
END;
-- public is on the path so pgvector's type and vector_dims() resolve (see record).
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = memory, public, pg_temp;
