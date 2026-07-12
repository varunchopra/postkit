-- @group Recording

-- @function memory.record
-- @brief Append one episode to the interaction log.
-- @param p_namespace Tenant namespace
-- @param p_session Session identifier the episode belongs to
-- @param p_role Message role (e.g. 'user', 'assistant', 'tool')
-- @param p_content Raw message or event text
-- @param p_embedding Optional embedding of the content (paired with p_embed_model)
-- @param p_embed_model Model that produced the embedding (required iff p_embedding is set)
-- @param p_keywords Optional keyword array for the lexical recall arm
-- @param p_occurred_at When the episode happened (defaults to now())
-- @param p_metadata Optional JSON metadata
-- @returns The new episode id
-- @example SELECT memory.record('default', 's1', 'user', 'hello', NULL, NULL, ARRAY['hello']);
--
-- The hot path and design principle 1: a single INSERT that never touches
-- nodes or edges. Embedding and its model are stored together or not at all
-- (the caller's model runs outside the database). When notify_on_record is
-- enabled for the namespace, a NOTIFY on memory.channel_name fires so a
-- consolidation worker can wake; consolidation_due() stays the source of truth.
CREATE OR REPLACE FUNCTION memory.record(
    p_namespace text,
    p_session text,
    p_role text,
    p_content text,
    p_embedding vector DEFAULT NULL,
    p_embed_model text DEFAULT NULL,
    p_keywords text[] DEFAULT NULL,
    p_occurred_at timestamptz DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_dim int;
    v_id bigint;
    v_actor record;
    v_notify boolean;
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._validate_session(p_session);
    PERFORM memory._validate_role(p_role);
    PERFORM memory._validate_content(p_content);
    IF p_embed_model IS NOT NULL THEN
        PERFORM memory._validate_embed_model(p_embed_model);
    END IF;

    PERFORM memory._warn_namespace_mismatch(p_namespace);

    -- Mirror the episodes_embedding_model_paired CHECK so a mismatch surfaces
    -- as a postkit error code rather than a bare constraint violation.
    IF (p_embedding IS NULL) != (p_embed_model IS NULL) THEN
        RAISE EXCEPTION 'Embedding and embed_model must be provided together'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:BIZ_EMBED_MODEL_REQUIRED';
    END IF;

    IF p_embedding IS NOT NULL THEN
        v_dim := memory._embedding_dim();
        IF v_dim IS NOT NULL AND vector_dims(p_embedding) != v_dim THEN
            RAISE EXCEPTION 'Embedding has % dimensions but the store is fixed at %',
                vector_dims(p_embedding), v_dim
                USING ERRCODE = 'data_exception',
                      HINT = 'postkit:memory:BIZ_EMBEDDING_DIMENSION_MISMATCH';
        END IF;
    END IF;

    SELECT * INTO v_actor FROM memory._get_actor_context();

    INSERT INTO memory.episodes (
        namespace, session_id, role, content, embedding, embed_model,
        keywords, occurred_at, metadata,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_namespace, p_session, p_role, p_content, p_embedding, p_embed_model,
        COALESCE(p_keywords, '{}'), COALESCE(p_occurred_at, now()),
        COALESCE(p_metadata, '{}'),
        v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
    )
    RETURNING id INTO v_id;

    -- The tenant's own row wins over the global default.
    SELECT c.notify_on_record INTO v_notify
    FROM memory.config c
    WHERE c.namespace IN (p_namespace, 'global')
    ORDER BY c.namespace = p_namespace DESC
    LIMIT 1;
    IF COALESCE(v_notify, false) THEN
        PERFORM pg_notify(memory.channel_name(p_namespace), jsonb_build_object(
            'episode_id', v_id,
            'session', p_session
        )::text);
    END IF;

    RETURN v_id;
END;
-- public is on the path so pgvector's type, operators, and vector_dims() (which
-- the extension installs into its own schema) resolve; the module never depends
-- on anything else in public.
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = memory, public, pg_temp;
