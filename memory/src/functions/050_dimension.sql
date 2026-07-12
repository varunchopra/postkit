-- @group Dimension

-- @function memory.set_dimension
-- @brief Fix the embedding dimension and build the vector search indexes.
-- @param p_dim Embedding dimension to set (1-16000)
-- @returns void
-- @example SELECT memory.set_dimension(1536);
--
-- A deployment-level operation, not tenant-scoped: it runs DDL (ALTER TABLE,
-- CREATE INDEX) and must be executed by a role that owns the tables, once,
-- after install and before embeddings are used at scale. The dimension is
-- stored only as the embedding columns' own type; this sets it. Setting the
-- same dimension again is a no-op; setting a different one after it is fixed
-- raises, because vectors of different dimension are not comparable and the
-- HNSW indexes (pgvector's approximate nearest-neighbor index) are already
-- built for the first choice.
CREATE OR REPLACE FUNCTION memory.set_dimension(p_dim int)
RETURNS void AS $$
DECLARE
    v_current int;
BEGIN
    IF p_dim IS NULL OR p_dim < 1 OR p_dim > 16000 THEN
        RAISE EXCEPTION 'Embedding dimension must be between 1 and 16000'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_DIMENSION_INVALID';
    END IF;

    v_current := memory._embedding_dim();
    IF v_current = p_dim THEN
        RETURN;
    END IF;
    IF v_current IS NOT NULL THEN
        RAISE EXCEPTION 'Embedding dimension is already set to %', v_current
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'postkit:memory:BIZ_DIMENSION_ALREADY_SET';
    END IF;

    -- The ALTER TYPE cast checks every stored vector, so its failure is the
    -- mismatch check. A pre-scan here could not be one: FORCE row-level
    -- security filters table reads by tenant context, the owner's included,
    -- so a count would miss offending rows in every other namespace.
    BEGIN
        EXECUTE format('ALTER TABLE memory.episodes ALTER COLUMN embedding TYPE vector(%s)', p_dim);
        EXECUTE format('ALTER TABLE memory.nodes ALTER COLUMN embedding TYPE vector(%s)', p_dim);
    EXCEPTION
        WHEN data_exception THEN
            RAISE EXCEPTION 'Cannot set dimension to %: %', p_dim, SQLERRM
                USING ERRCODE = 'data_exception',
                      HINT = 'postkit:memory:BIZ_DIMENSION_MISMATCH';
    END;

    EXECUTE 'CREATE INDEX episodes_embedding_hnsw ON memory.episodes USING hnsw (embedding vector_cosine_ops)';
    -- Partial over live nodes: supersession only invalidates rows, so a full
    -- index would accumulate dead vectors and waste nearest-neighbor
    -- candidates on rows recall always filters out.
    EXECUTE 'CREATE INDEX nodes_embedding_hnsw ON memory.nodes USING hnsw (embedding vector_cosine_ops) WHERE invalidated_at IS NULL';
END;
-- public is on the path so pgvector's type, vector_dims(), and the
-- vector_cosine_ops opclass resolve in the dynamic DDL (see record).
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = memory, public, pg_temp;
