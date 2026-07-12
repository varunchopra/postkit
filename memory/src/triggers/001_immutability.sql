-- =============================================================================
-- IMMUTABILITY ENFORCEMENT FOR POSTKIT/MEMORY (M1)
-- =============================================================================
-- Episodes are append-only. The one legal UPDATE flips consolidated_at from
-- NULL to a timestamp (consolidate() marks a batch done); every other column
-- must be unchanged. DELETE is allowed: retention is the deployer's policy.

CREATE FUNCTION memory._episodes_immutable()
RETURNS TRIGGER AS $$
BEGIN
    -- Allow only the consolidation stamp, and only from NULL. The whole-row
    -- comparison covers columns added after this trigger was written, so a
    -- schema change cannot silently open a mutable column. Two columns are
    -- removed from both sides: consolidated_at (the one legal change) and
    -- search (a generated column, a pure function of the compared content,
    -- not yet populated in NEW during a BEFORE trigger).
    IF OLD.consolidated_at IS NULL
       AND to_jsonb(NEW) - 'consolidated_at' - 'search'
           = to_jsonb(OLD) - 'consolidated_at' - 'search' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Episodes are immutable; only consolidated_at may be set once, from NULL'
        USING ERRCODE = 'object_not_in_prerequisite_state',
              HINT = 'postkit:memory:DATA_EPISODE_IMMUTABLE';
END;
$$ LANGUAGE plpgsql SET search_path = memory, pg_temp;

CREATE TRIGGER episodes_immutable
    BEFORE UPDATE ON memory.episodes
    FOR EACH ROW EXECUTE FUNCTION memory._episodes_immutable();
