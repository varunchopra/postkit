-- =============================================================================
-- IMMUTABILITY ENFORCEMENT FOR POSTKIT/METER
-- =============================================================================
-- Ledger entries are append-only. Corrections use adjustment entries.

CREATE TRIGGER ledger_no_update
    BEFORE UPDATE ON meter.ledger
    FOR EACH ROW EXECUTE FUNCTION meter._enforce_ledger_immutability();

CREATE TRIGGER ledger_no_delete
    BEFORE DELETE ON meter.ledger
    FOR EACH ROW EXECUTE FUNCTION meter._enforce_ledger_immutability();

CREATE TRIGGER ledger_no_truncate
    BEFORE TRUNCATE ON meter.ledger
    FOR EACH STATEMENT EXECUTE FUNCTION meter._enforce_ledger_immutability();
