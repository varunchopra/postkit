-- =============================================================================
-- IMMUTABILITY ENFORCEMENT FOR POSTKIT/METER
-- =============================================================================
-- Ledger entries are append-only. Corrections use adjustment entries.

CREATE FUNCTION meter._enforce_ledger_immutability()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Ledger entries are immutable. Use meter.adjust() for corrections.'
        USING ERRCODE = 'restrict_violation',
              HINT = 'postkit:meter:BIZ_LEDGER_IMMUTABLE';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ledger_no_update
    BEFORE UPDATE ON meter.ledger
    FOR EACH ROW EXECUTE FUNCTION meter._enforce_ledger_immutability();

CREATE TRIGGER ledger_no_delete
    BEFORE DELETE ON meter.ledger
    FOR EACH ROW EXECUTE FUNCTION meter._enforce_ledger_immutability();
