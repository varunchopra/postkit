-- @group Internal

CREATE FUNCTION meter._enforce_ledger_immutability()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Ledger entries are immutable. Use meter.adjust() for corrections.'
        USING ERRCODE = 'restrict_violation',
              HINT = 'postkit:meter:BIZ_LEDGER_IMMUTABLE';
END;
$$ LANGUAGE plpgsql;
