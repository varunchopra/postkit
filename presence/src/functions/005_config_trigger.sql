-- @group Config

-- @function presence._validate_config
-- @brief Trigger: reject a config row whose hook queue names are malformed.
-- presence.config is written by DML, so hook-queue validation lives in a
-- BEFORE trigger rather than a setter function. A bad on_death_queue or
-- on_revival_queue is rejected at write time instead of sitting latent until
-- the hook fires at sweep, far from its cause.
CREATE OR REPLACE FUNCTION presence._validate_config()
RETURNS trigger AS $$
BEGIN
    IF NEW.on_death_queue IS NOT NULL THEN
        PERFORM presence._validate_hook_queue(NEW.on_death_queue);
    END IF;
    IF NEW.on_revival_queue IS NOT NULL THEN
        PERFORM presence._validate_hook_queue(NEW.on_revival_queue);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;

CREATE OR REPLACE TRIGGER presence_config_validate
    BEFORE INSERT OR UPDATE ON presence.config
    FOR EACH ROW EXECUTE FUNCTION presence._validate_config();
