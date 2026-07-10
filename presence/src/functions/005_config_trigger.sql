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
        PERFORM presence._delegate_hook_queue_validation(NEW.on_death_queue);
    END IF;
    IF NEW.on_revival_queue IS NOT NULL THEN
        PERFORM presence._validate_hook_queue(NEW.on_revival_queue);
        PERFORM presence._delegate_hook_queue_validation(NEW.on_revival_queue);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;

-- @function presence._delegate_hook_queue_validation
-- @brief Run the installed queue module's own name check, if queue is installed.
-- Queue is an optional module installed from its own file, so its name
-- rules can differ from the rules presence applies locally. Running queue's
-- validator when the hook queue is configured means a bad name fails right
-- here, where someone can see it. The alternative is much worse: the name
-- is only used when an entity dies, the push to the queue fails inside the
-- sweep, and the sweep rolls the death back and retries forever, with
-- nothing but a warning in the logs. If queue is not installed (to_regproc
-- returns NULL, which also covers a renamed validator), presence's own
-- rules are the only check.
CREATE OR REPLACE FUNCTION presence._delegate_hook_queue_validation(p_value text)
RETURNS void AS $$
BEGIN
    IF to_regproc('queue._validate_queue_name') IS NOT NULL THEN
        EXECUTE 'SELECT queue._validate_queue_name($1)' USING p_value;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;

CREATE OR REPLACE TRIGGER presence_config_validate
    BEFORE INSERT OR UPDATE ON presence.config
    FOR EACH ROW EXECUTE FUNCTION presence._validate_config();
