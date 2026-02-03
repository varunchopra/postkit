-- @group Internal

-- @function queue._cron_parse_field
-- @brief Parse a single cron field into a sorted array of valid integers.
-- @param p_field Cron field string (e.g., '*/5', '1-10/3', '1,3,5', '*', '5')
-- @param p_min Minimum valid value for this field
-- @param p_max Maximum valid value for this field
-- @returns Sorted array of integers matching the field expression
CREATE OR REPLACE FUNCTION queue._cron_parse_field(
    p_field text,
    p_min int,
    p_max int
)
RETURNS int[] AS $$
DECLARE
    v_result int[] := '{}';
    v_term text;
    v_base text;
    v_step int;
    v_low int;
    v_high int;
    v_val int;
    v_slash_pos int;
    v_dash_pos int;
BEGIN
    -- Split by comma and process each term
    FOREACH v_term IN ARRAY string_to_array(p_field, ',')
    LOOP
        -- Check for step: base/step
        v_slash_pos := position('/' in v_term);
        IF v_slash_pos > 0 THEN
            v_base := substring(v_term from 1 for v_slash_pos - 1);
            v_step := substring(v_term from v_slash_pos + 1)::int;
        ELSE
            v_base := v_term;
            v_step := 1;
        END IF;

        IF v_base = '*' THEN
            -- Wildcard: generate from min to max with step
            FOR v_val IN SELECT generate_series(p_min, p_max, v_step)
            LOOP
                v_result := v_result || v_val;
            END LOOP;
        ELSE
            -- Check for range: low-high
            v_dash_pos := position('-' in v_base);
            IF v_dash_pos > 0 THEN
                v_low := substring(v_base from 1 for v_dash_pos - 1)::int;
                v_high := substring(v_base from v_dash_pos + 1)::int;
                -- Reverse ranges like '5-1' produce an empty series
                -- (generate_series(5,1) returns nothing). This is intentional:
                -- silently ignored rather than erroring, matching standard cron
                -- implementations.
                FOR v_val IN SELECT generate_series(v_low, v_high, v_step)
                LOOP
                    v_result := v_result || v_val;
                END LOOP;
            ELSE
                -- Single value
                v_result := v_result || v_base::int;
            END IF;
        END IF;
    END LOOP;

    -- Deduplicate and sort
    SELECT array_agg(DISTINCT val ORDER BY val)
    INTO v_result
    FROM unnest(v_result) AS val
    WHERE val >= p_min AND val <= p_max;

    RETURN COALESCE(v_result, '{}');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._cron_next_run
-- @brief Calculate the next run time for a 5-field cron expression.
-- @param p_cron 5-field cron expression (minute hour day month weekday)
-- @param p_timezone Timezone name for cron evaluation
-- @param p_base Base time to search from (next run will be strictly after this)
-- @returns Next matching timestamptz, or NULL if no match found within 4 years
--
-- Uses smart field advancement: instead of iterating every minute, advances
-- each field (month, day, hour, minute) to the next valid value. Day matching
-- follows POSIX semantics: if both day-of-month and day-of-week are restricted,
-- a day matches if EITHER condition is satisfied.
CREATE OR REPLACE FUNCTION queue._cron_next_run(
    p_cron text,
    p_timezone text,
    p_base timestamptz
)
RETURNS timestamptz AS $$
DECLARE
    v_fields text[];
    v_minutes int[];
    v_hours int[];
    v_days_of_month int[];
    v_months int[];
    v_days_of_week int[];
    v_dom_restricted boolean;
    v_dow_restricted boolean;
    v_year int;
    v_month int;
    v_day int;
    v_hour int;
    v_minute int;
    v_local timestamp;
    v_max_day int;
    v_dow int;
    v_day_matches boolean;
    v_found boolean;
    v_iter int := 0;
    v_max_iter int := 1464; -- 4 years of days
    v_next_val int;
BEGIN
    -- Parse cron fields
    v_fields := string_to_array(trim(regexp_replace(p_cron, '\s+', ' ', 'g')), ' ');

    v_minutes := queue._cron_parse_field(v_fields[1], 0, 59);
    v_hours := queue._cron_parse_field(v_fields[2], 0, 23);
    v_days_of_month := queue._cron_parse_field(v_fields[3], 1, 31);
    v_months := queue._cron_parse_field(v_fields[4], 1, 12);
    v_days_of_week := queue._cron_parse_field(v_fields[5], 0, 6);

    -- Detect whether day-of-month and day-of-week are restricted (not '*').
    -- POSIX: if both are restricted, a day matches if EITHER is satisfied.
    -- If only one is restricted, only that one applies.
    v_dom_restricted := (v_fields[3] != '*');
    v_dow_restricted := (v_fields[5] != '*');

    -- Start from base + 1 minute in target timezone
    v_local := (p_base AT TIME ZONE p_timezone) + interval '1 minute';
    v_local := date_trunc('minute', v_local);

    v_year := extract(year from v_local)::int;
    v_month := extract(month from v_local)::int;
    v_day := extract(day from v_local)::int;
    v_hour := extract(hour from v_local)::int;
    v_minute := extract(minute from v_local)::int;

    <<outer_loop>>
    LOOP
        v_iter := v_iter + 1;
        IF v_iter > v_max_iter THEN
            RETURN NULL; -- No match within 4 years
        END IF;

        -- Step 1: Find next valid month
        v_found := false;
        FOREACH v_next_val IN ARRAY v_months
        LOOP
            IF v_next_val >= v_month THEN
                IF v_next_val > v_month THEN
                    -- Jumped to a later month; reset day/hour/minute
                    v_month := v_next_val;
                    v_day := v_days_of_month[1];
                    v_hour := v_hours[1];
                    v_minute := v_minutes[1];
                END IF;
                v_found := true;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_found THEN
            -- Wrap to next year
            v_year := v_year + 1;
            v_month := v_months[1];
            v_day := v_days_of_month[1];
            v_hour := v_hours[1];
            v_minute := v_minutes[1];
            CONTINUE outer_loop;
        END IF;

        -- Step 2: Find next valid day
        -- First, determine how many days in this month
        v_max_day := extract(day from
            (make_date(v_year, v_month, 1) + interval '1 month' - interval '1 day'))::int;

        v_found := false;
        WHILE v_day <= v_max_day LOOP
            -- Check if this day matches the cron day constraints
            v_dow := extract(isodow from make_date(v_year, v_month, v_day))::int % 7;
            -- PostgreSQL isodow: Monday=1..Sunday=7; cron: Sunday=0..Saturday=6
            -- So isodow % 7 gives: Monday=1..Saturday=6, Sunday=0

            IF v_dom_restricted AND v_dow_restricted THEN
                -- POSIX OR: match if day-of-month OR day-of-week matches
                v_day_matches := (v_day = ANY(v_days_of_month)) OR (v_dow = ANY(v_days_of_week));
            ELSIF v_dom_restricted THEN
                v_day_matches := (v_day = ANY(v_days_of_month));
            ELSIF v_dow_restricted THEN
                v_day_matches := (v_dow = ANY(v_days_of_week));
            ELSE
                -- Both unrestricted (both *): any day matches
                v_day_matches := true;
            END IF;

            IF v_day_matches THEN
                v_found := true;
                EXIT;
            END IF;

            v_day := v_day + 1;
            v_hour := v_hours[1];
            v_minute := v_minutes[1];
        END LOOP;

        IF NOT v_found THEN
            -- No valid day in this month; advance to next month
            v_month := v_month + 1;
            v_day := 1;
            v_hour := v_hours[1];
            v_minute := v_minutes[1];
            IF v_month > 12 THEN
                v_month := 1;
                v_year := v_year + 1;
            END IF;
            CONTINUE outer_loop;
        END IF;

        -- Step 3: Find next valid hour
        v_found := false;
        FOREACH v_next_val IN ARRAY v_hours
        LOOP
            IF v_next_val >= v_hour THEN
                IF v_next_val > v_hour THEN
                    v_hour := v_next_val;
                    v_minute := v_minutes[1];
                END IF;
                v_found := true;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_found THEN
            -- Wrap to next day
            v_day := v_day + 1;
            v_hour := v_hours[1];
            v_minute := v_minutes[1];
            CONTINUE outer_loop;
        END IF;

        -- Step 4: Find next valid minute
        v_found := false;
        FOREACH v_next_val IN ARRAY v_minutes
        LOOP
            IF v_next_val >= v_minute THEN
                v_minute := v_next_val;
                v_found := true;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_found THEN
            -- Wrap to next hour
            v_hour := v_hour + 1;
            v_minute := v_minutes[1];
            CONTINUE outer_loop;
        END IF;

        -- All fields matched. Construct the timestamp.
        RETURN make_timestamptz(v_year, v_month, v_day, v_hour, v_minute, 0, p_timezone);
    END LOOP;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;
