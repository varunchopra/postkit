-- =============================================================================
-- CONFIGURATION
-- =============================================================================
-- System-wide constants exposed as functions. Changing these affects all
-- authorization operations.
--
-- Why functions instead of variables?
-- PostgreSQL doesn't have true constants. Using IMMUTABLE functions lets
-- the planner inline these values while keeping them in one place.

-- Default relation for group membership.
-- When a tuple grants to "team:engineering" without specifying a relation,
-- this is the relation used to find members of that team.
CREATE OR REPLACE FUNCTION authz.default_membership_relation()
RETURNS text AS $$
    SELECT 'member'::text;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;


-- Maximum recursion depth for nested group traversal.
-- Prevents infinite loops if cycles somehow get into the data.
-- 50 levels is generous - most real hierarchies are under 10.
CREATE OR REPLACE FUNCTION authz.max_group_depth()
RETURNS int AS $$
    SELECT 50::int;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;


-- Maximum recursion depth for resource hierarchy traversal.
-- Limits how deep parent relations are followed (doc → folder → root).
-- 50 levels is generous - most real hierarchies are under 10.
CREATE OR REPLACE FUNCTION authz.max_resource_depth()
RETURNS int AS $$
    SELECT 50::int;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;
