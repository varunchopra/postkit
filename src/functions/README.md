# Functions

Files are concatenated in alphabetical order during build, so numbering matters.

## Layers

```
000-009  Layer 0: Foundation  - no authz dependencies
010-019  Layer 1: Helpers     - depends on Layer 0
020-029  Layer 2: Core Ops    - depends on Layers 0-1
030-039  Layer 3: Management  - depends on Layers 0-2
```

Each layer can only call functions from lower-numbered layers.

## Files

```
000_config.sql           constants (_max_group_depth, _max_resource_depth)
001_validation.sql       input validation (_validate_identifier, _validate_id, _validate_id_array, _validate_namespace)

010_helpers.sql          _expand_user_memberships, _expand_resource_*
011_cycle_detection.sql  _would_create_cycle, _would_create_resource_cycle, _detect_cycles, _detect_resource_cycles

020_write.sql            write_tuple, write, write_tuples_bulk
021_delete.sql           delete_tuple, delete
022_check.sql            check, check_any, check_all
023_list.sql             list_resources, list_users, filter_authorized
024_explain.sql          explain, explain_text

030_hierarchy.sql        add_hierarchy, remove_hierarchy
031_expiration.sql       set_expiration, cleanup_expired, list_expiring
032_maintenance.sql      get_stats, verify_integrity, grant_to_resources_bulk
033_audit.sql            set_actor, partition management
034_rls.sql              set_tenant
```

## Adding Files

Pick a number in the appropriate layer range. The gaps (e.g., 002-009) leave
room for new files without renumbering.
