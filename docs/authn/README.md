# Authn API Reference

## Python SDK

| Function | Description |
|----------|-------------|
| [`add_credential`](sdk.md#add_credential) | Add a credential for a user. |
| [`cleanup_expired`](sdk.md#cleanup_expired) | Clean up expired sessions, tokens, impersonation records, and old login attempts. |
| [`clear_actor`](sdk.md#clear_actor) | Clear actor context. |
| [`clear_attempts`](sdk.md#clear_attempts) | Clear login attempts for an email. Returns count deleted. |
| [`consume_credential`](sdk.md#consume_credential) | Consume a one-time credential (e.g., recovery code). |
| [`consume_token`](sdk.md#consume_token) | Consume a one-time token. |
| [`create_api_key`](sdk.md#create_api_key) | Create an API key for programmatic access. |
| [`create_refresh_token`](sdk.md#create_refresh_token) | Create a refresh token for a session. |
| [`create_session`](sdk.md#create_session) | Create a new session. |
| [`create_token`](sdk.md#create_token) | Create a one-time use token. |
| [`create_user`](sdk.md#create_user) | Create a new user. |
| [`delete_user`](sdk.md#delete_user) | Permanently delete a user and all associated data. |
| [`disable_all_credentials`](sdk.md#disable_all_credentials) | Disable all credentials for a user (incident response). |
| [`disable_credential`](sdk.md#disable_credential) | Soft-disable a credential (preserves for forensics). |
| [`disable_user`](sdk.md#disable_user) | Disable user and revoke all their sessions. |
| [`enable_user`](sdk.md#enable_user) | Re-enable a disabled user. |
| [`end_impersonation`](sdk.md#end_impersonation) | End an impersonation session early. |
| [`end_operator_impersonation`](sdk.md#end_operator_impersonation) | End an operator impersonation session early. |
| [`extend_session`](sdk.md#extend_session) | Extend session expiration. |
| [`get_api_key`](sdk.md#get_api_key) | Get an API key by ID if owned by user. |
| [`get_audit_events`](sdk.md#get_audit_events) | Query audit events with optional filters. |
| [`get_credential_by_lookup`](sdk.md#get_credential_by_lookup) | Lookup a credential by key. Requires user_id for enumeration safety. |
| [`get_credentials`](sdk.md#get_credentials) | Get credentials for login verification. |
| [`get_impersonation_context`](sdk.md#get_impersonation_context) | Check if a session is an impersonation session. |
| [`get_operator_audit_events`](sdk.md#get_operator_audit_events) | Query operator audit events. |
| [`get_operator_impersonation_context`](sdk.md#get_operator_impersonation_context) | Check if a session is an operator impersonation session. |
| [`get_or_create_user`](sdk.md#get_or_create_user) | Atomically get existing user or create new one. |
| [`get_recent_attempts`](sdk.md#get_recent_attempts) | Get recent login attempts for an email. |
| [`get_stats`](sdk.md#get_stats) | Get namespace statistics. |
| [`get_user`](sdk.md#get_user) | Get user by ID. Does not return password_hash. |
| [`get_user_by_email`](sdk.md#get_user_by_email) | Get user by email. Does not return password_hash. |
| [`get_user_credentials`](sdk.md#get_user_credentials) | Get active credentials for verification. Returns secrets! |
| [`get_users_batch`](sdk.md#get_users_batch) | Get multiple users by ID in a single query. |
| [`has_credential`](sdk.md#has_credential) | Check if user has active credential of a specific type. |
| [`invalidate_tokens`](sdk.md#invalidate_tokens) | Invalidate all unused tokens of a type for a user. |
| [`is_locked_out`](sdk.md#is_locked_out) | Check if an email is locked out due to too many failed attempts. |
| [`list_active_impersonations`](sdk.md#list_active_impersonations) | List all active impersonations in the namespace. |
| [`list_active_operator_impersonations`](sdk.md#list_active_operator_impersonations) | List all active operator impersonations. |
| [`list_api_keys`](sdk.md#list_api_keys) | List active API keys for a user. Does not return key_hash. |
| [`list_impersonation_history`](sdk.md#list_impersonation_history) | List impersonation history for audit purposes. |
| [`list_operator_impersonations_by_operator`](sdk.md#list_operator_impersonations_by_operator) | List impersonations performed by an operator. |
| [`list_operator_impersonations_for_target`](sdk.md#list_operator_impersonations_for_target) | List operator impersonation history affecting a target namespace. |
| [`list_refresh_tokens`](sdk.md#list_refresh_tokens) | List active refresh tokens for a user. |
| [`list_sessions`](sdk.md#list_sessions) | List active sessions for a user. Does not return token_hash. |
| [`list_user_credentials`](sdk.md#list_user_credentials) | List credentials for settings UI. Does NOT return secrets. |
| [`list_users`](sdk.md#list_users) | List users with pagination. |
| [`record_credential_use`](sdk.md#record_credential_use) | Record credential usage (lazy update: only if >1hr since last). |
| [`record_login_attempt`](sdk.md#record_login_attempt) | Record a login attempt. |
| [`remove_credential`](sdk.md#remove_credential) | Hard-delete a credential (user self-service). |
| [`revoke_all_api_keys`](sdk.md#revoke_all_api_keys) | Revoke all API keys for a user. Returns count revoked. |
| [`revoke_all_refresh_tokens`](sdk.md#revoke_all_refresh_tokens) | Revoke all refresh tokens for a user. |
| [`revoke_all_sessions`](sdk.md#revoke_all_sessions) | Revoke all sessions for a user. Returns count revoked. |
| [`revoke_api_key`](sdk.md#revoke_api_key) | Revoke an API key. |
| [`revoke_other_sessions`](sdk.md#revoke_other_sessions) | Revoke all sessions except the specified one ("sign out other devices"). |
| [`revoke_refresh_token_family`](sdk.md#revoke_refresh_token_family) | Revoke all tokens in a family (security response). |
| [`revoke_session`](sdk.md#revoke_session) | Revoke a session. |
| [`revoke_session_by_id`](sdk.md#revoke_session_by_id) | Revoke a session by ID (for manage devices UI). |
| [`rotate_refresh_token`](sdk.md#rotate_refresh_token) | Rotate a refresh token (invalidate old, issue new). |
| [`set_actor`](sdk.md#set_actor) | Set actor context for audit logging. Only updates fields that are passed. |
| [`start_impersonation`](sdk.md#start_impersonation) | Start impersonating a user. |
| [`start_operator_impersonation`](sdk.md#start_operator_impersonation) | Start cross-namespace operator impersonation. |
| [`update_email`](sdk.md#update_email) | Update user's email. Clears email_verified_at. |
| [`update_password`](sdk.md#update_password) | Update user's password hash. |
| [`update_sign_count`](sdk.md#update_sign_count) | Update WebAuthn sign count. Returns False if clone detected. |
| [`validate_api_key`](sdk.md#validate_api_key) | Validate an API key. |
| [`validate_refresh_token`](sdk.md#validate_refresh_token) | Validate a refresh token without rotating (read-only check). |
| [`validate_session`](sdk.md#validate_session) | Validate a session token. |
| [`verify_email`](sdk.md#verify_email) | Verify email using a token. |

## SQL Functions

| Function | Description |
|----------|-------------|
| [`authn.create_api_key`](sql.md#authncreate_api_key) | Create an API key for programmatic access |
| [`authn.get_api_key`](sql.md#authnget_api_key) | Get a single API key by ID if owned by user (for ownership verification) |
| [`authn.list_api_keys`](sql.md#authnlist_api_keys) | List API keys for a user (for management UI) |
| [`authn.revoke_all_api_keys`](sql.md#authnrevoke_all_api_keys) | Revoke all API keys for a user |
| [`authn.revoke_api_key`](sql.md#authnrevoke_api_key) | Revoke an API key |
| [`authn.validate_api_key`](sql.md#authnvalidate_api_key) | Validate an API key and get owner info (hot path) |
| [`authn.clear_actor`](sql.md#authnclear_actor) | Clear actor context |
| [`authn.create_audit_partition`](sql.md#authncreate_audit_partition) | Create a monthly partition for audit events |
| [`authn.drop_audit_partitions`](sql.md#authndrop_audit_partitions) | Delete old audit partitions (default: keep 7 years for compliance) |
| [`authn.ensure_audit_partitions`](sql.md#authnensure_audit_partitions) | Create partitions for upcoming months (run monthly via cron) |
| [`authn.set_actor`](sql.md#authnset_actor) | Tag audit events with who made the change (call before user operations) |
| [`authn.add_credential`](sql.md#authnadd_credential) | Add a credential (TOTP, WebAuthn, or recovery code) |
| [`authn.consume_credential`](sql.md#authnconsume_credential) | Consume a one-time credential (e.g., recovery code) |
| [`authn.disable_all_credentials`](sql.md#authndisable_all_credentials) | Bulk disable all credentials for a user (incident response) |
| [`authn.disable_credential`](sql.md#authndisable_credential) | Soft-disable a credential (preserves for forensics) |
| [`authn.get_credential_by_lookup`](sql.md#authnget_credential_by_lookup) | Lookup a credential by its lookup_key (requires user context for security) |
| [`authn.get_credentials`](sql.md#authnget_credentials) | Get password hash for login verification (only function that returns hash) |
| [`authn.get_credentials`](sql.md#authnget_credentials) | Get active credentials for verification (returns secrets) |
| [`authn.has_credential`](sql.md#authnhas_credential) | Check if user has active credential of a specific type |
| [`authn.list_credentials`](sql.md#authnlist_credentials) | List credentials for settings UI (no secrets exposed) |
| [`authn.record_credential_use`](sql.md#authnrecord_credential_use) | Record credential usage (updates last_used_at) |
| [`authn.remove_credential`](sql.md#authnremove_credential) | Hard-delete a credential (user self-service) |
| [`authn.update_password`](sql.md#authnupdate_password) | Update user's password hash (after password change or reset) |
| [`authn.update_sign_count`](sql.md#authnupdate_sign_count) | Update WebAuthn sign count (clone detection) |
| [`authn.end_impersonation`](sql.md#authnend_impersonation) | End an impersonation session early (revokes the impersonation session) |
| [`authn.get_impersonation_context`](sql.md#authnget_impersonation_context) | Get impersonation context for a session (is this an impersonated session?) |
| [`authn.list_active_impersonations`](sql.md#authnlist_active_impersonations) | List all active impersonations in a namespace (admin dashboard) |
| [`authn.list_impersonation_history`](sql.md#authnlist_impersonation_history) | List impersonation history for audit (includes ended impersonations) |
| [`authn.start_impersonation`](sql.md#authnstart_impersonation) | Start impersonating a user (creates a session acting as target user) |
| [`authn.clear_attempts`](sql.md#authnclear_attempts) | Clear login attempts to unlock a user (admin function) |
| [`authn.get_recent_attempts`](sql.md#authnget_recent_attempts) | Get recent login attempts for admin UI or user security page |
| [`authn.is_locked_out`](sql.md#authnis_locked_out) | Check if email is locked out due to too many failed attempts |
| [`authn.record_login_attempt`](sql.md#authnrecord_login_attempt) | Record a login attempt (success or failure) for lockout tracking |
| [`authn.cleanup_expired`](sql.md#authncleanup_expired) | Delete expired sessions, tokens, refresh tokens, API keys, impersonation records, and old login attempts (run via cron) |
| [`authn.get_stats`](sql.md#authnget_stats) | Get namespace statistics for monitoring dashboards |
| [`authn.clear_tenant`](sql.md#authnclear_tenant) | Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants. |
| [`authn.set_tenant`](sql.md#authnset_tenant) | Set tenant context for RLS (transaction-local, clears on commit). Use BEGIN/COMMIT when autocommit is enabled. |
| [`authn.end_operator_impersonation`](sql.md#authnend_operator_impersonation) | End an operator impersonation session early |
| [`authn.get_operator_audit_events`](sql.md#authnget_operator_audit_events) | Query operator audit events |
| [`authn.get_operator_impersonation_context`](sql.md#authnget_operator_impersonation_context) | Get operator impersonation context for a session |
| [`authn.list_active_operator_impersonations`](sql.md#authnlist_active_operator_impersonations) | List all active operator impersonations (platform admin view) |
| [`authn.list_operator_impersonations_by_operator`](sql.md#authnlist_operator_impersonations_by_operator) | List impersonations performed by an operator |
| [`authn.list_operator_impersonations_for_target`](sql.md#authnlist_operator_impersonations_for_target) | List operator impersonation history affecting a target namespace |
| [`authn.start_operator_impersonation`](sql.md#authnstart_operator_impersonation) | Start cross-namespace operator impersonation |
| [`authn.create_refresh_token`](sql.md#authncreate_refresh_token) | Create a refresh token for a session (call after create_session) |
| [`authn.list_refresh_tokens`](sql.md#authnlist_refresh_tokens) | List active refresh tokens for a user (for "manage devices" UI) |
| [`authn.revoke_all_refresh_tokens`](sql.md#authnrevoke_all_refresh_tokens) | Revoke all refresh tokens for a user (password change, security concern) |
| [`authn.revoke_refresh_token_family`](sql.md#authnrevoke_refresh_token_family) | Revoke all tokens in a family (for security response) |
| [`authn.rotate_refresh_token`](sql.md#authnrotate_refresh_token) | Rotate a refresh token: invalidate old, create new (secure by default) |
| [`authn.validate_refresh_token`](sql.md#authnvalidate_refresh_token) | Check if a refresh token is valid WITHOUT rotating (for inspection only) |
| [`authn.create_session`](sql.md#authncreate_session) | Create a session after successful login |
| [`authn.extend_session`](sql.md#authnextend_session) | Extend session absolute timeout (for "remember me", not idle timeout) |
| [`authn.list_sessions`](sql.md#authnlist_sessions) | List active sessions for "manage devices" UI |
| [`authn.revoke_all_sessions`](sql.md#authnrevoke_all_sessions) | Log out all sessions for a user (password change, security concern) |
| [`authn.revoke_other_sessions`](sql.md#authnrevoke_other_sessions) | Log out all sessions except the current one ("sign out other devices") |
| [`authn.revoke_session`](sql.md#authnrevoke_session) | Log out a specific session |
| [`authn.revoke_session_by_id`](sql.md#authnrevoke_session_by_id) | Revoke a specific session by ID (for "manage devices" UI) |
| [`authn.validate_session`](sql.md#authnvalidate_session) | Check if session is valid and get user info (hot path, no logging) |
| [`authn.consume_token`](sql.md#authnconsume_token) | Use a one-time token (marks as used, can't be reused) |
| [`authn.create_token`](sql.md#authncreate_token) | Create a one-time token for password reset, email verification, or magic link |
| [`authn.invalidate_tokens`](sql.md#authninvalidate_tokens) | Invalidate unused tokens (e.g., after password change, invalidate reset tokens) |
| [`authn.verify_email`](sql.md#authnverify_email) | Verify email address using token from email link |
| [`authn.create_user`](sql.md#authncreate_user) | Create a new user account |
| [`authn.delete_user`](sql.md#authndelete_user) | Permanently delete user and all their data (sessions, tokens, credentials) |
| [`authn.disable_user`](sql.md#authndisable_user) | Disable user and revoke all credentials (sessions, API keys, refresh tokens, impersonations, tokens) |
| [`authn.enable_user`](sql.md#authnenable_user) | Re-enable a disabled user account |
| [`authn.get_or_create_user`](sql.md#authnget_or_create_user) | Atomically get existing user or create new one (for SSO flows) |
| [`authn.get_user`](sql.md#authnget_user) | Get user by ID (does not return password hash) |
| [`authn.get_user_by_email`](sql.md#authnget_user_by_email) | Look up user by email (normalized to lowercase) |
| [`authn.get_users_batch`](sql.md#authnget_users_batch) | Get multiple users by ID in a single query |
| [`authn.list_users`](sql.md#authnlist_users) | List users with cursor-based pagination |
| [`authn.update_email`](sql.md#authnupdate_email) | Change user's email address (clears email_verified_at) |
