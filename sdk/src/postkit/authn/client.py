"""
postkit.authn - Authentication client for PostgreSQL-native auth.

This module provides:
- AuthnClient: SDK-style interface for authentication operations
- Exception classes: AuthnError, AuthnValidationError
"""

from __future__ import annotations

from datetime import datetime, timedelta

from postkit.base import BaseClient, PostkitError

__all__ = [
    "AuthnClient",
    "AuthnError",
    "AuthnValidationError",
]


class AuthnError(PostkitError):
    """Base exception for authn operations."""


class AuthnValidationError(AuthnError):
    """Raised when input validation fails."""


class AuthnClient(BaseClient):
    """
    SDK-style client for postkit/authn.

    This wraps the SQL functions with a Pythonic API.

    Example:
        authn = AuthnClient(cursor, namespace="production")

        # Create user
        user_id = authn.create_user("alice@example.com", "argon2_hash")

        # Create session
        session_id = authn.create_session(user_id, "sha256_token_hash")

        # Validate session
        user = authn.validate_session("sha256_token_hash")
        if user:
            print(f"Logged in as {user['email']}")
    """

    _schema = "authn"
    _error_class = AuthnError
    _module_sqlstate_map = {
        "22023": AuthnValidationError,  # invalid_parameter_value
        "22004": AuthnValidationError,  # null_value_not_allowed
        "22001": AuthnValidationError,  # string_data_right_truncation
        "22026": AuthnValidationError,  # string_data_length_mismatch
    }

    def __init__(self, cursor, namespace: str):
        super().__init__(cursor, namespace)
        # Extra actor fields specific to authn
        self._ip_address: str | None = None
        self._user_agent: str | None = None

    def _has_context(self) -> bool:
        """Check if any context field is set (includes authn-specific fields)."""
        return bool(super()._has_context() or self._ip_address or self._user_agent)

    def _apply_actor_context(self) -> None:
        """Apply actor context via authn.set_actor()."""
        self.cursor.execute(
            """SELECT authn.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_ip_address := %s,
                p_user_agent := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (
                self._actor_id,
                self._request_id,
                self._ip_address,
                self._user_agent,
                self._on_behalf_of,
                self._reason,
            ),
        )

    def create_user(
        self,
        email: str,
        password_hash: str | None = None,
    ) -> str:
        """
        Create a new user.

        Args:
            email: User's email address (will be normalized to lowercase)
            password_hash: Pre-hashed password (None for SSO-only users)

        Returns:
            User ID (UUID string)
        """
        result = self._fetch_val(
            "SELECT authn.create_user(%s, %s, %s)",
            (email, password_hash, self.namespace),
            write=True,
        )
        return str(result)

    def get_user(self, user_id: str) -> dict | None:
        """Get user by ID. Does not return password_hash."""
        return self._fetch_one(
            "SELECT * FROM authn.get_user(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def get_user_by_email(self, email: str) -> dict | None:
        """Get user by email. Does not return password_hash."""
        return self._fetch_one(
            "SELECT * FROM authn.get_user_by_email(%s, %s)",
            (email, self.namespace),
        )

    def update_email(self, user_id: str, new_email: str) -> bool:
        """Update user's email. Clears email_verified_at."""
        return self._fetch_val(
            "SELECT authn.update_email(%s::uuid, %s, %s)",
            (user_id, new_email, self.namespace),
            write=True,
        )

    def disable_user(self, user_id: str) -> bool:
        """Disable user and revoke all their sessions."""
        return self._fetch_val(
            "SELECT authn.disable_user(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def enable_user(self, user_id: str) -> bool:
        """Re-enable a disabled user."""
        return self._fetch_val(
            "SELECT authn.enable_user(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def delete_user(self, user_id: str) -> bool:
        """Permanently delete a user and all associated data."""
        return self._fetch_val(
            "SELECT authn.delete_user(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def list_users(self, limit: int = 100, cursor: str | None = None) -> list[dict]:
        """List users with pagination."""
        return self._fetch_all(
            "SELECT * FROM authn.list_users(%s, %s, %s)",
            (self.namespace, limit, cursor),
        )

    def get_users_batch(self, user_ids: list[str]) -> dict[str, dict]:
        """Get multiple users by ID in a single query.

        Args:
            user_ids: List of user IDs (UUIDs as strings)

        Returns:
            Dict mapping user_id -> user dict. Missing IDs are omitted.
        """
        if not user_ids:
            return {}

        rows = self._fetch_all(
            "SELECT * FROM authn.get_users_batch(%s::uuid[], %s)",
            (user_ids, self.namespace),
        )
        return {str(row["user_id"]): row for row in rows}

    def get_or_create_user(
        self, email: str, password_hash: str | None = None
    ) -> tuple[str, bool]:
        """Atomically get existing user or create new one.

        Args:
            email: User's email address (normalized to lowercase)
            password_hash: Pre-hashed password (None for SSO-only users)

        Returns:
            Tuple of (user_id, was_created)

        Raises:
            AuthnError: If user exists but is disabled
        """
        result = self._fetch_one(
            "SELECT * FROM authn.get_or_create_user(%s, %s, %s)",
            (email, password_hash, self.namespace),
            write=True,
        )
        if result is None:
            # This can only happen in an extremely rare race condition:
            # 1. INSERT fails because user exists (ON CONFLICT DO NOTHING)
            # 2. Another transaction DELETEs that user before our SELECT
            # 3. Our SELECT returns NULL
            # This indicates a bug in the application - user deletion during
            # concurrent registration should not occur.
            raise AuthnError(
                "Race condition: user was deleted between creation conflict and lookup. "
                "This requires concurrent INSERT and DELETE on the same email, "
                "which typically indicates an application bug."
            )
        if result["disabled"]:
            raise AuthnError("User is disabled")
        return str(result["user_id"]), result["created"]

    def get_credentials(self, email: str) -> dict | None:
        """
        Get credentials for login verification.

        Returns user_id, password_hash, and disabled_at for caller to verify.
        This is the ONLY method that returns password_hash.
        """
        return self._fetch_one(
            "SELECT * FROM authn.get_credentials(%s, %s)",
            (email, self.namespace),
        )

    def update_password(self, user_id: str, new_password_hash: str) -> bool:
        """Update user's password hash."""
        return self._fetch_val(
            "SELECT authn.update_password(%s::uuid, %s, %s)",
            (user_id, new_password_hash, self.namespace),
            write=True,
        )

    def create_session(
        self,
        user_id: str,
        token_hash: str,
        expires_in: timedelta | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """
        Create a new session.

        Args:
            user_id: User ID
            token_hash: Pre-hashed session token (SHA-256)
            expires_in: Session duration (default: 7 days)
            ip_address: Client IP
            user_agent: Client user agent

        Returns:
            Session ID (UUID string)
        """
        result = self._fetch_val(
            "SELECT authn.create_session(%s::uuid, %s, %s, %s::inet, %s, %s)",
            (user_id, token_hash, expires_in, ip_address, user_agent, self.namespace),
            write=True,
        )
        return str(result)

    def validate_session(self, token_hash: str) -> dict | None:
        """
        Validate a session token.

        Returns user info if valid, None otherwise.
        Does not log to audit (hot path).

        If the session is an impersonation session, the response includes
        impersonation context (is_impersonating, impersonator_id, impersonator_email,
        impersonation_reason) and the audit actor context is automatically set.

        Returns:
            Dict with user_id, email, session_id, is_impersonating,
            impersonator_id, impersonator_email, impersonation_reason
            - or None if session invalid/expired/revoked.
        """
        return self._fetch_one(
            "SELECT * FROM authn.validate_session(%s, %s)",
            (token_hash, self.namespace),
        )

    def extend_session(
        self,
        token_hash: str,
        extend_by: timedelta | None = None,
    ) -> datetime | None:
        """Extend session expiration.

        Returns:
            New expires_at timestamp, or None if session invalid/expired/revoked.
        """
        return self._fetch_val(
            "SELECT authn.extend_session(%s, %s, %s)",
            (token_hash, extend_by, self.namespace),
            write=True,
        )

    def revoke_session(self, token_hash: str) -> bool:
        """Revoke a session."""
        return self._fetch_val(
            "SELECT authn.revoke_session(%s, %s)",
            (token_hash, self.namespace),
            write=True,
        )

    def revoke_session_by_id(self, session_id: str, user_id: str) -> bool:
        """Revoke a session by ID (for manage devices UI).

        Args:
            session_id: Session ID to revoke
            user_id: User ID (for ownership verification)

        Returns:
            True if revoked, False if not found or not owned by user
        """
        return self._fetch_val(
            "SELECT authn.revoke_session_by_id(%s::uuid, %s::uuid, %s)",
            (session_id, user_id, self.namespace),
            write=True,
        )

    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user. Returns count revoked."""
        return self._fetch_val(
            "SELECT authn.revoke_all_sessions(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def revoke_other_sessions(self, user_id: str, except_session_id: str) -> int:
        """
        Revoke all sessions except the specified one ("sign out other devices").

        Use this when a user wants to log out of all other devices while staying
        logged in on the current device.

        Args:
            user_id: User whose sessions to revoke
            except_session_id: Session ID to preserve (the current session)

        Returns:
            Count of sessions revoked (excludes the preserved session)
        """
        return self._fetch_val(
            "SELECT authn.revoke_other_sessions(%s::uuid, %s::uuid, %s)",
            (user_id, except_session_id, self.namespace),
            write=True,
        )

    def list_sessions(self, user_id: str) -> list[dict]:
        """List active sessions for a user. Does not return token_hash."""
        return self._fetch_all(
            "SELECT * FROM authn.list_sessions(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    # =========================================================================
    # IMPERSONATION
    # =========================================================================

    def start_impersonation(
        self,
        actor_session_id: str,
        target_user_id: str,
        reason: str,
        token_hash: str,
        duration: timedelta | None = None,
    ) -> dict:
        """
        Start impersonating a user.

        Creates a new session that acts as the target user, with full audit trail.
        The calling application MUST verify authorization before calling this method.

        Args:
            actor_session_id: Session ID of the admin starting impersonation
                (cannot be an impersonation session - chaining is prevented)
            target_user_id: User ID to impersonate
            reason: Required justification (cannot be empty)
            token_hash: SHA-256 hash of the impersonation session token
            duration: How long the impersonation lasts (default 1 hour, max 8 hours)

        Returns:
            Dict with impersonation_id, impersonation_session_id, expires_at

        Raises:
            AuthnError: If actor session invalid, target user invalid/disabled,
                reason empty, duration exceeds max, attempting self-impersonation,
                or attempting to chain impersonation
        """
        result = self._fetch_one(
            "SELECT * FROM authn.start_impersonation(%s::uuid, %s::uuid, %s, %s, %s, %s)",
            (
                actor_session_id,
                target_user_id,
                token_hash,
                reason,
                duration,
                self.namespace,
            ),
            write=True,
        )
        if result is None:
            raise AuthnError("Failed to start impersonation")
        return result

    def end_impersonation(self, impersonation_id: str) -> bool:
        """
        End an impersonation session early.

        Revokes the impersonation session and marks the impersonation as ended.

        Args:
            impersonation_id: The impersonation to end

        Returns:
            True if ended, False if not found or already ended
        """
        return self._fetch_val(
            "SELECT authn.end_impersonation(%s::uuid, %s)",
            (impersonation_id, self.namespace),
            write=True,
        )

    def get_impersonation_context(self, session_id: str) -> dict:
        """
        Check if a session is an impersonation session.

        Note: validate_session() already returns this info and auto-sets audit context,
        so this method is rarely needed. Use it for explicit lookups.

        Args:
            session_id: Session ID to check

        Returns:
            Dict with is_impersonating (bool), and if True:
            impersonation_id, actor_id, actor_email, target_user_id,
            reason, started_at, expires_at
        """
        result = self._fetch_one(
            "SELECT * FROM authn.get_impersonation_context(%s::uuid, %s)",
            (session_id, self.namespace),
        )
        return result or {"is_impersonating": False}

    def list_active_impersonations(self) -> list[dict]:
        """
        List all active impersonations in the namespace.

        For admin dashboard to see who is impersonating whom.

        Returns:
            List of active impersonation records with actor/target info
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_active_impersonations(%s)",
            (self.namespace,),
        )

    def list_impersonation_history(
        self,
        limit: int = 100,
        actor_id: str | None = None,
        target_user_id: str | None = None,
    ) -> list[dict]:
        """
        List impersonation history for audit purposes.

        Args:
            limit: Maximum records to return
            actor_id: Optional filter by actor (admin who impersonated)
            target_user_id: Optional filter by target (user who was impersonated)

        Returns:
            List of impersonation records (including ended ones)
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_impersonation_history(%s, %s, %s::uuid, %s::uuid)",
            (self.namespace, limit, actor_id, target_user_id),
        )

    # =========================================================================
    # OPERATOR IMPERSONATION
    # =========================================================================

    def start_operator_impersonation(
        self,
        operator_session_id: str,
        target_user_id: str,
        target_namespace: str,
        token_hash: str,
        reason: str,
        duration: timedelta | None = None,
        ticket_reference: str | None = None,
    ) -> dict:
        """
        Start cross-namespace operator impersonation.

        Creates a new session in the target namespace that acts as the target user,
        with full audit trail. The calling application MUST verify the operator
        is authorized before calling this method.

        Args:
            operator_session_id: Session ID of the operator starting impersonation
                (cannot be an impersonation session - chaining is prevented)
            target_user_id: User ID to impersonate
            target_namespace: Namespace of the target user
            token_hash: SHA-256 hash of the impersonation session token
            reason: Required justification (cannot be empty)
            duration: How long the impersonation lasts (default 30 min, max 4 hours)
            ticket_reference: Optional external ticket reference (Zendesk, Jira, etc.)

        Returns:
            Dict with impersonation_id, impersonation_session_id, expires_at

        Raises:
            AuthnError: If operator session invalid, target user invalid/disabled,
                reason empty, duration exceeds max, attempting self-impersonation,
                or attempting to chain impersonation
        """
        result = self._fetch_one(
            "SELECT * FROM authn.start_operator_impersonation(%s::uuid, %s::uuid, %s, %s, %s, %s, %s)",
            (
                operator_session_id,
                target_user_id,
                target_namespace,
                token_hash,
                reason,
                duration,
                ticket_reference,
            ),
            write=True,
        )
        if result is None:
            raise AuthnError("Failed to start operator impersonation")
        return result

    def end_operator_impersonation(self, impersonation_id: str) -> bool:
        """
        End an operator impersonation session early.

        Revokes the impersonation session and marks the impersonation as ended.

        Args:
            impersonation_id: The impersonation to end

        Returns:
            True if ended, False if not found or already ended
        """
        return self._fetch_val(
            "SELECT authn.end_operator_impersonation(%s::uuid)",
            (impersonation_id,),
            write=True,
        )

    def get_operator_impersonation_context(self, session_id: str) -> dict:
        """
        Check if a session is an operator impersonation session.

        Args:
            session_id: Session ID to check

        Returns:
            Dict with is_operator_impersonating (bool), and if True:
            impersonation_id, operator_id, operator_email, operator_namespace,
            target_user_id, target_user_email, target_namespace, reason,
            ticket_reference, started_at, expires_at
        """
        result = self._fetch_one(
            "SELECT * FROM authn.get_operator_impersonation_context(%s::uuid)",
            (session_id,),
        )
        return result or {"is_operator_impersonating": False}

    def list_operator_impersonations_for_target(
        self,
        target_namespace: str,
        limit: int = 100,
        target_user_id: str | None = None,
    ) -> list[dict]:
        """
        List operator impersonation history affecting a target namespace.

        For tenant admins to see who from the platform accessed their users.

        Args:
            target_namespace: Namespace to query
            limit: Maximum records to return
            target_user_id: Optional filter by specific target user

        Returns:
            List of impersonation records (including ended ones)
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_operator_impersonations_for_target(%s, %s, %s::uuid)",
            (target_namespace, limit, target_user_id),
        )

    def list_operator_impersonations_by_operator(
        self,
        operator_id: str,
        operator_namespace: str,
        limit: int = 100,
    ) -> list[dict]:
        """
        List impersonations performed by an operator.

        Args:
            operator_id: Operator user ID to query
            operator_namespace: Operator's namespace
            limit: Maximum records to return

        Returns:
            List of impersonation records by the operator
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_operator_impersonations_by_operator(%s::uuid, %s, %s)",
            (operator_id, operator_namespace, limit),
        )

    def list_active_operator_impersonations(self, limit: int = 100) -> list[dict]:
        """
        List all active operator impersonations.

        For platform admin dashboard to see who is impersonating whom
        across all namespaces.

        Args:
            limit: Maximum records to return

        Returns:
            List of active impersonation records
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_active_operator_impersonations(%s)",
            (limit,),
        )

    def get_operator_audit_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        operator_namespace: str | None = None,
        target_namespace: str | None = None,
    ) -> list[dict]:
        """
        Query operator audit events.

        Args:
            limit: Maximum records to return
            event_type: Optional filter by event type
            operator_namespace: Optional filter by operator namespace
            target_namespace: Optional filter by target namespace

        Returns:
            List of operator audit event records
        """
        return self._fetch_all(
            "SELECT * FROM authn.get_operator_audit_events(%s, %s, %s, %s)",
            (limit, event_type, operator_namespace, target_namespace),
        )

    # =========================================================================
    # REFRESH TOKENS
    # =========================================================================

    def create_refresh_token(
        self,
        session_id: str,
        token_hash: str,
        expires_in: timedelta | None = None,
    ) -> dict:
        """
        Create a refresh token for a session.

        Call this after create_session() to enable token rotation.

        Args:
            session_id: Session ID to associate with
            token_hash: Pre-hashed refresh token (SHA-256)
            expires_in: Token lifetime (default: 30 days)

        Returns:
            Dict with refresh_token_id, family_id, expires_at
        """
        result = self._fetch_one(
            "SELECT * FROM authn.create_refresh_token(%s::uuid, %s, %s, %s)",
            (session_id, token_hash, expires_in, self.namespace),
            write=True,
        )
        if result is None:
            raise AuthnError("Failed to create refresh token")
        return result

    def rotate_refresh_token(
        self,
        old_token_hash: str,
        new_token_hash: str,
        expires_in: timedelta | None = None,
    ) -> dict | None:
        """
        Rotate a refresh token (invalidate old, issue new).

        Returns None if:
        - Token not found
        - Token expired
        - Token already rotated (reuse attack - entire family revoked!)
        - Associated session revoked/expired
        - User disabled

        Args:
            old_token_hash: Hash of token being rotated
            new_token_hash: Hash of new token to issue
            expires_in: New token lifetime (default: 30 days)

        Returns:
            Dict with user_id, session_id, new_refresh_token_id, family_id,
            generation, expires_at - or None if rotation failed
        """
        return self._fetch_one(
            "SELECT * FROM authn.rotate_refresh_token(%s, %s, %s, %s)",
            (old_token_hash, new_token_hash, expires_in, self.namespace),
            write=True,
        )

    def validate_refresh_token(self, token_hash: str) -> dict | None:
        """
        Validate a refresh token without rotating (read-only check).

        Use for inspection/debugging, not for actual token refresh.

        Returns:
            Dict with user_id, session_id, family_id, generation,
            expires_at, is_current - or None if invalid
        """
        return self._fetch_one(
            "SELECT * FROM authn.validate_refresh_token(%s, %s)",
            (token_hash, self.namespace),
        )

    def revoke_refresh_token_family(self, family_id: str) -> int:
        """
        Revoke all tokens in a family (security response).

        Returns:
            Count of tokens revoked
        """
        return self._fetch_val(
            "SELECT authn.revoke_refresh_token_family(%s::uuid, %s)",
            (family_id, self.namespace),
            write=True,
        )

    def revoke_all_refresh_tokens(self, user_id: str) -> int:
        """
        Revoke all refresh tokens for a user.

        Returns:
            Count of tokens revoked
        """
        return self._fetch_val(
            "SELECT authn.revoke_all_refresh_tokens(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def list_refresh_tokens(self, user_id: str) -> list[dict]:
        """
        List active refresh tokens for a user.

        Does not return token_hash. For "manage devices" UI.
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_refresh_tokens(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def create_api_key(
        self,
        user_id: str,
        key_hash: str,
        name: str | None = None,
        expires_in: timedelta | None = None,
    ) -> str:
        """
        Create an API key for programmatic access.

        Args:
            user_id: User ID (owner of the key)
            key_hash: Pre-hashed API key (SHA-256)
            name: Optional friendly name ("Production", "CI/CD")
            expires_in: Optional expiration duration (None = never expires)

        Returns:
            API key ID (UUID string)
        """
        result = self._fetch_val(
            "SELECT authn.create_api_key(%s::uuid, %s, %s, %s, %s)",
            (user_id, key_hash, name, expires_in, self.namespace),
            write=True,
        )
        return str(result)

    def validate_api_key(self, key_hash: str) -> dict | None:
        """
        Validate an API key.

        Returns key info if valid, None otherwise.
        Updates last_used_at on successful validation.

        Returns:
            Dict with user_id, key_id, name, expires_at or None if invalid
        """
        return self._fetch_one(
            "SELECT * FROM authn.validate_api_key(%s, %s)",
            (key_hash, self.namespace),
        )

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        return self._fetch_val(
            "SELECT authn.revoke_api_key(%s::uuid, %s)",
            (key_id, self.namespace),
            write=True,
        )

    def revoke_all_api_keys(self, user_id: str) -> int:
        """Revoke all API keys for a user. Returns count revoked."""
        return self._fetch_val(
            "SELECT authn.revoke_all_api_keys(%s::uuid, %s)",
            (user_id, self.namespace),
            write=True,
        )

    def list_api_keys(self, user_id: str) -> list[dict]:
        """List active API keys for a user. Does not return key_hash."""
        return self._fetch_all(
            "SELECT * FROM authn.list_api_keys(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def get_api_key(self, key_id: str, user_id: str) -> dict | None:
        """Get an API key by ID if owned by user.

        Use this for O(1) ownership verification instead of listing all keys.

        Args:
            key_id: The API key ID to look up
            user_id: The user who should own the key

        Returns:
            Key metadata dict if found and owned by user, None otherwise
        """
        return self._fetch_one(
            "SELECT * FROM authn.get_api_key(%s::uuid, %s::uuid, %s)",
            (key_id, user_id, self.namespace),
        )

    def create_token(
        self,
        user_id: str,
        token_hash: str,
        token_type: str,
        expires_in: timedelta | None = None,
    ) -> str:
        """
        Create a one-time use token.

        Args:
            user_id: User ID
            token_hash: Pre-hashed token (SHA-256)
            token_type: 'password_reset', 'email_verify', or 'magic_link'
            expires_in: Token lifetime (defaults vary by type)

        Returns:
            Token ID (UUID string)
        """
        result = self._fetch_val(
            "SELECT authn.create_token(%s::uuid, %s, %s, %s, %s)",
            (user_id, token_hash, token_type, expires_in, self.namespace),
            write=True,
        )
        return str(result)

    def consume_token(self, token_hash: str, token_type: str) -> dict | None:
        """
        Consume a one-time token.

        Returns user info if valid, None otherwise.
        Token is marked as used after this call.
        """
        return self._fetch_one(
            "SELECT * FROM authn.consume_token(%s, %s, %s)",
            (token_hash, token_type, self.namespace),
            write=True,
        )

    def verify_email(self, token_hash: str) -> dict | None:
        """
        Verify email using a token.

        Convenience method that consumes email_verify token and sets email_verified_at.
        """
        return self._fetch_one(
            "SELECT * FROM authn.verify_email(%s, %s)",
            (token_hash, self.namespace),
            write=True,
        )

    def invalidate_tokens(self, user_id: str, token_type: str) -> int:
        """Invalidate all unused tokens of a type for a user."""
        return self._fetch_val(
            "SELECT authn.invalidate_tokens(%s::uuid, %s, %s)",
            (user_id, token_type, self.namespace),
            write=True,
        )

    # =========================================================================
    # CREDENTIALS (TOTP, WebAuthn, Recovery Codes)
    # =========================================================================

    def add_credential(
        self,
        user_id: str,
        credential_type: str,
        *,
        lookup_key: str | None = None,
        secret_data: str | None = None,
        name: str | None = None,
        metadata: dict | None = None,
        created_by: str | None = None,
    ) -> str:
        """
        Add a credential for a user.

        Args:
            user_id: User ID
            credential_type: 'totp', 'recovery_code', or 'webauthn'
            lookup_key: Lookup key (WebAuthn credential_id, recovery code hash)
            secret_data: Secret data (TOTP seed, WebAuthn public key)
            name: Optional friendly name like "Work Yubikey"
            metadata: Optional JSON metadata
            created_by: UUID of user who added this credential (for audit)

        Returns:
            Credential ID (UUID string)
        """
        import json

        result = self._fetch_val(
            "SELECT authn.add_credential(%s::uuid, %s, %s, %s, %s, %s::jsonb, %s::uuid, %s)",
            (
                user_id,
                credential_type,
                lookup_key,
                secret_data,
                name,
                json.dumps(metadata) if metadata else None,
                created_by,
                self.namespace,
            ),
            write=True,
        )
        return str(result)

    def get_user_credentials(self, user_id: str, credential_type: str) -> list[dict]:
        """
        Get active credentials for verification. Returns secrets!

        Args:
            user_id: User ID
            credential_type: 'totp', 'recovery_code', or 'webauthn'

        Returns:
            List of credentials with id, lookup_key, secret_data, sign_count
        """
        return self._fetch_all(
            "SELECT * FROM authn.get_credentials(%s::uuid, %s, %s)",
            (user_id, credential_type, self.namespace),
        )

    def get_credential_by_lookup(
        self, user_id: str, lookup_key: str, credential_type: str
    ) -> dict | None:
        """
        Lookup a credential by key. Requires user_id for enumeration safety.

        Args:
            user_id: User ID (prevents cross-user enumeration)
            lookup_key: The lookup key (e.g., recovery code hash)
            credential_type: 'totp', 'recovery_code', or 'webauthn'

        Returns:
            Credential with id, secret_data, sign_count, consumed_at - or None
        """
        return self._fetch_one(
            "SELECT * FROM authn.get_credential_by_lookup(%s::uuid, %s, %s, %s)",
            (user_id, lookup_key, credential_type, self.namespace),
        )

    def record_credential_use(self, credential_id: str) -> None:
        """
        Record credential usage (lazy update: only if >1hr since last).

        Args:
            credential_id: Credential that was used
        """
        self._fetch_val(
            "SELECT authn.record_credential_use(%s::uuid, %s)",
            (credential_id, self.namespace),
            write=True,
        )

    def consume_credential(self, credential_id: str) -> bool:
        """
        Consume a one-time credential (e.g., recovery code).

        Args:
            credential_id: Credential to consume

        Returns:
            True if consumed, False if already consumed/disabled
        """
        return self._fetch_val(
            "SELECT authn.consume_credential(%s::uuid, %s)",
            (credential_id, self.namespace),
            write=True,
        )

    def update_sign_count(self, credential_id: str, new_count: int) -> bool:
        """
        Update WebAuthn sign count. Returns False if clone detected.

        SECURITY: A False return indicates potential authenticator cloning.
        The caller should log a security alert and potentially disable the credential.

        Args:
            credential_id: WebAuthn credential to update
            new_count: New sign count from authenticator

        Returns:
            True if updated, False if new_count <= current (clone attack!)
        """
        return self._fetch_val(
            "SELECT authn.update_sign_count(%s::uuid, %s, %s)",
            (credential_id, new_count, self.namespace),
            write=True,
        )

    def disable_credential(self, credential_id: str, reason: str) -> bool:
        """
        Soft-disable a credential (preserves for forensics).

        Args:
            credential_id: Credential to disable
            reason: Required reason for audit trail

        Returns:
            True if disabled, False if not found/already disabled
        """
        return self._fetch_val(
            "SELECT authn.disable_credential(%s::uuid, %s, %s)",
            (credential_id, reason, self.namespace),
            write=True,
        )

    def remove_credential(self, credential_id: str) -> bool:
        """
        Hard-delete a credential (user self-service).

        Args:
            credential_id: Credential to remove

        Returns:
            True if removed, False if not found
        """
        return self._fetch_val(
            "SELECT authn.remove_credential(%s::uuid, %s)",
            (credential_id, self.namespace),
            write=True,
        )

    def disable_all_credentials(self, user_id: str, reason: str) -> int:
        """
        Disable all credentials for a user (incident response).

        Args:
            user_id: User whose credentials to disable
            reason: Required reason for audit trail

        Returns:
            Count of credentials disabled
        """
        return self._fetch_val(
            "SELECT authn.disable_all_credentials(%s::uuid, %s, %s)",
            (user_id, reason, self.namespace),
            write=True,
        )

    def list_user_credentials(
        self,
        user_id: str,
        credential_type: str | None = None,
        include_disabled: bool = False,
    ) -> list[dict]:
        """
        List credentials for settings UI. Does NOT return secrets.

        Args:
            user_id: User ID
            credential_type: Optional filter by type
            include_disabled: Include disabled credentials (for admin/forensics)

        Returns:
            List of credential metadata (no secrets)
        """
        return self._fetch_all(
            "SELECT * FROM authn.list_credentials(%s::uuid, %s, %s, %s)",
            (user_id, credential_type, include_disabled, self.namespace),
        )

    def has_credential(self, user_id: str, credential_type: str) -> bool:
        """
        Check if user has active credential of a specific type.

        Args:
            user_id: User ID
            credential_type: 'totp', 'recovery_code', or 'webauthn'

        Returns:
            True if user has at least one active credential of type
        """
        return self._fetch_val(
            "SELECT authn.has_credential(%s::uuid, %s, %s)",
            (user_id, credential_type, self.namespace),
        )

    def record_login_attempt(
        self,
        email: str,
        success: bool,
        ip_address: str | None = None,
    ) -> None:
        """Record a login attempt."""
        self._fetch_val(
            "SELECT authn.record_login_attempt(%s, %s, %s::inet, %s)",
            (email, success, ip_address, self.namespace),
            write=True,
        )

    def is_locked_out(
        self,
        email: str,
        window: timedelta | None = None,
        max_attempts: int | None = None,
    ) -> bool:
        """Check if an email is locked out due to too many failed attempts."""
        return self._fetch_val(
            "SELECT authn.is_locked_out(%s, %s, %s, %s)",
            (email, self.namespace, window, max_attempts),
        )

    def get_recent_attempts(self, email: str, limit: int = 10) -> list[dict]:
        """Get recent login attempts for an email."""
        return self._fetch_all(
            "SELECT * FROM authn.get_recent_attempts(%s, %s, %s)",
            (email, self.namespace, limit),
        )

    def clear_attempts(self, email: str) -> int:
        """Clear login attempts for an email. Returns count deleted."""
        return self._fetch_val(
            "SELECT authn.clear_attempts(%s, %s)",
            (email, self.namespace),
            write=True,
        )

    def cleanup_expired(self, batch_size: int = 10000) -> dict:
        """Clean up expired sessions, tokens, impersonation records, and old login attempts.

        Args:
            batch_size: Max rows to delete per table per iteration (default 10000).
                Smaller values reduce lock contention but require more iterations.

        Returns:
            Dict with counts: sessions_deleted, tokens_deleted, refresh_tokens_deleted,
            api_keys_deleted, impersonations_deleted, operator_impersonations_deleted,
            attempts_deleted
        """
        return (
            self._fetch_one(
                "SELECT * FROM authn.cleanup_expired(%s, %s)",
                (self.namespace, batch_size),
                write=True,
            )
            or {}
        )

    def get_stats(self) -> dict:
        """Get namespace statistics."""
        result = self._fetch_one(
            "SELECT * FROM authn.get_stats(%s)",
            (self.namespace,),
        )
        return result or {}

    def set_actor(
        self,
        actor_id: str | None = None,
        request_id: str | None = None,
        on_behalf_of: str | None = None,
        reason: str | None = None,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Set actor context for audit logging. Only updates fields that are passed.

        Args:
            actor_id: The actor making changes (e.g., 'user:alice')
            request_id: Request/correlation ID for tracing
            on_behalf_of: Principal being represented
            reason: Reason for the action
            ip_address: Client IP address
            user_agent: Client user agent string

        Example:
            # In before_request: set HTTP context
            authn.clear_actor()
            authn.set_actor(request_id=req_id, ip_address=ip, user_agent=ua)

            # After authentication: add actor_id (preserves HTTP context)
            authn.set_actor(actor_id="user:alice")
        """
        super().set_actor(actor_id, request_id, on_behalf_of, reason)
        if ip_address is not None:
            self._ip_address = ip_address
        if user_agent is not None:
            self._user_agent = user_agent

    def clear_actor(self) -> None:
        """Clear actor context."""
        super().clear_actor()
        self._ip_address = None
        self._user_agent = None

    def get_audit_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        before: str | None = None,
    ) -> list[dict]:
        """Query audit events with optional filters.

        Args:
            limit: Maximum number of events to return (default 100)
            event_type: Filter by event type (e.g., 'user_created', 'session_revoked')
            actor_id: Filter by actor ID (who made the change)
            resource_type: Filter by resource type (e.g., 'user', 'session')
            resource_id: Filter by resource ID
            before: Opaque cursor from a previous response's event['cursor']

        Returns:
            List of audit event dictionaries. Each event includes a 'cursor' field
            that can be passed to 'before' for pagination.

        Example:
            events = authn.get_audit_events(limit=50)
            if events:
                more = authn.get_audit_events(limit=50, before=events[-1]["cursor"])
        """
        return super().get_audit_events(
            limit=limit,
            event_type=event_type,
            actor_id=actor_id,
            before=before,
            resource_type=resource_type,
            resource_id=resource_id,
        )
