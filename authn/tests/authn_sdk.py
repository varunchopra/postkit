"""
postkit/authn SDK - Python client for the authentication system.

This module provides:
- AuthnClient: SDK-style interface for authentication operations
- Exception classes: AuthnError, AuthnValidationError
- AuthnTestHelpers: Direct table access for testing
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

import psycopg


__all__ = [
    "AuthnClient",
    "AuthnTestHelpers",
    "AuthnError",
    "AuthnValidationError",
]


# =============================================================================
# EXCEPTIONS
# =============================================================================


class AuthnError(Exception):
    """Base exception for authn operations."""

    pass


class AuthnValidationError(AuthnError):
    """Raised when input validation fails."""

    pass


# =============================================================================
# SDK CLIENT
# =============================================================================


class AuthnClient:
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

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        # Set tenant context for RLS
        self.cursor.execute("SELECT authn.set_tenant(%s)", (namespace,))
        # Actor context stored as instance state (applied per-operation in _write_scalar)
        self._actor_id: str | None = None
        self._request_id: str | None = None
        self._ip_address: str | None = None
        self._user_agent: str | None = None

    def _handle_error(self, e: psycopg.Error) -> None:
        """Convert psycopg errors to SDK exceptions."""
        raise AuthnError(str(e)) from e

    def _normalize_row(self, row: dict) -> dict:
        """Normalize types in result row (UUIDs to strings)."""
        return {k: str(v) if isinstance(v, UUID) else v for k, v in row.items()}

    def _scalar(self, sql: str, params: tuple):
        """Execute SQL and return single scalar value."""
        try:
            self.cursor.execute(sql, params)
            result = self.cursor.fetchone()
            return result[0] if result else None
        except psycopg.Error as e:
            self._handle_error(e)

    def _row(self, sql: str, params: tuple) -> dict | None:
        """Execute SQL and return single row as dict with normalized types."""
        try:
            self.cursor.execute(sql, params)
            result = self.cursor.fetchone()
            if result is None:
                return None
            columns = [desc[0] for desc in self.cursor.description]
            return self._normalize_row(dict(zip(columns, result)))
        except psycopg.Error as e:
            self._handle_error(e)

    def _fetchall(self, sql: str, params: tuple) -> list[dict]:
        """Execute SQL and return all rows as list of dicts with normalized types."""
        self.cursor.execute(sql, params)
        columns = [desc[0] for desc in self.cursor.description]
        return [
            self._normalize_row(dict(zip(columns, row)))
            for row in self.cursor.fetchall()
        ]

    def _write_scalar(self, sql: str, params: tuple):
        """Execute a write operation with actor context for audit logging."""
        if self._actor_id is None:
            return self._scalar(sql, params)

        in_transaction = self.cursor.connection.info.transaction_status != 0

        if in_transaction:
            self.cursor.execute(
                "SELECT authn.set_actor(%s, %s, %s, %s)",
                (self._actor_id, self._request_id, self._ip_address, self._user_agent),
            )
            return self._scalar(sql, params)

        try:
            self.cursor.execute("BEGIN")
            self.cursor.execute(
                "SELECT authn.set_actor(%s, %s, %s, %s)",
                (self._actor_id, self._request_id, self._ip_address, self._user_agent),
            )
            result = self._scalar(sql, params)
            self.cursor.execute("COMMIT")
            return result
        except Exception:
            self.cursor.execute("ROLLBACK")
            raise

    # =========================================================================
    # User Management
    # =========================================================================

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
        result = self._write_scalar(
            "SELECT authn.create_user(%s, %s, %s)",
            (email, password_hash, self.namespace),
        )
        return str(result) if result else None

    def get_user(self, user_id: str) -> dict | None:
        """Get user by ID. Does not return password_hash."""
        return self._row(
            "SELECT * FROM authn.get_user(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def get_user_by_email(self, email: str) -> dict | None:
        """Get user by email. Does not return password_hash."""
        return self._row(
            "SELECT * FROM authn.get_user_by_email(%s, %s)",
            (email, self.namespace),
        )

    def update_email(self, user_id: str, new_email: str) -> bool:
        """Update user's email. Clears email_verified_at."""
        return self._write_scalar(
            "SELECT authn.update_email(%s::uuid, %s, %s)",
            (user_id, new_email, self.namespace),
        )

    def disable_user(self, user_id: str) -> bool:
        """Disable user and revoke all their sessions."""
        return self._write_scalar(
            "SELECT authn.disable_user(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def enable_user(self, user_id: str) -> bool:
        """Re-enable a disabled user."""
        return self._write_scalar(
            "SELECT authn.enable_user(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def delete_user(self, user_id: str) -> bool:
        """Permanently delete a user and all associated data."""
        return self._write_scalar(
            "SELECT authn.delete_user(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def list_users(self, limit: int = 100, cursor: str | None = None) -> list[dict]:
        """List users with pagination."""
        return self._fetchall(
            "SELECT * FROM authn.list_users(%s, %s, %s)",
            (self.namespace, limit, cursor),
        )

    # =========================================================================
    # Credentials
    # =========================================================================

    def get_credentials(self, email: str) -> dict | None:
        """
        Get credentials for login verification.

        Returns user_id, password_hash, and disabled_at for caller to verify.
        This is the ONLY method that returns password_hash.
        """
        return self._row(
            "SELECT * FROM authn.get_credentials(%s, %s)",
            (email, self.namespace),
        )

    def update_password(self, user_id: str, new_password_hash: str) -> bool:
        """Update user's password hash."""
        return self._write_scalar(
            "SELECT authn.update_password(%s::uuid, %s, %s)",
            (user_id, new_password_hash, self.namespace),
        )

    # =========================================================================
    # Sessions
    # =========================================================================

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
        result = self._write_scalar(
            "SELECT authn.create_session(%s::uuid, %s, %s, %s::inet, %s, %s)",
            (user_id, token_hash, expires_in, ip_address, user_agent, self.namespace),
        )
        return str(result) if result else None

    def validate_session(self, token_hash: str) -> dict | None:
        """
        Validate a session token.

        Returns user info if valid, None otherwise.
        Does not log to audit (hot path).
        """
        return self._row(
            "SELECT * FROM authn.validate_session(%s, %s)",
            (token_hash, self.namespace),
        )

    def extend_session(
        self,
        token_hash: str,
        extend_by: timedelta | None = None,
    ) -> datetime | None:
        """Extend session expiration. Returns new expires_at."""
        return self._scalar(
            "SELECT authn.extend_session(%s, %s, %s)",
            (token_hash, extend_by, self.namespace),
        )

    def revoke_session(self, token_hash: str) -> bool:
        """Revoke a session."""
        return self._write_scalar(
            "SELECT authn.revoke_session(%s, %s)",
            (token_hash, self.namespace),
        )

    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user. Returns count revoked."""
        return self._write_scalar(
            "SELECT authn.revoke_all_sessions(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def list_sessions(self, user_id: str) -> list[dict]:
        """List active sessions for a user. Does not return token_hash."""
        return self._fetchall(
            "SELECT * FROM authn.list_sessions(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    # =========================================================================
    # Tokens (password reset, email verification, magic links)
    # =========================================================================

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
        result = self._write_scalar(
            "SELECT authn.create_token(%s::uuid, %s, %s, %s, %s)",
            (user_id, token_hash, token_type, expires_in, self.namespace),
        )
        return str(result) if result else None

    def consume_token(self, token_hash: str, token_type: str) -> dict | None:
        """
        Consume a one-time token.

        Returns user info if valid, None otherwise.
        Token is marked as used after this call.
        """
        return self._row(
            "SELECT * FROM authn.consume_token(%s, %s, %s)",
            (token_hash, token_type, self.namespace),
        )

    def verify_email(self, token_hash: str) -> dict | None:
        """
        Verify email using a token.

        Convenience method that consumes email_verify token and sets email_verified_at.
        """
        return self._row(
            "SELECT * FROM authn.verify_email(%s, %s)",
            (token_hash, self.namespace),
        )

    def invalidate_tokens(self, user_id: str, token_type: str) -> int:
        """Invalidate all unused tokens of a type for a user."""
        return self._write_scalar(
            "SELECT authn.invalidate_tokens(%s::uuid, %s, %s)",
            (user_id, token_type, self.namespace),
        )

    # =========================================================================
    # MFA
    # =========================================================================

    def add_mfa(
        self,
        user_id: str,
        mfa_type: str,
        secret: str,
        name: str | None = None,
    ) -> str:
        """
        Add an MFA method for a user.

        Args:
            user_id: User ID
            mfa_type: 'totp', 'webauthn', or 'recovery_codes'
            secret: The MFA secret (caller stores this securely)
            name: Optional friendly name

        Returns:
            MFA ID (UUID string)
        """
        result = self._write_scalar(
            "SELECT authn.add_mfa(%s::uuid, %s, %s, %s, %s)",
            (user_id, mfa_type, secret, name, self.namespace),
        )
        return str(result) if result else None

    def get_mfa(self, user_id: str, mfa_type: str) -> list[dict]:
        """Get MFA secrets for verification. Returns secrets!"""
        return self._fetchall(
            "SELECT * FROM authn.get_mfa(%s::uuid, %s, %s)",
            (user_id, mfa_type, self.namespace),
        )

    def list_mfa(self, user_id: str) -> list[dict]:
        """List MFA methods. Does NOT return secrets."""
        return self._fetchall(
            "SELECT * FROM authn.list_mfa(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    def remove_mfa(self, mfa_id: str) -> bool:
        """Remove an MFA method."""
        return self._write_scalar(
            "SELECT authn.remove_mfa(%s::uuid, %s)",
            (mfa_id, self.namespace),
        )

    def record_mfa_use(self, mfa_id: str) -> bool:
        """Record that an MFA method was used."""
        return self._write_scalar(
            "SELECT authn.record_mfa_use(%s::uuid, %s)",
            (mfa_id, self.namespace),
        )

    def has_mfa(self, user_id: str) -> bool:
        """Check if user has any MFA method enabled."""
        return self._scalar(
            "SELECT authn.has_mfa(%s::uuid, %s)",
            (user_id, self.namespace),
        )

    # =========================================================================
    # Lockout
    # =========================================================================

    def record_login_attempt(
        self,
        email: str,
        success: bool,
        ip_address: str | None = None,
    ) -> None:
        """Record a login attempt."""
        self._scalar(
            "SELECT authn.record_login_attempt(%s, %s, %s::inet, %s)",
            (email, success, ip_address, self.namespace),
        )

    def is_locked_out(
        self,
        email: str,
        window: timedelta | None = None,
        max_attempts: int | None = None,
    ) -> bool:
        """Check if an email is locked out due to too many failed attempts."""
        return self._scalar(
            "SELECT authn.is_locked_out(%s, %s, %s, %s)",
            (email, self.namespace, window, max_attempts),
        )

    def get_recent_attempts(self, email: str, limit: int = 10) -> list[dict]:
        """Get recent login attempts for an email."""
        return self._fetchall(
            "SELECT * FROM authn.get_recent_attempts(%s, %s, %s)",
            (email, self.namespace, limit),
        )

    def clear_attempts(self, email: str) -> int:
        """Clear login attempts for an email. Returns count deleted."""
        return self._write_scalar(
            "SELECT authn.clear_attempts(%s, %s)",
            (email, self.namespace),
        )

    # =========================================================================
    # Maintenance
    # =========================================================================

    def cleanup_expired(self) -> dict:
        """Clean up expired sessions, tokens, and old login attempts."""
        result = self._row(
            "SELECT * FROM authn.cleanup_expired(%s)",
            (self.namespace,),
        )
        return result or {}

    def get_stats(self) -> dict:
        """Get namespace statistics."""
        result = self._row(
            "SELECT * FROM authn.get_stats(%s)",
            (self.namespace,),
        )
        return result or {}

    # =========================================================================
    # Audit Context
    # =========================================================================

    def set_actor(
        self,
        actor_id: str,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Set actor context for audit logging.

        Note: Unlike set_tenant() which applies immediately via SQL, actor context
        is stored as instance state and applied per-operation in _write_scalar.
        This ensures actor context is set within the same transaction as the
        audited operation (required because PostgreSQL's set_config with is_local=true
        only persists within the current transaction).
        """
        self._actor_id = actor_id
        self._request_id = request_id
        self._ip_address = ip_address
        self._user_agent = user_agent

    def clear_actor(self) -> None:
        """Clear actor context."""
        self._actor_id = None
        self._request_id = None
        self._ip_address = None
        self._user_agent = None

    def get_audit_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> list[dict]:
        """Query audit events."""
        conditions = ["namespace = %s"]
        params: list = [self.namespace]

        if event_type is not None:
            conditions.append("event_type = %s")
            params.append(event_type)

        if resource_type is not None:
            conditions.append("resource_type = %s")
            params.append(resource_type)

        if resource_id is not None:
            conditions.append("resource_id = %s")
            params.append(resource_id)

        params.append(limit)

        sql = f"""
            SELECT *
            FROM authn.audit_events
            WHERE {' AND '.join(conditions)}
            ORDER BY event_time DESC, id DESC
            LIMIT %s
        """

        self.cursor.execute(sql, tuple(params))
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]


# =============================================================================
# TEST HELPERS
# =============================================================================


class AuthnTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Inserting expired/invalid data that SDK would reject
    - Counting records for verification
    - Testing edge cases that require direct table manipulation
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT authn.set_tenant(%s)", (namespace,))

    def count_users(self) -> int:
        """Count users in namespace."""
        self.cursor.execute(
            "SELECT COUNT(*) FROM authn.users WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def count_sessions(self, user_id: str | None = None) -> int:
        """Count sessions, optionally filtered by user."""
        if user_id:
            self.cursor.execute(
                "SELECT COUNT(*) FROM authn.sessions WHERE namespace = %s AND user_id = %s::uuid",
                (self.namespace, user_id),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM authn.sessions WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def count_tokens(
        self, user_id: str | None = None, token_type: str | None = None
    ) -> int:
        """Count tokens, optionally filtered."""
        conditions = ["namespace = %s"]
        params: list = [self.namespace]

        if user_id:
            conditions.append("user_id = %s::uuid")
            params.append(user_id)
        if token_type:
            conditions.append("token_type = %s")
            params.append(token_type)

        self.cursor.execute(
            f"SELECT COUNT(*) FROM authn.tokens WHERE {' AND '.join(conditions)}",
            tuple(params),
        )
        return self.cursor.fetchone()[0]

    def insert_expired_session(
        self,
        user_id: str,
        token_hash: str,
        expired_ago: timedelta = timedelta(hours=1),
    ) -> str:
        """Insert an already-expired session for testing."""
        self.cursor.execute(
            """
            INSERT INTO authn.sessions (namespace, user_id, token_hash, expires_at)
            VALUES (%s, %s::uuid, %s, now() - %s)
            RETURNING id
            """,
            (self.namespace, user_id, token_hash, expired_ago),
        )
        return str(self.cursor.fetchone()[0])

    def insert_expired_token(
        self,
        user_id: str,
        token_hash: str,
        token_type: str,
        expired_ago: timedelta = timedelta(hours=1),
    ) -> str:
        """Insert an already-expired token for testing."""
        self.cursor.execute(
            """
            INSERT INTO authn.tokens (namespace, user_id, token_hash, token_type, expires_at)
            VALUES (%s, %s::uuid, %s, %s, now() - %s)
            RETURNING id
            """,
            (self.namespace, user_id, token_hash, token_type, expired_ago),
        )
        return str(self.cursor.fetchone()[0])

    def get_user_raw(self, user_id: str) -> dict | None:
        """Get user including password_hash for testing."""
        self.cursor.execute(
            "SELECT * FROM authn.users WHERE namespace = %s AND id = %s::uuid",
            (self.namespace, user_id),
        )
        result = self.cursor.fetchone()
        if result is None:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, result))
