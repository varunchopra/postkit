"""Test helpers for authn - direct table access for test setup/teardown."""

from datetime import timedelta

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all authn data for a namespace.

    Delete order respects foreign key constraints (children before parents).
    Used by both authn/conftest.py and integration/conftest.py.
    """
    cursor.execute("DELETE FROM authn.audit_events WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM authn.login_attempts WHERE namespace = %s", (namespace,)
    )
    cursor.execute("DELETE FROM authn.credentials WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM authn.api_keys WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM authn.tokens WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM authn.refresh_tokens WHERE namespace = %s", (namespace,)
    )
    cursor.execute(
        "DELETE FROM authn.impersonation_sessions WHERE namespace = %s", (namespace,)
    )
    # Operator impersonation (cross-namespace) - clean up where namespace is operator or target
    cursor.execute(
        "DELETE FROM authn.operator_audit_events WHERE operator_namespace = %s OR target_namespace = %s",
        (namespace, namespace),
    )
    cursor.execute(
        "DELETE FROM authn.operator_impersonation_sessions WHERE operator_namespace = %s OR target_namespace = %s",
        (namespace, namespace),
    )
    cursor.execute("DELETE FROM authn.sessions WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM authn.users WHERE namespace = %s", (namespace,))


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
        return fetch_row(self.cursor)

    def insert_expired_refresh_token(
        self,
        user_id: str,
        session_id: str,
        token_hash: str,
        expired_ago: timedelta = timedelta(hours=1),
    ) -> str:
        """Insert an already-expired refresh token for testing."""
        self.cursor.execute(
            """
            INSERT INTO authn.refresh_tokens
                (namespace, user_id, session_id, token_hash, family_id, expires_at)
            VALUES (%s, %s::uuid, %s::uuid, %s, gen_random_uuid(), now() - %s)
            RETURNING id
            """,
            (self.namespace, user_id, session_id, token_hash, expired_ago),
        )
        return str(self.cursor.fetchone()[0])

    def count_refresh_tokens(self, user_id: str | None = None) -> int:
        """Count refresh tokens, optionally filtered by user."""
        if user_id:
            self.cursor.execute(
                """SELECT COUNT(*) FROM authn.refresh_tokens
                   WHERE namespace = %s AND user_id = %s::uuid""",
                (self.namespace, user_id),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM authn.refresh_tokens WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def count_active_refresh_tokens_in_family(self, family_id: str) -> int:
        """Count active (non-revoked, non-replaced) tokens in a family."""
        self.cursor.execute(
            """SELECT COUNT(*) FROM authn.refresh_tokens
               WHERE namespace = %s AND family_id = %s::uuid
                 AND revoked_at IS NULL AND replaced_by IS NULL""",
            (self.namespace, family_id),
        )
        return self.cursor.fetchone()[0]

    def get_refresh_token_raw(self, token_hash: str) -> dict | None:
        """Get refresh token by hash for testing."""
        self.cursor.execute(
            """SELECT * FROM authn.refresh_tokens
               WHERE namespace = %s AND token_hash = %s""",
            (self.namespace, token_hash),
        )
        return fetch_row(self.cursor)
