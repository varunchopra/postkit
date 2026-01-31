"""
Transaction semantics tests for postkit/authz.

Tests for:
- Rollback behavior
- Atomicity and isolation of multiple writes
"""

import psycopg

from tests.conftest import DATABASE_URL


class TestTransactionSemantics:
    """Verify transactional behavior."""

    def test_rollback_reverts_permission(self, make_authz):
        """Rolled-back grants should not persist."""
        checker = make_authz("test_rollback")

        conn = psycopg.connect(DATABASE_URL, autocommit=False)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT authz.write('doc', '1', 'read', 'user', 'alice', 'test_rollback')"
            )
            conn.rollback()
        finally:
            conn.close()

        assert not checker.check(("user", "alice"), "read", ("doc", "1"))

    def test_multiple_writes_atomic(self, make_authz):
        """Multiple writes in one transaction are atomic and isolated."""
        checker = make_authz("test_atomic")

        conn = psycopg.connect(DATABASE_URL, autocommit=False)
        try:
            cursor = conn.cursor()

            # Two writes in same transaction
            cursor.execute(
                "SELECT authz.write('team', 'eng', 'member', 'user', 'alice', 'test_atomic')"
            )
            cursor.execute(
                "SELECT authz.write('doc', '1', 'read', 'team', 'eng', 'test_atomic')"
            )

            # Within transaction: visible to the writing connection
            cursor.execute(
                "SELECT authz.check('user', 'alice', 'read', 'doc', '1', 'test_atomic')"
            )
            assert cursor.fetchone()[0] is True

            # Before commit: invisible to other connections
            assert not checker.check(("user", "alice"), "read", ("doc", "1"))

            conn.commit()
        finally:
            conn.close()

        # After commit: visible to other connections
        assert checker.check(("user", "alice"), "read", ("doc", "1"))
