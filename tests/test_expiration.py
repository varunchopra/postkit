"""Time-bound permission tests."""

from datetime import datetime, timedelta, timezone

import pytest


class TestExpiringPermissions:
    """Test permissions with expiration."""

    def test_grant_with_expiration(self, authz):
        """Grant with future expiration works."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=expires
        )

        assert authz.check("alice", "read", ("doc", "1")) is True

    def test_expired_permission_denied(self, authz, db_connection):
        """Expired permissions return false."""
        cursor = db_connection.cursor()

        # Grant with past expiration (bypass validation via direct SQL)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'read', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        assert authz.check("alice", "read", ("doc", "1")) is False

    def test_expiration_propagates_through_groups(self, authz):
        """Group membership expiration propagates to computed permissions."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        # Alice is member of team (expires in 1 hour)
        authz.grant(
            "member",
            resource=("team", "eng"),
            subject=("user", "alice"),
            expires_at=expires,
        )

        # Team has admin on repo (no expiration)
        authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))

        # Alice has access (via team)
        assert authz.check("alice", "admin", ("repo", "api")) is True

    def test_expiration_minimum_of_chain(self, authz, db_connection):
        """Computed expiration is minimum of all expirations in chain."""
        cursor = db_connection.cursor()

        membership_expires = datetime.now(timezone.utc) + timedelta(days=7)
        grant_expires = datetime.now(timezone.utc) + timedelta(days=30)

        authz.grant(
            "member",
            resource=("team", "eng"),
            subject=("user", "alice"),
            expires_at=membership_expires,
        )
        authz.grant(
            "admin",
            resource=("repo", "api"),
            subject=("team", "eng"),
            expires_at=grant_expires,
        )

        # Check computed expiration is the earlier one (membership)
        cursor.execute(
            """
            SELECT expires_at FROM authz.computed
            WHERE namespace = %s AND user_id = 'alice' AND resource_id = 'api'
            LIMIT 1
        """,
            (authz.namespace,),
        )

        computed_expires = cursor.fetchone()[0]
        assert abs((computed_expires - membership_expires).total_seconds()) < 1

    def test_list_users_excludes_expired(self, authz, db_connection):
        """list_users does not return users with expired permissions."""
        cursor = db_connection.cursor()

        # Alice: valid permission
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Bob: expired permission
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'read', 'user', 'bob', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        users = authz.list_users("read", ("doc", "1"))
        assert "alice" in users
        assert "bob" not in users

    def test_list_resources_excludes_expired(self, authz, db_connection):
        """list_resources does not return resources with expired permissions."""
        cursor = db_connection.cursor()

        # Alice has valid permission on doc 1
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Alice has expired permission on doc 2 (bypass validation)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '2', 'read', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        resources = authz.list_resources("alice", "doc", "read")
        assert "1" in resources
        assert "2" not in resources

    def test_past_expiration_rejected(self, authz):
        """Cannot grant with past expiration."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with pytest.raises(Exception) as exc:
            authz.grant(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                expires_at=past,
            )

        assert "future" in str(exc.value).lower()

    def test_update_expiration_via_grant(self, authz):
        """Can extend or shorten expiration by granting again."""
        original = datetime.now(timezone.utc) + timedelta(hours=1)
        extended = datetime.now(timezone.utc) + timedelta(days=7)

        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=original,
        )

        # Extend by granting again
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=extended,
        )

        expiring = authz.list_expiring(within=timedelta(days=30))
        assert len(expiring) == 1
        assert abs((expiring[0]["expires_at"] - extended).total_seconds()) < 1

    def test_hierarchy_inherits_expiration(self, authz, db_connection):
        """Implied permissions inherit expiration from source."""
        cursor = db_connection.cursor()
        expires = datetime.now(timezone.utc) + timedelta(days=7)

        # admin implies write implies read
        authz.set_hierarchy("repo", "admin", "write", "read")

        # Grant admin with expiration
        authz.grant(
            "admin",
            resource=("repo", "api"),
            subject=("user", "alice"),
            expires_at=expires,
        )

        # All permissions (admin, write, read) should have the same expiration
        cursor.execute(
            """
            SELECT DISTINCT expires_at FROM authz.computed
            WHERE namespace = %s AND user_id = 'alice' AND resource_id = 'api'
        """,
            (authz.namespace,),
        )
        expirations = [row[0] for row in cursor.fetchall()]
        assert len(expirations) == 1  # All same
        assert abs((expirations[0] - expires).total_seconds()) < 1


class TestListExpiring:
    """Test list_expiring function."""

    def test_list_expiring_within_window(self, authz):
        """Returns grants expiring within the window."""
        soon = datetime.now(timezone.utc) + timedelta(days=3)
        later = datetime.now(timezone.utc) + timedelta(days=30)

        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=soon
        )
        authz.grant(
            "read", resource=("doc", "2"), subject=("user", "bob"), expires_at=later
        )

        expiring = authz.list_expiring(within=timedelta(days=7))

        assert len(expiring) == 1
        assert expiring[0]["subject"] == ("user", "alice")

    def test_list_expiring_excludes_permanent(self, authz):
        """Permanent grants not included."""
        soon = datetime.now(timezone.utc) + timedelta(days=3)

        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=soon
        )
        authz.grant(
            "read", resource=("doc", "2"), subject=("user", "bob")
        )  # No expiration

        expiring = authz.list_expiring(within=timedelta(days=7))

        assert len(expiring) == 1
        assert expiring[0]["subject"] == ("user", "alice")

    def test_list_expiring_sorted_by_time(self, authz):
        """Results are sorted by expiration time (soonest first)."""
        day1 = datetime.now(timezone.utc) + timedelta(days=1)
        day3 = datetime.now(timezone.utc) + timedelta(days=3)
        day2 = datetime.now(timezone.utc) + timedelta(days=2)

        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=day3
        )
        authz.grant(
            "read", resource=("doc", "2"), subject=("user", "bob"), expires_at=day1
        )
        authz.grant(
            "read", resource=("doc", "3"), subject=("user", "charlie"), expires_at=day2
        )

        expiring = authz.list_expiring(within=timedelta(days=7))

        assert len(expiring) == 3
        assert expiring[0]["subject"] == ("user", "bob")
        assert expiring[1]["subject"] == ("user", "charlie")
        assert expiring[2]["subject"] == ("user", "alice")


class TestCleanupExpired:
    """Test cleanup_expired function."""

    def test_cleanup_removes_expired(self, authz, db_connection):
        """Cleanup removes expired tuples and computed entries."""
        cursor = db_connection.cursor()

        # Insert expired tuple directly
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'read', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        result = authz.cleanup_expired()

        assert result["tuples_deleted"] == 1

    def test_cleanup_preserves_valid(self, authz):
        """Cleanup does not remove non-expired grants."""
        future = datetime.now(timezone.utc) + timedelta(days=7)

        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=future
        )
        authz.grant("read", resource=("doc", "2"), subject=("user", "bob"))  # Permanent

        result = authz.cleanup_expired()

        assert result["tuples_deleted"] == 0
        assert authz.check("alice", "read", ("doc", "1")) is True
        assert authz.check("bob", "read", ("doc", "2")) is True


class TestSetExpiration:
    """Test set_expiration and related functions."""

    def test_set_expiration(self, authz):
        """Can set expiration on existing grant."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        new_expiration = datetime.now(timezone.utc) + timedelta(days=7)
        result = authz.set_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=new_expiration,
        )

        assert result is True
        expiring = authz.list_expiring(within=timedelta(days=30))
        assert len(expiring) == 1
        assert abs((expiring[0]["expires_at"] - new_expiration).total_seconds()) < 1

    def test_set_expiration_not_found(self, authz):
        """set_expiration returns false for non-existent grant."""
        result = authz.set_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

        assert result is False

    def test_clear_expiration(self, authz):
        """Can remove expiration from a grant."""
        expires = datetime.now(timezone.utc) + timedelta(days=7)
        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=expires
        )

        result = authz.clear_expiration(
            "read", resource=("doc", "1"), subject=("user", "alice")
        )

        assert result is True
        expiring = authz.list_expiring(within=timedelta(days=30))
        assert len(expiring) == 0

    def test_extend_expiration(self, authz):
        """Can extend an existing expiration."""
        original = datetime.now(timezone.utc) + timedelta(days=7)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=original,
        )

        new_expires = authz.extend_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            extension=timedelta(days=30),
        )

        expected = original + timedelta(days=30)
        assert abs((new_expires - expected).total_seconds()) < 1

    def test_extend_expiration_not_found(self, authz):
        """extend_expiration raises for non-existent grant."""
        with pytest.raises(Exception) as exc:
            authz.extend_expiration(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                extension=timedelta(days=30),
            )

        assert "not found" in str(exc.value).lower()

    def test_extend_expiration_no_expiration(self, authz):
        """extend_expiration raises if grant has no expiration."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        with pytest.raises(Exception) as exc:
            authz.extend_expiration(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                extension=timedelta(days=30),
            )

        assert "no expiration" in str(exc.value).lower()


class TestExpirationWithBatchOperations:
    """Test expiration with batch check operations."""

    def test_check_any_excludes_expired(self, authz, db_connection):
        """check_any excludes expired permissions."""
        cursor = db_connection.cursor()

        # Unexpired read
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Expired write (bypass validation)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'write', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        # Should find read but not write
        assert authz.check_any("alice", ["read", "write"], ("doc", "1")) is True
        assert authz.check("alice", "write", ("doc", "1")) is False

    def test_check_all_excludes_expired(self, authz, db_connection):
        """check_all excludes expired permissions."""
        cursor = db_connection.cursor()

        # Unexpired read
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Expired write (bypass validation)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'write', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        # Should fail because write is expired
        assert authz.check_all("alice", ["read", "write"], ("doc", "1")) is False
        assert authz.check_all("alice", ["read"], ("doc", "1")) is True

    def test_filter_authorized_excludes_expired(self, authz, db_connection):
        """filter_authorized excludes expired permissions."""
        cursor = db_connection.cursor()

        # Unexpired read on doc 1
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Expired read on doc 2 (bypass validation)
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '2', 'read', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )
        cursor.execute("SELECT authz.recompute_all(%s)", (authz.namespace,))

        authorized = authz.filter_authorized("alice", "doc", "read", ["1", "2", "3"])
        assert "1" in authorized
        assert "2" not in authorized
        assert "3" not in authorized
