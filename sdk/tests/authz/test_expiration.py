"""Time-bound permission tests."""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authz import AuthzError, AuthzErrorCode
from postkit.base import CheckViolationError


class TestExpiringPermissions:
    """Test permissions with expiration."""

    def test_grant_with_expiration(self, authz):
        """Grant with future expiration works and stores the timestamp."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        authz.grant(
            "read", resource=("doc", "1"), subject=("user", "alice"), expires_at=expires
        )

        assert authz.check(("user", "alice"), "read", ("doc", "1")) is True

        # Verify expiration was actually stored.
        expiring = authz.list_expiring(within=timedelta(days=1))
        assert len(expiring) == 1
        assert abs((expiring[0]["expires_at"] - expires).total_seconds()) < 1

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

        assert authz.check(("user", "alice"), "read", ("doc", "1")) is False

    def test_expiration_propagates_through_groups(self, authz):
        """Group membership expiration propagates to permissions."""
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
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is True

    def test_expired_membership_blocks_access(self, authz, db_connection):
        """Expired membership blocks access even if grant is valid."""
        cursor = db_connection.cursor()

        # Insert expired membership
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'team', 'eng', 'member', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )

        # Team has admin on repo (no expiration)
        authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))

        # Alice does NOT have access because membership is expired
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is False

    def test_list_subjects_excludes_expired(self, authz, db_connection):
        """list_subjects does not return subjects with expired permissions."""
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

        subjects = authz.list_subjects("read", ("doc", "1"))
        assert ("user", "alice") in subjects
        assert ("user", "bob") not in subjects

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

        resources = authz.list_resources(("user", "alice"), "doc", "read")
        assert "1" in resources
        assert "2" not in resources

    def test_past_expiration_rejected(self, authz):
        """Cannot grant with past expiration."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with pytest.raises(CheckViolationError) as exc_info:
            authz.grant(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                expires_at=past,
            )
        assert exc_info.value.error_code == AuthzErrorCode.VAL_EXPIRATION_FUTURE
        authz.cursor.execute(
            "SELECT count(*) FROM authz.tuples "
            "WHERE namespace = %s AND resource_id = '1' AND subject_id = 'alice'",
            (authz.namespace,),
        )
        assert authz.cursor.fetchone()[0] == 0

    def test_regrant_ignores_expired_requested_expiration(self, authz):
        requested = datetime.now(timezone.utc) + timedelta(hours=1)
        existing_expiry = datetime.now(timezone.utc) - timedelta(hours=1)
        tuple_id = authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=requested,
        )
        authz.cursor.execute(
            "UPDATE authz.tuples SET expires_at = %s WHERE id = %s",
            (existing_expiry, tuple_id),
        )

        assert (
            authz.grant(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                expires_at=requested - timedelta(hours=2),
            )
            == tuple_id
        )
        authz.cursor.execute(
            "SELECT expires_at FROM authz.tuples WHERE id = %s", (tuple_id,)
        )
        assert authz.cursor.fetchone()[0] == existing_expiry

    def test_regrant_preserves_existing_expiration(self, authz):
        """An explicit expiration on a re-grant does not replace the original."""
        original = datetime.now(timezone.utc) + timedelta(hours=1)
        extended = datetime.now(timezone.utc) + timedelta(days=7)

        tuple_id = authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=original,
        )

        regrant_id = authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=extended,
        )

        expiring = authz.list_expiring(within=timedelta(days=30))
        assert regrant_id == tuple_id
        assert len(expiring) == 1
        assert abs((expiring[0]["expires_at"] - original).total_seconds()) < 1

    def test_regrant_without_expiration_preserves_existing_expiration(self, authz):
        original = datetime.now(timezone.utc) + timedelta(hours=1)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=original,
        )

        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        expiring = authz.list_expiring(within=timedelta(days=1))
        assert len(expiring) == 1
        assert abs((expiring[0]["expires_at"] - original).total_seconds()) < 1

    def test_regrant_cannot_add_expiration_to_permanent_grant(self, authz):
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        assert authz.list_expiring(within=timedelta(days=1)) == []
        assert authz.check(("user", "alice"), "read", ("doc", "1"))

    def test_hierarchy_with_expiration(self, authz):
        """Implied permissions work correctly with expiration."""
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

        # All permissions should work
        assert authz.check(("user", "alice"), "admin", ("repo", "api"))
        assert authz.check(("user", "alice"), "write", ("repo", "api"))
        assert authz.check(("user", "alice"), "read", ("repo", "api"))

    def test_expired_hierarchy_blocks_implied_permissions(self, authz, db_connection):
        """Expired grant blocks all implied permissions through hierarchy."""
        cursor = db_connection.cursor()

        # admin implies write implies read
        authz.set_hierarchy("repo", "admin", "write", "read")

        # Insert expired admin grant (bypass validation).
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'repo', 'api', 'admin', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )

        # All implied permissions must also be denied.
        assert authz.check(("user", "alice"), "admin", ("repo", "api")) is False
        assert authz.check(("user", "alice"), "write", ("repo", "api")) is False
        assert authz.check(("user", "alice"), "read", ("repo", "api")) is False


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
        """Cleanup removes expired tuples."""
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
        assert authz.check(("user", "alice"), "read", ("doc", "1")) is True
        assert authz.check(("user", "bob"), "read", ("doc", "2")) is True


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

    def test_clear_expiration_matches_subject_relation(self, authz):
        """Clearing expiration on a direct grant leaves a userset grant that
        differs only by subject_relation untouched."""
        direct_expires = datetime.now(timezone.utc) + timedelta(days=7)
        userset_expires = datetime.now(timezone.utc) + timedelta(days=14)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            expires_at=direct_expires,
        )
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            subject_relation="member",
            expires_at=userset_expires,
        )

        result = authz.clear_expiration(
            "read", resource=("doc", "1"), subject=("team", "eng")
        )

        assert result is True
        expiring = authz.list_expiring(within=timedelta(days=30))
        assert len(expiring) == 1
        assert expiring[0]["subject_relation"] == "member"
        assert abs((expiring[0]["expires_at"] - userset_expires).total_seconds()) < 1

    def test_extend_expiration_matches_subject_relation(self, authz):
        """Extending a userset grant's expiration leaves a direct grant that
        differs only by subject_relation untouched."""
        direct_expires = datetime.now(timezone.utc) + timedelta(days=7)
        userset_expires = datetime.now(timezone.utc) + timedelta(days=14)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            expires_at=direct_expires,
        )
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            subject_relation="member",
            expires_at=userset_expires,
        )

        new_expires = authz.extend_expiration(
            "read",
            resource=("doc", "1"),
            subject=("team", "eng"),
            subject_relation="member",
            extension=timedelta(days=30),
        )

        expected = userset_expires + timedelta(days=30)
        assert abs((new_expires - expected).total_seconds()) < 1
        by_relation = {
            row["subject_relation"]: row["expires_at"]
            for row in authz.list_expiring(within=timedelta(days=60))
        }
        assert abs((by_relation[None] - direct_expires).total_seconds()) < 1
        assert abs((by_relation["member"] - expected).total_seconds()) < 1

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
        with pytest.raises(AuthzError) as exc_info:
            authz.extend_expiration(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                extension=timedelta(days=30),
            )
        assert exc_info.value.error_code == AuthzErrorCode.DATA_GRANT_NOT_FOUND

    def test_extend_expiration_no_expiration(self, authz):
        """extend_expiration raises if grant has no expiration."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        with pytest.raises(AuthzError) as exc_info:
            authz.extend_expiration(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                extension=timedelta(days=30),
            )
        assert exc_info.value.error_code == AuthzErrorCode.BIZ_GRANT_NO_EXPIRATION

    def test_extend_already_expired_anchors_from_now(self, authz, db_connection):
        """Extending an already-expired grant anchors from now(), not the past timestamp."""
        cursor = db_connection.cursor()

        # Insert a grant that expired 1 hour ago (bypass validation).
        cursor.execute(
            """
            INSERT INTO authz.tuples
                (namespace, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
            VALUES (%s, 'doc', '1', 'read', 'user', 'alice', now() - interval '1 hour')
        """,
            (authz.namespace,),
        )

        extension = timedelta(days=30)
        new_expires = authz.extend_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            extension=extension,
        )

        # Should be ~30 days from now, not ~29 days 23 hours ago + 30 days.
        expected = datetime.now(timezone.utc) + extension
        assert abs((new_expires - expected).total_seconds()) < 5

    def test_set_expiration_rejects_past_timestamp(self, authz):
        """set_expiration rejects timestamps in the past."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        past = datetime.now(timezone.utc) - timedelta(hours=1)
        with pytest.raises(CheckViolationError) as exc_info:
            authz.set_expiration(
                "read",
                resource=("doc", "1"),
                subject=("user", "alice"),
                expires_at=past,
            )
        assert exc_info.value.error_code == AuthzErrorCode.VAL_EXPIRATION_FUTURE


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

        # Should find read but not write
        assert (
            authz.check_any(("user", "alice"), ["read", "write"], ("doc", "1")) is True
        )
        assert authz.check(("user", "alice"), "write", ("doc", "1")) is False

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

        # Should fail because write is expired
        assert (
            authz.check_all(("user", "alice"), ["read", "write"], ("doc", "1")) is False
        )
        assert authz.check_all(("user", "alice"), ["read"], ("doc", "1")) is True

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

        authorized = authz.filter_authorized(
            ("user", "alice"), "doc", "read", ["1", "2", "3"]
        )
        assert "1" in authorized
        assert "2" not in authorized
        assert "3" not in authorized
