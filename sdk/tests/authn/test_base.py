"""Tests for base client functionality (S13, S14, S16)."""

import pytest
from postkit.authn import AuthnClient
from postkit.base import UniqueViolationError
from psycopg.rows import dict_row, kwargs_row


class TestRowFactoryValidation:
    """Tests for S13: Row factory detection."""

    def test_rejects_dict_row_factory(self, db_connection):
        """Cursor with dict_row should be rejected at init."""
        cursor = db_connection.cursor(row_factory=dict_row)
        try:
            with pytest.raises(ValueError, match="tuple row factory") as exc_info:
                AuthnClient(cursor, "test_reject_dict")

            # Message explains the SDK returns dicts automatically.
            assert "SDK returns dicts automatically" in str(exc_info.value)
        finally:
            cursor.close()

    def test_rejects_kwargs_row_factory(self, db_connection):
        """Cursor with kwargs_row should be rejected at init."""
        cursor = db_connection.cursor(row_factory=kwargs_row)
        try:
            with pytest.raises(ValueError, match="tuple row factory"):
                AuthnClient(cursor, "test_reject_kwargs")
        finally:
            cursor.close()

    def test_accepts_default_row_factory(self, db_connection):
        """Default tuple row factory should be accepted."""
        cursor = db_connection.cursor()
        try:
            client = AuthnClient(cursor, "test_accept_default")
            assert client is not None
            assert client.namespace == "test_accept_default"
        finally:
            cursor.close()


class TestErrorHandling:
    """Tests for S14: SQLSTATE preservation."""

    def test_unique_violation_raises_specific_exception(self, authn):
        """Duplicate email should raise UniqueViolationError with SQLSTATE preserved."""
        authn.create_user("duplicate@example.com", "hash1")

        with pytest.raises(UniqueViolationError) as exc_info:
            authn.create_user("duplicate@example.com", "hash2")

        assert exc_info.value.sqlstate == "23505"
        # PostgreSQL error message is passed through, not swallowed.
        assert str(exc_info.value)


class TestNormalizeValue:
    """Tests for value type normalization in _normalize_value."""

    def test_uuid_normalized_to_str(self, authn):
        """UUID values from DB are converted to str."""
        user_id = authn.create_user("uuid_test@example.com", "hash")
        user = authn.get_user(user_id)

        # Verify returned user_id in dict is a string, not UUID object
        assert isinstance(user["user_id"], str), (
            f"Expected str, got {type(user['user_id'])}"
        )
        assert len(user["user_id"]) == 36  # UUID string format: 8-4-4-4-12

    def test_ipv4_address_normalized_to_str(self, authn):
        """IPv4Address values from DB are converted to str."""
        user_id = authn.create_user("ipv4_test@example.com", "hash")
        authn.create_session(user_id, "token_hash", ip_address="192.168.1.100")
        sessions = authn.list_sessions(user_id)

        ip = sessions[0]["ip_address"]
        assert isinstance(ip, str), f"Expected str, got {type(ip)}"
        assert ip == "192.168.1.100"

    def test_ipv6_address_normalized_to_str(self, authn):
        """IPv6Address values from DB are converted to str."""
        user_id = authn.create_user("ipv6_test@example.com", "hash")
        authn.create_session(user_id, "token_hash", ip_address="::1")
        sessions = authn.list_sessions(user_id)

        ip = sessions[0]["ip_address"]
        assert isinstance(ip, str), f"Expected str, got {type(ip)}"
