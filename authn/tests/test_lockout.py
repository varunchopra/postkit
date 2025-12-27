"""Tests for lockout management functions."""

import pytest
from datetime import timedelta


class TestRecordLoginAttempt:
    def test_records_successful_attempt(self, authn):
        authn.record_login_attempt("alice@example.com", True)

        attempts = authn.get_recent_attempts("alice@example.com")
        assert len(attempts) == 1
        assert attempts[0]["success"] is True

    def test_records_failed_attempt(self, authn):
        authn.record_login_attempt("alice@example.com", False)

        attempts = authn.get_recent_attempts("alice@example.com")
        assert len(attempts) == 1
        assert attempts[0]["success"] is False

    def test_stores_ip_address(self, authn):
        authn.record_login_attempt("alice@example.com", True, ip_address="192.168.1.1")

        attempts = authn.get_recent_attempts("alice@example.com")
        assert str(attempts[0]["ip_address"]) == "192.168.1.1"


class TestIsLockedOut:
    def test_returns_false_with_no_attempts(self, authn):
        assert authn.is_locked_out("alice@example.com") is False

    def test_returns_false_under_threshold(self, authn):
        for _ in range(4):  # Default max is 5
            authn.record_login_attempt("alice@example.com", False)

        assert authn.is_locked_out("alice@example.com") is False

    def test_returns_true_at_threshold(self, authn):
        for _ in range(5):
            authn.record_login_attempt("alice@example.com", False)

        assert authn.is_locked_out("alice@example.com") is True

    def test_only_counts_failed_attempts(self, authn):
        # Mix of success and failure
        for _ in range(3):
            authn.record_login_attempt("alice@example.com", False)
        for _ in range(10):
            authn.record_login_attempt("alice@example.com", True)
        for _ in range(1):
            authn.record_login_attempt("alice@example.com", False)

        # Only 4 failures, should not be locked out
        assert authn.is_locked_out("alice@example.com") is False

    def test_custom_threshold(self, authn):
        for _ in range(2):
            authn.record_login_attempt("alice@example.com", False)

        # Not locked with default threshold
        assert authn.is_locked_out("alice@example.com", max_attempts=5) is False

        # Locked with lower threshold
        assert authn.is_locked_out("alice@example.com", max_attempts=2) is True

    def test_sliding_window(self, authn, test_helpers):
        # Insert old attempts outside the window
        for i in range(5):
            test_helpers.cursor.execute(
                """
                INSERT INTO authn.login_attempts
                (namespace, email, success, attempted_at)
                VALUES (%s, %s, false, now() - interval '1 hour')
                """,
                (authn.namespace, "alice@example.com"),
            )

        # Should not be locked (attempts are old)
        assert (
            authn.is_locked_out(
                "alice@example.com",
                window=timedelta(minutes=15),
            )
            is False
        )

    def test_returns_false_for_nonexistent_email(self, authn):
        """Verifies no error is raised for emails that don't exist."""
        assert authn.is_locked_out("nonexistent@example.com") is False


class TestGetRecentAttempts:
    def test_returns_attempts_in_order(self, authn):
        for i in range(3):
            authn.record_login_attempt("alice@example.com", i % 2 == 0)

        attempts = authn.get_recent_attempts("alice@example.com")

        assert len(attempts) == 3
        # Most recent first
        assert attempts[0]["attempted_at"] >= attempts[1]["attempted_at"]

    def test_respects_limit(self, authn):
        for _ in range(10):
            authn.record_login_attempt("alice@example.com", False)

        attempts = authn.get_recent_attempts("alice@example.com", limit=3)
        assert len(attempts) == 3


class TestClearAttempts:
    def test_clears_all_attempts(self, authn):
        for _ in range(5):
            authn.record_login_attempt("alice@example.com", False)

        count = authn.clear_attempts("alice@example.com")

        assert count == 5
        assert authn.is_locked_out("alice@example.com") is False

    def test_returns_zero_if_no_attempts(self, authn):
        count = authn.clear_attempts("alice@example.com")
        assert count == 0
