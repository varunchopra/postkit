"""Tests for impersonation functionality."""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authn import AuthnValidationError


class TestStartImpersonation:
    def test_creates_impersonation_session(self, authn):
        """Basic impersonation creates all required records."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        result = authn.start_impersonation(
            admin_session, target_id, "Support ticket #123", token_hash="imp_token"
        )

        assert result is not None
        assert "impersonation_id" in result
        assert "impersonation_session_id" in result
        assert "expires_at" in result

    def test_creates_session_as_target_user(self, authn):
        """Impersonation session is valid and belongs to target user."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        result = authn.start_impersonation(
            admin_session, target_id, "Support ticket #123", token_hash="imp_token"
        )

        # The impersonation session should list under target user's sessions
        sessions = authn.list_sessions(target_id)
        session_ids = [str(s["session_id"]) for s in sessions]
        assert str(result["impersonation_session_id"]) in session_ids

    def test_requires_reason(self, authn):
        """Impersonation requires a non-empty reason."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session, target_id, "", token_hash="imp_token1"
            )
        assert exc_info.value.error_code == "VAL_REASON_REQUIRED"

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session, target_id, "   ", token_hash="imp_token2"
            )
        assert exc_info.value.error_code == "VAL_REASON_REQUIRED"

    def test_prevents_self_impersonation(self, authn):
        """Cannot impersonate yourself."""
        user_id = authn.create_user("user@example.com", "hash")
        session_id = authn.create_session(user_id, "token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                session_id, user_id, "Testing self", token_hash="imp_token"
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_SELF"

    def test_prevents_impersonation_chaining(self, authn):
        """Cannot start impersonation from a regular impersonation session."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        user_b_id = authn.create_user("userb@example.com", "hash2")
        user_c_id = authn.create_user("userc@example.com", "hash3")
        admin_session = authn.create_session(admin_id, "admin_token")

        # Admin impersonates user B
        imp = authn.start_impersonation(
            admin_session, user_b_id, "Support ticket", token_hash="imp_token_b"
        )

        # Try to use the impersonation session to impersonate user C
        # This should be rejected - no chaining allowed
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                str(imp["impersonation_session_id"]),
                user_c_id,
                "Chained impersonation",
                token_hash="imp_token_c",
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_CHAIN"

    def test_prevents_cross_type_chaining_operator_to_regular(self, make_authn):
        """Cannot start regular impersonation from an operator impersonation session.

        This tests that if operator impersonates user B using operator impersonation,
        the impersonation session cannot then be used to start a regular impersonation.
        This prevents chaining across impersonation types.
        """
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        user_b_id = customer.create_user("userb@customer.com", "hash2")
        user_c_id = customer.create_user("userc@customer.com", "hash3")

        # Operator starts OPERATOR impersonation of user B
        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=user_b_id,
            target_namespace="customer",
            token_hash="imp_token_b",
            reason="Support ticket",
        )

        # Try to use the operator impersonation session for REGULAR impersonation
        # This should be prevented - no cross-type chaining allowed
        with pytest.raises(AuthnValidationError) as exc_info:
            customer.start_impersonation(
                str(imp["impersonation_session_id"]),
                user_c_id,
                "Cross-type chained impersonation",
                token_hash="imp_token_c",
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_CHAIN"

    def test_rejects_invalid_actor_session(self, authn):
        """Cannot start impersonation with invalid session."""
        target_id = authn.create_user("target@example.com", "hash")
        fake_session = "00000000-0000-0000-0000-000000000000"

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                fake_session, target_id, "Invalid session", token_hash="imp_token"
            )
        assert exc_info.value.error_code == "SESSION_ACTOR_INVALID"

    def test_rejects_disabled_target_user(self, authn):
        """Cannot impersonate a disabled user."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.disable_user(target_id)

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session, target_id, "Disabled user", token_hash="imp_token"
            )
        assert exc_info.value.error_code == "SESSION_TARGET_INVALID"

    def test_custom_duration(self, authn):
        """Can specify custom duration within limits."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        result = authn.start_impersonation(
            admin_session,
            target_id,
            "Quick check",
            token_hash="imp_token",
            duration=timedelta(minutes=30),
        )

        # Verify custom expiry was applied (30 minutes, not default 1 hour)
        expected = datetime.now(timezone.utc) + timedelta(minutes=30)
        actual = result["expires_at"]
        assert abs((expected - actual).total_seconds()) < 60

    def test_rejects_excessive_duration(self, authn):
        """Cannot exceed maximum duration."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session,
                target_id,
                "Too long",
                token_hash="imp_token",
                duration=timedelta(days=1),
            )
        assert exc_info.value.error_code == "LIMIT_DURATION_EXCEEDED"

    def test_rejects_zero_duration(self, authn):
        """Cannot use zero duration."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session,
                target_id,
                "Zero duration",
                token_hash="imp_token",
                duration=timedelta(0),
            )
        assert exc_info.value.error_code == "VAL_DURATION_POSITIVE"

    def test_rejects_negative_duration(self, authn):
        """Cannot use negative duration."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session,
                target_id,
                "Negative duration",
                token_hash="imp_token",
                duration=timedelta(minutes=-30),
            )
        assert exc_info.value.error_code == "VAL_DURATION_POSITIVE"

    def test_rejects_revoked_actor_session(self, authn):
        """Cannot start impersonation with a revoked session."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.revoke_session("admin_token")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session, target_id, "Revoked session", token_hash="imp_token"
            )
        assert exc_info.value.error_code == "SESSION_ACTOR_INVALID"

    def test_rejects_disabled_actor_user(self, authn):
        """Cannot start impersonation if actor user is disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.disable_user(admin_id)

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.start_impersonation(
                admin_session, target_id, "Disabled actor", token_hash="imp_token"
            )
        assert exc_info.value.error_code == "SESSION_ACTOR_INVALID"

    def test_creates_audit_event(self, authn):
        """Impersonation start is logged to audit."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        result = authn.start_impersonation(
            admin_session, target_id, "Support ticket #456", token_hash="imp_token"
        )

        events = authn.get_audit_events(event_type="impersonation_started")
        assert len(events) == 1
        event = events[0]
        assert event["resource_type"] == "impersonation"
        assert event["resource_id"] == str(result["impersonation_id"])
        assert event["new_values"]["actor_id"] == admin_id
        assert event["new_values"]["target_user_id"] == target_id
        assert event["new_values"]["reason"] == "Support ticket #456"


class TestEndImpersonation:
    def test_ends_impersonation(self, authn):
        """Ending impersonation marks it as ended."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )
        result = authn.end_impersonation(str(imp["impersonation_id"]))

        assert result is True

    def test_revokes_impersonation_session(self, authn):
        """Ending impersonation revokes the impersonation session."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )

        # Session should be active before ending
        sessions_before = authn.list_sessions(target_id)
        assert len(sessions_before) == 1

        authn.end_impersonation(str(imp["impersonation_id"]))

        # Session should be revoked after ending
        sessions_after = authn.list_sessions(target_id)
        assert len(sessions_after) == 0

    def test_returns_false_for_unknown(self, authn):
        """Returns false for non-existent impersonation."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        result = authn.end_impersonation(fake_id)
        assert result is False

    def test_returns_false_if_already_ended(self, authn):
        """Returns false if impersonation already ended."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        result = authn.end_impersonation(str(imp["impersonation_id"]))
        assert result is False

    def test_creates_audit_event(self, authn):
        """Ending impersonation is logged to audit."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        events = authn.get_audit_events(event_type="impersonation_ended")
        assert len(events) == 1
        event = events[0]
        assert event["resource_id"] == str(imp["impersonation_id"])


class TestGetImpersonationContext:
    def test_returns_context_for_impersonation_session(self, authn):
        """Returns impersonation context for an impersonation session."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support #123", token_hash="imp_token"
        )

        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))

        assert context["is_impersonating"] is True
        assert str(context["actor_id"]) == admin_id
        assert context["actor_email"] == "admin@example.com"
        assert str(context["target_user_id"]) == target_id
        assert context["reason"] == "Support #123"

    def test_returns_false_for_regular_session(self, authn):
        """Returns is_impersonating=false for regular sessions."""
        user_id = authn.create_user("user@example.com", "hash")
        session_id = authn.create_session(user_id, "token")

        context = authn.get_impersonation_context(session_id)

        assert context["is_impersonating"] is False

    def test_returns_false_for_ended_impersonation(self, authn):
        """Returns is_impersonating=false after impersonation ends."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))
        assert context["is_impersonating"] is False

    def test_returns_false_when_actor_disabled(self, authn):
        """Returns is_impersonating=false when the actor has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the actor
        authn.disable_user(admin_id)

        # Should return false - matches validate_session behavior
        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))
        assert context["is_impersonating"] is False

    def test_returns_false_when_session_revoked(self, authn):
        """Returns is_impersonating=false when the session has been revoked."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Revoke the session directly
        authn.revoke_session("imp_token")

        # Should return false - session is revoked
        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))
        assert context["is_impersonating"] is False

    def test_returns_false_when_target_disabled(self, authn):
        """Returns is_impersonating=false when the target user has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the target user
        authn.disable_user(target_id)

        # Should return false - matches validate_session behavior
        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))
        assert context["is_impersonating"] is False

    def test_returns_false_when_target_disabled_direct(self, authn):
        """Returns is_impersonating=false when target disabled_at is set directly."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Manually set disabled_at without revoking sessions (simulates direct DB update)
        authn.cursor.execute(
            "UPDATE authn.users SET disabled_at = now() WHERE id = %s::uuid",
            (target_id,),
        )

        # Should return false - matches validate_session behavior
        context = authn.get_impersonation_context(str(imp["impersonation_session_id"]))
        assert context["is_impersonating"] is False


class TestListActiveImpersonations:
    def test_lists_active_impersonations(self, authn):
        """Lists all active impersonations in namespace."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target1_id = authn.create_user("target1@example.com", "hash2")
        target2_id = authn.create_user("target2@example.com", "hash3")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target1_id, "Support #1", token_hash="imp_token1"
        )
        authn.start_impersonation(
            admin_session, target2_id, "Support #2", token_hash="imp_token2"
        )

        active = authn.list_active_impersonations()

        assert len(active) == 2
        target_emails = {imp["target_email"] for imp in active}
        assert target_emails == {"target1@example.com", "target2@example.com"}

    def test_excludes_ended_impersonations(self, authn):
        """Does not include ended impersonations."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash="imp_token"
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        active = authn.list_active_impersonations()
        assert len(active) == 0

    def test_excludes_impersonations_by_disabled_actor(self, authn):
        """Does not include impersonations where the actor has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the actor
        authn.disable_user(admin_id)

        # Should not be listed - the impersonation is effectively invalid
        active = authn.list_active_impersonations()
        assert len(active) == 0

    def test_excludes_impersonations_with_revoked_session(self, authn):
        """Does not include impersonations where the session was revoked directly."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Revoke the impersonation session directly (not via end_impersonation)
        authn.revoke_session("imp_token")

        # Should not be listed - the session is revoked
        active = authn.list_active_impersonations()
        assert len(active) == 0

    def test_excludes_impersonations_with_disabled_target(self, authn):
        """Does not include impersonations where the target user has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the target user
        authn.disable_user(target_id)

        # Should not be listed - the impersonation is effectively invalid
        active = authn.list_active_impersonations()
        assert len(active) == 0

    def test_excludes_impersonations_with_disabled_target_direct(self, authn):
        """Does not include impersonations where the target user disabled_at is set directly."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Manually set disabled_at without revoking sessions (simulates direct DB update)
        authn.cursor.execute(
            "UPDATE authn.users SET disabled_at = now() WHERE id = %s::uuid",
            (target_id,),
        )

        # Should not be listed - matches validate_session behavior
        active = authn.list_active_impersonations()
        assert len(active) == 0


class TestListImpersonationHistory:
    def test_includes_ended_impersonations(self, authn):
        """History includes both active and ended impersonations."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp1 = authn.start_impersonation(
            admin_session, target_id, "First", token_hash="imp_token1"
        )
        authn.end_impersonation(str(imp1["impersonation_id"]))
        authn.start_impersonation(
            admin_session, target_id, "Second", token_hash="imp_token2"
        )

        history = authn.list_impersonation_history()

        assert len(history) == 2
        active_count = sum(1 for h in history if h["is_active"])
        assert active_count == 1

    def test_is_active_false_when_actor_disabled(self, authn):
        """is_active should be false when the actor has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the actor
        authn.disable_user(admin_id)

        # is_active should be false - the impersonation is effectively invalid
        history = authn.list_impersonation_history()
        assert len(history) == 1
        assert history[0]["is_active"] is False

    def test_is_active_false_when_session_revoked(self, authn):
        """is_active should be false when the session has been revoked."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Revoke the session directly
        authn.revoke_session("imp_token")

        # is_active should be false - session is revoked
        history = authn.list_impersonation_history()
        assert len(history) == 1
        assert history[0]["is_active"] is False

    def test_is_active_false_when_target_disabled(self, authn):
        """is_active should be false when the target user has been disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Disable the target user
        authn.disable_user(target_id)

        # is_active should be false - the impersonation is effectively invalid
        history = authn.list_impersonation_history()
        assert len(history) == 1
        assert history[0]["is_active"] is False

    def test_is_active_false_when_target_disabled_direct(self, authn):
        """is_active should be false when target disabled_at is set directly."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )

        # Manually set disabled_at without revoking sessions (simulates direct DB update)
        authn.cursor.execute(
            "UPDATE authn.users SET disabled_at = now() WHERE id = %s::uuid",
            (target_id,),
        )

        # is_active should be false - matches validate_session behavior
        history = authn.list_impersonation_history()
        assert len(history) == 1
        assert history[0]["is_active"] is False

    def test_filters_by_actor(self, authn):
        """Can filter history by actor."""
        admin1_id = authn.create_user("admin1@example.com", "hash1")
        admin2_id = authn.create_user("admin2@example.com", "hash2")
        target_id = authn.create_user("target@example.com", "hash3")
        admin1_session = authn.create_session(admin1_id, "admin1_token")
        admin2_session = authn.create_session(admin2_id, "admin2_token")

        authn.start_impersonation(
            admin1_session, target_id, "Admin 1", token_hash="imp_token1"
        )
        authn.start_impersonation(
            admin2_session, target_id, "Admin 2", token_hash="imp_token2"
        )

        history = authn.list_impersonation_history(actor_id=admin1_id)

        assert len(history) == 1
        assert history[0]["actor_email"] == "admin1@example.com"

    def test_filters_by_target(self, authn):
        """Can filter history by target user."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target1_id = authn.create_user("target1@example.com", "hash2")
        target2_id = authn.create_user("target2@example.com", "hash3")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target1_id, "Target 1", token_hash="imp_token1"
        )
        authn.start_impersonation(
            admin_session, target2_id, "Target 2", token_hash="imp_token2"
        )

        history = authn.list_impersonation_history(target_user_id=target1_id)

        assert len(history) == 1
        assert history[0]["target_email"] == "target1@example.com"


class TestValidateSessionWithImpersonation:
    """Tests for validate_session returning impersonation context."""

    def test_returns_is_impersonating_false_for_normal_session(self, authn):
        """Normal sessions return is_impersonating=false."""
        user_id = authn.create_user("user@example.com", "hash")
        authn.create_session(user_id, "token_hash")

        result = authn.validate_session("token_hash")

        assert result is not None
        assert result["is_impersonating"] is False
        assert result["impersonator_id"] is None
        assert result["impersonator_email"] is None
        assert result["impersonation_reason"] is None

    def test_returns_impersonation_context(self, authn):
        """validate_session returns impersonation context for impersonation sessions."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        # Provide known token_hash so we can validate the session
        imp_token = "impersonation_session_token_hash"
        authn.start_impersonation(
            admin_session, target_id, "Support #123", token_hash=imp_token
        )

        result = authn.validate_session(imp_token)

        assert result is not None
        assert result["is_impersonating"] is True
        assert str(result["impersonator_id"]) == admin_id
        assert result["impersonator_email"] == "admin@example.com"
        assert result["impersonation_reason"] == "Support #123"
        # Verify we're authenticated as the target user
        assert str(result["user_id"]) == target_id
        assert result["email"] == "target@example.com"

    def test_returns_none_after_impersonation_ends(self, authn):
        """validate_session returns None after impersonation ends (session revoked)."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp_token = "impersonation_session_token_hash"
        imp = authn.start_impersonation(
            admin_session, target_id, "Testing", token_hash=imp_token
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        # Session is revoked when impersonation ends, so validate returns None
        result = authn.validate_session(imp_token)
        assert result is None

    def test_invalid_after_actor_disabled(self, authn):
        """Impersonation session becomes invalid if actor is disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp_token = "impersonation_token_hash"
        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash=imp_token
        )

        # Session valid before actor disabled
        assert authn.validate_session(imp_token) is not None

        # Disable the actor (admin)
        authn.disable_user(admin_id)

        # Session should now be invalid
        result = authn.validate_session(imp_token)
        assert result is None

    def test_impersonation_session_revoked_when_original_session_deleted(self, authn):
        """Impersonation session is revoked when original session is cascade deleted."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp_token = "impersonation_token_hash"
        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash=imp_token
        )

        # Session valid initially
        assert authn.validate_session(imp_token) is not None

        # Revoke original session and run cleanup (which deletes it)
        authn.revoke_session("admin_token")
        authn.cleanup_expired()

        # Impersonation session should also be invalid (revoked by trigger)
        result = authn.validate_session(imp_token)
        assert result is None
