"""Tests for cross-namespace operator impersonation functionality."""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authn import AuthnValidationError


class TestStartOperatorImpersonation:
    """Tests for authn.start_operator_impersonation()."""

    def test_creates_cross_namespace_impersonation(self, make_authn):
        """Operator in one namespace can impersonate user in another."""
        # Setup: operator in platform namespace, target in customer namespace
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("user@customer.com", "hash2")

        # Start operator impersonation
        result = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token_hash",
            reason="Support ticket #123",
        )

        assert result is not None
        assert "impersonation_id" in result
        assert "impersonation_session_id" in result
        assert "expires_at" in result

    def test_creates_session_in_target_namespace(self, make_authn):
        """Impersonation session is created in target namespace."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("user@customer.com", "hash2")

        result = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token_hash",
            reason="Support ticket #123",
        )

        # The impersonation session should be in the customer namespace
        # and list under the target user's sessions
        sessions = customer.list_sessions(target_id)
        session_ids = [str(s["session_id"]) for s in sessions]
        assert str(result["impersonation_session_id"]) in session_ids

    def test_requires_reason(self, make_authn):
        """Operator impersonation requires a non-empty reason."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("user@customer.com", "hash2")

        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=operator_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token1",
                reason="",
            )
        assert exc_info.value.error_code == "VAL_REASON_REQUIRED"

        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=operator_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token2",
                reason="   ",
            )
        assert exc_info.value.error_code == "VAL_REASON_REQUIRED"

    def test_prevents_self_impersonation_cross_namespace(self, make_authn):
        """Cannot impersonate yourself even across namespaces."""
        # When user exists in both namespaces with same ID (unlikely but possible)
        ns1 = make_authn("ns1")

        user_id = ns1.create_user("user@example.com", "hash")
        session_id = ns1.create_session(user_id, "token")

        with pytest.raises(AuthnValidationError) as exc_info:
            ns1.start_operator_impersonation(
                operator_session_id=session_id,
                target_user_id=user_id,
                target_namespace="ns1",
                token_hash="imp_token",
                reason="Testing self",
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_SELF"

    def test_prevents_impersonation_chaining(self, make_authn):
        """Cannot start operator impersonation from an operator impersonation session."""
        platform = make_authn("platform")
        customer = make_authn("customer")
        other = make_authn("other")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        user_b_id = customer.create_user("userb@customer.com", "hash2")
        user_c_id = other.create_user("userc@other.com", "hash3")

        # Operator impersonates user B
        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=user_b_id,
            target_namespace="customer",
            token_hash="imp_token_b",
            reason="Support ticket",
        )

        # Try to use the impersonation session to impersonate user C
        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=str(imp["impersonation_session_id"]),
                target_user_id=user_c_id,
                target_namespace="other",
                token_hash="imp_token_c",
                reason="Chained impersonation",
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_CHAIN"

    def test_prevents_cross_type_chaining_regular_to_operator(self, make_authn):
        """Cannot start operator impersonation from a regular impersonation session.

        This tests that if admin A impersonates user B using regular impersonation,
        the impersonation session cannot then be used to start an operator impersonation.
        This prevents chaining across impersonation types.
        """
        platform = make_authn("platform")
        customer = make_authn("customer")

        admin_id = platform.create_user("admin@platform.com", "hash1")
        user_b_id = platform.create_user("userb@platform.com", "hash2")
        admin_session = platform.create_session(admin_id, "admin_token")

        target_id = customer.create_user("target@customer.com", "hash3")

        # Admin starts REGULAR impersonation of user B in same namespace
        imp = platform.start_impersonation(
            admin_session, user_b_id, "Support ticket", token_hash="imp_token_b"
        )

        # Try to use the regular impersonation session for operator impersonation
        # This should be prevented - no cross-type chaining allowed
        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=str(imp["impersonation_session_id"]),
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token_c",
                reason="Cross-type chained impersonation",
            )
        assert exc_info.value.error_code == "BIZ_IMPERSONATE_CHAIN"

    def test_rejects_invalid_operator_session(self, make_authn):
        """Cannot start operator impersonation with invalid session."""
        customer = make_authn("customer")
        target_id = customer.create_user("target@customer.com", "hash")
        fake_session = "00000000-0000-0000-0000-000000000000"

        with pytest.raises(AuthnValidationError) as exc_info:
            customer.start_operator_impersonation(
                operator_session_id=fake_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token",
                reason="Invalid session",
            )
        assert exc_info.value.error_code == "SESSION_OPERATOR_INVALID"

    def test_rejects_disabled_target_user(self, make_authn):
        """Cannot impersonate a disabled user."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")
        customer.disable_user(target_id)

        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=operator_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token",
                reason="Disabled user",
            )
        assert exc_info.value.error_code == "SESSION_TARGET_INVALID"

    def test_custom_duration(self, make_authn):
        """Can specify custom duration within limits."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        result = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Quick check",
            duration=timedelta(minutes=15),
        )

        # Verify custom expiry was applied
        expected = datetime.now(timezone.utc) + timedelta(minutes=15)
        actual = result["expires_at"]
        assert abs((expected - actual).total_seconds()) < 60

    def test_rejects_excessive_duration(self, make_authn):
        """Cannot exceed maximum duration (4 hours for operator impersonation)."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=operator_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token",
                reason="Too long",
                duration=timedelta(hours=5),
            )
        assert exc_info.value.error_code == "LIMIT_DURATION_EXCEEDED"

    def test_rejects_zero_duration(self, make_authn):
        """Cannot use zero duration."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        with pytest.raises(AuthnValidationError) as exc_info:
            platform.start_operator_impersonation(
                operator_session_id=operator_session,
                target_user_id=target_id,
                target_namespace="customer",
                token_hash="imp_token",
                reason="Zero duration",
                duration=timedelta(0),
            )
        assert exc_info.value.error_code == "VAL_DURATION_POSITIVE"

    def test_stores_ticket_reference(self, make_authn):
        """Ticket reference is stored in impersonation record."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support ticket",
            ticket_reference="ZENDESK-12345",
        )

        # Verify ticket reference is in audit events
        events = platform.get_operator_audit_events(
            event_type="operator_impersonation_started"
        )
        assert len(events) == 1
        assert events[0]["ticket_reference"] == "ZENDESK-12345"

    def test_creates_audit_event(self, make_authn):
        """Operator impersonation start is logged to operator audit."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        result = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support ticket #456",
        )

        events = platform.get_operator_audit_events(
            event_type="operator_impersonation_started"
        )
        assert len(events) == 1
        event = events[0]
        assert event["operator_namespace"] == "platform"
        assert str(event["operator_id"]) == operator_id
        assert event["operator_email"] == "operator@platform.com"
        assert event["target_namespace"] == "customer"
        assert str(event["target_user_id"]) == target_id
        assert event["target_user_email"] == "target@customer.com"
        assert event["reason"] == "Support ticket #456"
        assert event["details"]["impersonation_id"] == str(result["impersonation_id"])


class TestEndOperatorImpersonation:
    """Tests for authn.end_operator_impersonation()."""

    def test_ends_impersonation(self, make_authn):
        """Ending impersonation marks it as ended."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )

        result = platform.end_operator_impersonation(str(imp["impersonation_id"]))
        assert result is True

    def test_revokes_impersonation_session(self, make_authn):
        """Ending impersonation revokes the impersonation session."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )

        # Session should be active before ending
        sessions_before = customer.list_sessions(target_id)
        assert len(sessions_before) == 1

        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        # Session should be revoked after ending
        sessions_after = customer.list_sessions(target_id)
        assert len(sessions_after) == 0

    def test_returns_false_for_unknown(self, make_authn):
        """Returns false for non-existent impersonation."""
        platform = make_authn("platform")
        fake_id = "00000000-0000-0000-0000-000000000000"
        result = platform.end_operator_impersonation(fake_id)
        assert result is False

    def test_returns_false_if_already_ended(self, make_authn):
        """Returns false if impersonation already ended."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )

        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        result = platform.end_operator_impersonation(str(imp["impersonation_id"]))
        assert result is False

    def test_creates_audit_event(self, make_authn):
        """Ending impersonation is logged to operator audit."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )
        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        events = platform.get_operator_audit_events(
            event_type="operator_impersonation_ended"
        )
        assert len(events) == 1
        assert events[0]["details"]["impersonation_id"] == str(imp["impersonation_id"])


class TestGetOperatorImpersonationContext:
    """Tests for authn.get_operator_impersonation_context()."""

    def test_returns_context_for_operator_impersonation_session(self, make_authn):
        """Returns operator impersonation context for an impersonation session."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support #123",
            ticket_reference="ZENDESK-456",
        )

        context = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )

        assert context["is_operator_impersonating"] is True
        assert str(context["operator_id"]) == operator_id
        assert context["operator_email"] == "operator@platform.com"
        assert context["operator_namespace"] == "platform"
        assert str(context["target_user_id"]) == target_id
        assert context["target_user_email"] == "target@customer.com"
        assert context["target_namespace"] == "customer"
        assert context["reason"] == "Support #123"
        assert context["ticket_reference"] == "ZENDESK-456"

    def test_returns_false_for_regular_session(self, make_authn):
        """Returns is_operator_impersonating=false for regular sessions."""
        platform = make_authn("platform")
        user_id = platform.create_user("user@platform.com", "hash")
        session_id = platform.create_session(user_id, "token")

        context = platform.get_operator_impersonation_context(session_id)

        assert context["is_operator_impersonating"] is False

    def test_returns_false_for_ended_impersonation(self, make_authn):
        """Returns is_operator_impersonating=false after impersonation ends."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )
        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        context = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )
        assert context["is_operator_impersonating"] is False

    def test_returns_false_when_operator_disabled(self, make_authn):
        """Context should return false if operator user is disabled after impersonation starts.

        This is a consistency check - regular impersonation's get_impersonation_context
        checks actor.disabled_at IS NULL, so operator impersonation should do the same.
        """
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )

        # Verify context returns true before disabling
        context_before = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )
        assert context_before["is_operator_impersonating"] is True

        # Disable the operator user
        platform.disable_user(operator_id)

        # Context should now return false (operator disabled)
        context_after = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )
        assert context_after["is_operator_impersonating"] is False

    def test_returns_false_when_target_disabled(self, make_authn):
        """Context should return false if target user is disabled after impersonation starts.

        This is a consistency check - regular impersonation's get_impersonation_context
        checks target.disabled_at IS NULL, so operator impersonation should do the same.
        """
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Testing",
        )

        # Verify context returns true before disabling
        context_before = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )
        assert context_before["is_operator_impersonating"] is True

        # Disable the target user
        customer.disable_user(target_id)

        # Context should now return false (target disabled)
        context_after = platform.get_operator_impersonation_context(
            str(imp["impersonation_session_id"])
        )
        assert context_after["is_operator_impersonating"] is False


class TestListOperatorImpersonationsForTarget:
    """Tests for authn.list_operator_impersonations_for_target()."""

    def test_lists_impersonations_affecting_namespace(self, make_authn):
        """Lists all impersonations affecting a target namespace."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target1_id = customer.create_user("target1@customer.com", "hash2")
        target2_id = customer.create_user("target2@customer.com", "hash3")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target1_id,
            target_namespace="customer",
            token_hash="imp_token1",
            reason="Support #1",
        )
        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target2_id,
            target_namespace="customer",
            token_hash="imp_token2",
            reason="Support #2",
        )

        history = platform.list_operator_impersonations_for_target("customer")

        assert len(history) == 2
        target_emails = {h["target_user_email"] for h in history}
        assert target_emails == {"target1@customer.com", "target2@customer.com"}

    def test_includes_ended_impersonations(self, make_authn):
        """History includes both active and ended impersonations."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp1 = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token1",
            reason="First",
        )
        platform.end_operator_impersonation(str(imp1["impersonation_id"]))

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token2",
            reason="Second",
        )

        history = platform.list_operator_impersonations_for_target("customer")

        assert len(history) == 2
        active_count = sum(1 for h in history if h["is_active"])
        assert active_count == 1

    def test_filters_by_target_user(self, make_authn):
        """Can filter by specific target user."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target1_id = customer.create_user("target1@customer.com", "hash2")
        target2_id = customer.create_user("target2@customer.com", "hash3")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target1_id,
            target_namespace="customer",
            token_hash="imp_token1",
            reason="Target 1",
        )
        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target2_id,
            target_namespace="customer",
            token_hash="imp_token2",
            reason="Target 2",
        )

        history = platform.list_operator_impersonations_for_target(
            "customer", target_user_id=target1_id
        )

        assert len(history) == 1
        assert history[0]["target_user_email"] == "target1@customer.com"


class TestListOperatorImpersonationsByOperator:
    """Tests for authn.list_operator_impersonations_by_operator()."""

    def test_lists_impersonations_by_operator(self, make_authn):
        """Lists all impersonations performed by an operator."""
        platform = make_authn("platform")
        customer1 = make_authn("customer1")
        customer2 = make_authn("customer2")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target1_id = customer1.create_user("target1@customer1.com", "hash2")
        target2_id = customer2.create_user("target2@customer2.com", "hash3")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target1_id,
            target_namespace="customer1",
            token_hash="imp_token1",
            reason="Support in customer1",
        )
        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target2_id,
            target_namespace="customer2",
            token_hash="imp_token2",
            reason="Support in customer2",
        )

        history = platform.list_operator_impersonations_by_operator(
            operator_id, "platform"
        )

        assert len(history) == 2
        target_namespaces = {h["target_namespace"] for h in history}
        assert target_namespaces == {"customer1", "customer2"}


class TestListActiveOperatorImpersonations:
    """Tests for authn.list_active_operator_impersonations()."""

    def test_lists_only_active_impersonations(self, make_authn):
        """Lists only currently active impersonations."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target1_id = customer.create_user("target1@customer.com", "hash2")
        target2_id = customer.create_user("target2@customer.com", "hash3")

        imp1 = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target1_id,
            target_namespace="customer",
            token_hash="imp_token1",
            reason="Support #1",
        )
        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target2_id,
            target_namespace="customer",
            token_hash="imp_token2",
            reason="Support #2",
        )

        # End one impersonation
        platform.end_operator_impersonation(str(imp1["impersonation_id"]))

        active = platform.list_active_operator_impersonations()

        assert len(active) == 1
        assert active[0]["target_user_email"] == "target2@customer.com"


class TestGetOperatorAuditEvents:
    """Tests for authn.get_operator_audit_events()."""

    def test_filters_by_target_namespace(self, make_authn):
        """Can filter audit events by target namespace."""
        platform = make_authn("platform")
        customer1 = make_authn("customer1")
        customer2 = make_authn("customer2")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target1_id = customer1.create_user("target1@customer1.com", "hash2")
        target2_id = customer2.create_user("target2@customer2.com", "hash3")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target1_id,
            target_namespace="customer1",
            token_hash="imp_token1",
            reason="Support in customer1",
        )
        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target2_id,
            target_namespace="customer2",
            token_hash="imp_token2",
            reason="Support in customer2",
        )

        events = platform.get_operator_audit_events(target_namespace="customer1")

        assert len(events) == 1
        assert events[0]["target_namespace"] == "customer1"

    def test_filters_by_event_type(self, make_authn):
        """Can filter audit events by event type."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")

        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support",
        )
        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        started_events = platform.get_operator_audit_events(
            event_type="operator_impersonation_started"
        )
        ended_events = platform.get_operator_audit_events(
            event_type="operator_impersonation_ended"
        )

        assert len(started_events) == 1
        assert len(ended_events) == 1
