import pytest
from postkit.authn import AuthnValidationError


def test_every_bounded_authn_api_rejects_max_plus_one(authn):
    zero_uuid = "00000000-0000-0000-0000-000000000000"
    calls = (
        (lambda: authn.get_users_batch([zero_uuid] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: authn.list_impersonation_history(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: authn.cleanup_expired(batch_size=10001), "VAL_LIMIT_TOO_LARGE"),
        (
            lambda: authn.cleanup_expired_operator_sessions(batch_size=10001),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (
            lambda: authn.list_operator_impersonations_for_target(
                authn.namespace, limit=1001
            ),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (
            lambda: authn.list_operator_impersonations_by_operator(
                zero_uuid, authn.namespace, limit=1001
            ),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (
            lambda: authn.list_active_operator_impersonations(limit=1001),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (lambda: authn.get_operator_audit_events(limit=1001), "VAL_LIMIT_TOO_LARGE"),
    )
    for call, code in calls:
        with pytest.raises(AuthnValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_authn_boundaries_accept_max_and_reject_nonpositive(authn):
    zero_uuid = "00000000-0000-0000-0000-000000000000"
    assert authn.get_users_batch([zero_uuid] * 1000) == {}
    for bad in (None, 0, -1):
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.list_impersonation_history(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
