from datetime import timedelta

import pytest
from postkit.presence import PresenceValidationError


def test_every_bounded_presence_api_rejects_max_plus_one(presence):
    calls = (
        (lambda: presence.heartbeat_many(["missing"] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: presence.sweep(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: presence.get_transitions(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: presence.trim(timedelta(days=1), limit=10001), "VAL_LIMIT_TOO_LARGE"),
    )
    for call, code in calls:
        with pytest.raises(PresenceValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_presence_boundaries_accept_max_and_reject_nonpositive(presence):
    assert len(presence.heartbeat_many([f"missing-{i}" for i in range(1000)])) == 1000
    for bad in (None, 0, -1):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.get_transitions(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
