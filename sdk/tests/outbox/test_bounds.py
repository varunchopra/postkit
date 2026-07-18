from datetime import timedelta

import pytest
from postkit.outbox import OutboxValidationError


def test_every_bounded_outbox_api_rejects_max_plus_one(outbox):
    calls = (
        (lambda: outbox.poll("topic", "consumer", limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: outbox.read_from("topic", 0, 0, limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: outbox.trim(timedelta(days=1), limit=10001), "VAL_LIMIT_TOO_LARGE"),
    )
    for call, code in calls:
        with pytest.raises(OutboxValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_outbox_boundaries_accept_max_and_reject_nonpositive(outbox):
    assert outbox.trim(timedelta(days=1), limit=10000) == []
    for bad in (None, 0, -1):
        with pytest.raises(OutboxValidationError) as exc_info:
            outbox.trim(timedelta(days=1), limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
