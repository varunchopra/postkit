from datetime import timedelta

import pytest
from postkit.lease import LeaseValidationError


def test_every_bounded_lease_api_rejects_max_plus_one(lease):
    for call in (
        lambda: lease.get_events(limit=1001),
        lambda: lease.prune_events(timedelta(days=1), limit=10001),
    ):
        with pytest.raises(LeaseValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_LIMIT_TOO_LARGE"


def test_lease_boundaries_accept_max_and_reject_nonpositive(lease):
    assert lease.get_events(limit=1000) == []
    for bad in (None, 0, -1):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.get_events(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
