import pytest
from postkit.meter import MeterValidationError


def test_ledger_rejects_max_plus_one(meter):
    with pytest.raises(MeterValidationError) as exc_info:
        meter.get_ledger("user", "event", "unit", limit=10001)
    assert exc_info.value.sqlstate == "22023"
    assert exc_info.value.error_code == "VAL_LIMIT_TOO_LARGE"


def test_meter_boundaries_accept_max_and_reject_nonpositive(meter):
    assert meter.get_ledger("user", "event", "unit", limit=10000) == []
    for bad in (None, 0, -1):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.get_ledger("user", "event", "unit", limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
