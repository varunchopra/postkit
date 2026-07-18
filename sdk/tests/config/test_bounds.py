import pytest
from postkit.config import ConfigValidationError


def test_every_bounded_config_api_rejects_max_plus_one(config):
    calls = [
        (lambda: config.get_batch(["missing"] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: config.list_entries(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: config.history("missing", limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: config.search({}, limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: config.list_schemas(limit=1001), "VAL_LIMIT_TOO_LARGE"),
    ]
    for call, code in calls:
        with pytest.raises(ConfigValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_config_boundaries_accept_max_and_reject_nonpositive(config):
    assert config.get_batch(["missing"] * 1000) == []
    for bad in (None, 0, -1):
        with pytest.raises(ConfigValidationError) as exc_info:
            config.list_entries(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
