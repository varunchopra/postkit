"""Namespace validation tests for meter module."""

import pytest
from postkit.meter import MeterError, MeterValidationError


class TestNamespaceValidation:
    """Tests for namespace validation - must be 1-1024 chars, no control chars."""

    def test_valid_namespaces(self, make_meter):
        """Valid namespace formats should be accepted."""
        valid = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]
        for ns in valid:
            client = make_meter(ns)
            client.allocate("user-1", "api.calls", 100, "credits")

    def test_rejects_null(self, make_meter):
        with pytest.raises(MeterError):
            make_meter(None)

    def test_rejects_empty(self, make_meter):
        with pytest.raises(MeterError):
            make_meter("")

    def test_rejects_whitespace_only(self, make_meter):
        with pytest.raises(MeterError):
            make_meter("   ")

    def test_rejects_leading_whitespace(self, make_meter):
        with pytest.raises(MeterError):
            make_meter(" leading")

    def test_rejects_trailing_whitespace(self, make_meter):
        with pytest.raises(MeterError):
            make_meter("trailing ")

    def test_rejects_control_characters(self, make_meter):
        with pytest.raises(MeterError):
            make_meter("has\ttab")

    def test_rejects_over_max_length(self, make_meter):
        with pytest.raises(MeterError):
            make_meter("a" * 1025)


class TestFieldLimits:
    """Length limits enforced on event_type and unit."""

    def test_rejects_overly_long_event_type(self, meter):
        """event_type has a length limit."""
        meter.allocate("user", "a" * 256, 100, "unit")  # at limit
        with pytest.raises(MeterError) as exc_info:
            meter.allocate("user", "a" * 257, 100, "unit")
        assert exc_info.value.error_code == "VAL_EVENT_TYPE_TOO_LONG"

    def test_rejects_overly_long_unit(self, meter):
        """unit has a length limit."""
        meter.allocate("user", "event", 100, "a" * 64)  # at limit
        with pytest.raises(MeterError) as exc_info:
            meter.allocate("user", "event", 100, "a" * 65)
        assert exc_info.value.error_code == "VAL_UNIT_TOO_LONG"


class TestValidationErrorType:
    """Validation errors raise MeterValidationError for precise error handling."""

    def test_null_validation_raises_meter_validation_error(self, make_meter):
        """Null validation raises MeterValidationError (SQLSTATE 22004)."""
        with pytest.raises(MeterValidationError) as exc_info:
            make_meter(None)
        assert exc_info.value.error_code == "VAL_NAMESPACE_NULL"

    def test_empty_validation_raises_meter_validation_error(self, make_meter):
        """Empty string validation raises MeterValidationError (SQLSTATE 22026)."""
        with pytest.raises(MeterValidationError) as exc_info:
            make_meter("")
        assert exc_info.value.error_code == "VAL_NAMESPACE_EMPTY"

    def test_length_validation_raises_meter_validation_error(self, meter):
        """Length exceeded validation raises MeterValidationError (SQLSTATE 22001)."""
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", "a" * 257, 100, "unit")  # event_type too long
        assert exc_info.value.error_code == "VAL_EVENT_TYPE_TOO_LONG"

    def test_format_validation_raises_meter_validation_error(self, make_meter):
        """Format validation raises MeterValidationError (SQLSTATE 22023)."""
        with pytest.raises(MeterValidationError) as exc_info:
            make_meter("has\ttab")
        assert exc_info.value.error_code == "VAL_NAMESPACE_INVALID_CHARS"

    def test_meter_validation_error_is_meter_error(self):
        """MeterValidationError is a subclass of MeterError for backwards compatibility."""
        assert issubclass(MeterValidationError, MeterError)
