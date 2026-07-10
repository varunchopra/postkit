"""Namespace validation tests for meter module."""

from datetime import date

import pytest
from postkit.meter import MeterError, MeterErrorCode, MeterValidationError
from tests.helpers import (
    ACCEPTED_NAMES,
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
    name_error_cases,
)


class TestNamespaceValidation:
    """Tests for namespace validation - must be 1-1024 chars, no control chars."""

    def test_valid_namespaces(self, make_meter):
        for ns in VALID_NAMESPACES:
            client = make_meter(ns)
            client.allocate("user-1", "api.calls", 100, "credits")


class TestFieldLimits:
    """Length limits enforced on event_type and unit."""

    def test_rejects_overly_long_event_type(self, meter):
        """event_type has a length limit."""
        meter.allocate("user", "a" * 256, 100, "unit")  # at limit
        with pytest.raises(MeterError) as exc_info:
            meter.allocate("user", "a" * 257, 100, "unit")
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_TOO_LONG

    def test_rejects_overly_long_unit(self, meter):
        """unit has a length limit."""
        meter.allocate("user", "event", 100, "a" * 64)  # at limit
        with pytest.raises(MeterError) as exc_info:
            meter.allocate("user", "event", 100, "a" * 65)
        assert exc_info.value.error_code == MeterErrorCode.VAL_UNIT_TOO_LONG

    def test_event_type_null_rejected(self, meter):
        """event_type=None triggers VAL_EVENT_TYPE_NULL."""
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", None, 100, "unit")  # type: ignore[arg-type]
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_NULL

    def test_unit_null_rejected(self, meter):
        """unit=None triggers VAL_UNIT_NULL."""
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", "event", 100, None)  # type: ignore[arg-type]
        assert exc_info.value.error_code == MeterErrorCode.VAL_UNIT_NULL

    def test_unit_empty_rejected(self, meter):
        """Empty unit triggers VAL_UNIT_EMPTY."""
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", "event", 100, "")
        assert exc_info.value.error_code == MeterErrorCode.VAL_UNIT_EMPTY


class TestNameRules:
    """Event types and units follow the shared name rules."""

    @pytest.mark.parametrize(
        ("event_type", "code_name"), name_error_cases("VAL_EVENT_TYPE")
    )
    def test_event_type_violations(self, meter, event_type, code_name):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", event_type, 100, "credits")
        assert exc_info.value.error_code == getattr(MeterErrorCode, code_name)

    @pytest.mark.parametrize(("unit", "code_name"), name_error_cases("VAL_UNIT"))
    def test_unit_violations(self, meter, unit, code_name):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", "api.calls", 100, unit)
        assert exc_info.value.error_code == getattr(MeterErrorCode, code_name)

    @pytest.mark.parametrize("name", ACCEPTED_NAMES)
    def test_flexible_names_accepted(self, meter, name):
        assert meter.allocate("user", name, 100, name) is not None


class TestValidationErrorType:
    """Validation errors raise MeterValidationError for precise error handling."""

    @pytest.mark.parametrize("ns, error_code_name", NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_meter, ns, error_code_name
    ):
        with pytest.raises(MeterValidationError) as exc_info:
            make_meter(ns)
        assert exc_info.value.error_code == getattr(MeterErrorCode, error_code_name)

    def test_length_validation_raises_meter_validation_error(self, meter):
        """Length exceeded validation raises MeterValidationError (SQLSTATE 22001)."""
        with pytest.raises(MeterValidationError) as exc_info:
            meter.allocate("user", "a" * 257, 100, "unit")  # event_type too long
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_TOO_LONG

    def test_meter_validation_error_is_meter_error(self):
        """MeterValidationError is a subclass of MeterError for backwards compatibility."""
        assert issubclass(MeterValidationError, MeterError)


class TestPeriodFunctionValidation:
    """Period functions call the same validators as allocate."""

    def test_set_period_config_validates_inputs(self, meter):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.set_period_config("user", "", "unit", None, date(2025, 1, 1), 1000)
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_EMPTY

    def test_close_period_validates_inputs(self, meter):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.close_period("user", "", "unit", None, date(2025, 1, 31))
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_EMPTY

    def test_open_period_validates_inputs(self, meter):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.open_period("user", "", "unit", None, date(2025, 2, 1), 1000)
        assert exc_info.value.error_code == MeterErrorCode.VAL_EVENT_TYPE_EMPTY

    def test_set_period_config_validates_allocation(self, meter):
        with pytest.raises(MeterValidationError) as exc_info:
            meter.set_period_config("user", "event", "unit", None, date(2025, 1, 1), 0)
        assert exc_info.value.error_code == MeterErrorCode.VAL_NOT_POSITIVE
