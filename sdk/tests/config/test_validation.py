"""Namespace validation tests for config module."""

import pytest
from postkit.config.client import ConfigError, ConfigValidationError

from tests.helpers import (
    INVALID_NAMESPACES,
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
)


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_config):
        for ns in VALID_NAMESPACES:
            client = make_config(ns)
            client.set("test.key", "value")
            assert client.get("test.key") is not None

    @pytest.mark.parametrize("ns", INVALID_NAMESPACES)
    def test_rejects_invalid_namespace(self, make_config, ns):
        with pytest.raises(ConfigError):
            make_config(ns)


class TestValidationErrorType:
    """Validation errors raise ConfigValidationError for precise error handling."""

    @pytest.mark.parametrize("ns, error_code_name", NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_config, ns, error_code_name
    ):
        with pytest.raises(ConfigValidationError):
            make_config(ns)

    def test_config_validation_error_is_config_error(self):
        """ConfigValidationError is a subclass of ConfigError for backwards compatibility."""
        assert issubclass(ConfigValidationError, ConfigError)
