"""Namespace validation tests for config module."""

import pytest
from postkit.config.client import ConfigError, ConfigValidationError


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_config):
        """Valid namespace formats should be accepted."""
        valid = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]
        for ns in valid:
            client = make_config(ns)
            client.set("test.key", "value")
            assert client.get("test.key") is not None

    def test_rejects_null(self, make_config):
        with pytest.raises(ConfigError):
            make_config(None)

    def test_rejects_empty(self, make_config):
        with pytest.raises(ConfigError):
            make_config("")

    def test_rejects_whitespace_only(self, make_config):
        with pytest.raises(ConfigError):
            make_config("   ")

    def test_rejects_leading_whitespace(self, make_config):
        with pytest.raises(ConfigError):
            make_config(" leading")

    def test_rejects_trailing_whitespace(self, make_config):
        with pytest.raises(ConfigError):
            make_config("trailing ")

    def test_rejects_control_characters(self, make_config):
        with pytest.raises(ConfigError):
            make_config("has\ttab")

    def test_rejects_over_max_length(self, make_config):
        with pytest.raises(ConfigError):
            make_config("a" * 1025)


class TestValidationErrorType:
    """Validation errors raise ConfigValidationError for precise error handling."""

    def test_null_validation_raises_config_validation_error(self, make_config):
        """Null validation raises ConfigValidationError (SQLSTATE 22004)."""
        with pytest.raises(ConfigValidationError, match="cannot be null"):
            make_config(None)

    def test_empty_validation_raises_config_validation_error(self, make_config):
        """Empty string validation raises ConfigValidationError (SQLSTATE 22026)."""
        with pytest.raises(ConfigValidationError, match="cannot be empty"):
            make_config("")

    def test_length_validation_raises_config_validation_error(self, make_config):
        """Length exceeded validation raises ConfigValidationError (SQLSTATE 22001)."""
        with pytest.raises(ConfigValidationError, match="exceeds maximum"):
            make_config("a" * 1025)

    def test_format_validation_raises_config_validation_error(self, make_config):
        """Format validation raises ConfigValidationError (SQLSTATE 22023)."""
        with pytest.raises(ConfigValidationError, match="control characters"):
            make_config("has\ttab")

    def test_config_validation_error_is_config_error(self):
        """ConfigValidationError is a subclass of ConfigError for backwards compatibility."""
        assert issubclass(ConfigValidationError, ConfigError)
