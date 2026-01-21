"""Tests for config schema validation."""

import pytest
from postkit.config import (
    ConfigClient,
    ConfigValidationError,
    SchemaViolationError,
)


@pytest.fixture
def admin_config(db_connection):
    """Admin ConfigClient for schema management. Cleans up after each test."""
    cursor = db_connection.cursor()
    client = ConfigClient(cursor, namespace="admin_test")

    yield client

    cursor.execute("DELETE FROM config.schemas")
    cursor.execute("DELETE FROM config.entries WHERE namespace = 'admin_test'")
    cursor.close()


class TestSetSchema:
    def test_creates_schema(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {"type": "object", "required": ["enabled"]},
            description="Feature flag schema",
        )

        schemas = admin_config.list_schemas()
        assert len(schemas) == 1
        assert schemas[0]["key_pattern"] == "flags/"
        assert schemas[0]["description"] == "Feature flag schema"

    def test_upserts_schema(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object"})
        admin_config.set_schema("flags/", {"type": "object", "required": ["enabled"]})

        schemas = admin_config.list_schemas()
        assert len(schemas) == 1
        assert schemas[0]["schema"]["required"] == ["enabled"]

    def test_validates_pattern_format(self, admin_config):
        # Leading slash fails format check (must start with alphanumeric)
        with pytest.raises(ConfigValidationError) as exc_info:
            admin_config.set_schema("//invalid", {"type": "object"})
        assert exc_info.value.error_code == "VAL_PATTERN_FORMAT"

        with pytest.raises(ConfigValidationError) as exc_info:
            admin_config.set_schema("/leading", {"type": "object"})
        assert exc_info.value.error_code == "VAL_PATTERN_FORMAT"

        # Double slash in middle fails slashes check
        with pytest.raises(ConfigValidationError) as exc_info:
            admin_config.set_schema("valid//double", {"type": "object"})
        assert exc_info.value.error_code == "VAL_PATTERN_SLASHES"


class TestGetSchema:
    def test_returns_exact_match(self, admin_config):
        admin_config.set_schema(
            "integrations/webhook",
            {"type": "object", "required": ["url"]},
        )

        schema = admin_config.get_schema("integrations/webhook")
        assert schema is not None
        assert schema["required"] == ["url"]

    def test_returns_prefix_match(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object", "required": ["enabled"]})

        schema = admin_config.get_schema("flags/checkout")
        assert schema is not None
        assert schema["required"] == ["enabled"]

    def test_returns_none_when_no_match(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object"})

        schema = admin_config.get_schema("settings/email")
        assert schema is None


class TestDeleteSchema:
    def test_deletes_schema(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object"})

        result = admin_config.delete_schema("flags/")
        assert result is True

        schemas = admin_config.list_schemas()
        assert len(schemas) == 0

    def test_returns_false_when_not_found(self, admin_config):
        result = admin_config.delete_schema("nonexistent/")
        assert result is False


class TestListSchemas:
    def test_lists_all_schemas(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object"})
        admin_config.set_schema("prompts/", {"type": "object"})
        admin_config.set_schema("integrations/webhook", {"type": "object"})

        schemas = admin_config.list_schemas()
        assert len(schemas) == 3

    def test_filters_by_prefix(self, admin_config):
        admin_config.set_schema("flags/", {"type": "object"})
        admin_config.set_schema("flags/special", {"type": "object"})
        admin_config.set_schema("prompts/", {"type": "object"})

        schemas = admin_config.list_schemas(prefix="flags")
        assert len(schemas) == 2

    def test_prefix_underscores_escaped(self, admin_config):
        """list_schemas() escapes SQL underscore wildcard in prefix."""
        admin_config.set_schema("test_exact/", {"type": "object"})
        admin_config.set_schema("testXother/", {"type": "object"})

        # Underscore should be literal, not single-char wildcard
        schemas = admin_config.list_schemas(prefix="test_")
        patterns = [s["key_pattern"] for s in schemas]
        assert patterns == ["test_exact/"]
        assert "testXother/" not in patterns


class TestPatternMatching:
    """Tests for schema pattern matching precedence."""

    def test_exact_match_wins_over_prefix(self, admin_config):
        admin_config.set_schema("prompts/", {"type": "object", "title": "prefix"})
        admin_config.set_schema("prompts/support", {"type": "object", "title": "exact"})

        schema = admin_config.get_schema("prompts/support")
        assert schema["title"] == "exact"

        schema = admin_config.get_schema("prompts/sales")
        assert schema["title"] == "prefix"

    def test_longer_prefix_wins(self, admin_config):
        admin_config.set_schema("a/", {"type": "object", "title": "short"})
        admin_config.set_schema("a/b/", {"type": "object", "title": "long"})

        schema = admin_config.get_schema("a/b/c")
        assert schema["title"] == "long"

        schema = admin_config.get_schema("a/x")
        assert schema["title"] == "short"


class TestValidationOnSet:
    """Tests for automatic validation when setting config values."""

    def test_valid_value_succeeds(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "required": ["enabled"],
                "properties": {"enabled": {"type": "boolean"}},
            },
        )

        version = admin_config.set("flags/checkout", {"enabled": True})
        assert version == 1

    def test_invalid_type_raises(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
            },
        )

        with pytest.raises(ConfigValidationError) as exc_info:
            admin_config.set("flags/checkout", {"enabled": "yes"})

        assert "flags/checkout" in str(exc_info.value)
        assert "boolean" in str(exc_info.value).lower()

    def test_missing_required_raises(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "required": ["enabled"],
            },
        )

        with pytest.raises(ConfigValidationError) as exc_info:
            admin_config.set("flags/checkout", {"rollout": 50})

        assert "enabled" in str(exc_info.value).lower()

    def test_no_schema_passes_through(self, admin_config):
        """Config without matching schema passes without validation."""
        admin_config.set_schema("flags/", {"type": "object"})

        version = admin_config.set("settings/email", {"anything": "goes"})
        assert version == 1


class TestSchemaUpdateBlocking:
    """Tests for blocking schema updates when existing configs don't comply."""

    def test_schema_allowed_when_configs_comply(self, admin_config):
        admin_config.set("flags/checkout", {"enabled": True})

        admin_config.set_schema(
            "flags/",
            {"type": "object", "required": ["enabled"]},
        )

        schema = admin_config.get_schema("flags/checkout")
        assert schema is not None

    def test_schema_blocked_when_configs_dont_comply(self, admin_config):
        admin_config.set("flags/checkout", {"enabled": True})

        with pytest.raises(SchemaViolationError) as exc_info:
            admin_config.set_schema(
                "flags/",
                {"type": "object", "required": ["enabled", "description"]},
            )

        assert len(exc_info.value.invalid_configs) == 1
        assert exc_info.value.invalid_configs[0]["key"] == "flags/checkout"

    def test_reports_all_non_compliant_configs(self, admin_config):
        admin_config.set("flags/a", {"enabled": True})
        admin_config.set("flags/b", {"enabled": False})
        admin_config.set("flags/c", {"enabled": True, "description": "ok"})

        with pytest.raises(SchemaViolationError) as exc_info:
            admin_config.set_schema(
                "flags/",
                {"type": "object", "required": ["enabled", "description"]},
            )

        assert len(exc_info.value.invalid_configs) == 2
        keys = {c["key"] for c in exc_info.value.invalid_configs}
        assert keys == {"flags/a", "flags/b"}


class TestCollectionTypes:
    """Homogeneous vs heterogeneous collection patterns."""

    def test_homogeneous_collection_with_prefix(self, admin_config):
        """All items in collection share same schema via prefix pattern."""
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "required": ["enabled"],
                "properties": {
                    "enabled": {"type": "boolean"},
                    "rollout": {"type": "number", "minimum": 0, "maximum": 100},
                },
            },
        )

        admin_config.set("flags/checkout", {"enabled": True, "rollout": 50})
        admin_config.set("flags/dark-mode", {"enabled": False})
        admin_config.set("flags/new-pricing", {"enabled": True, "rollout": 10})

        assert admin_config.exists("flags/checkout")
        assert admin_config.exists("flags/dark-mode")
        assert admin_config.exists("flags/new-pricing")

    def test_heterogeneous_collection_with_exact(self, admin_config):
        """Each item has unique schema via exact pattern."""
        admin_config.set_schema(
            "integrations/webhook",
            {
                "type": "object",
                "required": ["url"],
                "properties": {"url": {"type": "string", "format": "uri"}},
            },
        )
        admin_config.set_schema(
            "integrations/slack",
            {
                "type": "object",
                "required": ["channel"],
                "properties": {"channel": {"type": "string"}},
            },
        )

        admin_config.set("integrations/webhook", {"url": "https://example.com/hook"})
        admin_config.set("integrations/slack", {"channel": "#alerts"})

        with pytest.raises(ConfigValidationError):
            admin_config.set("integrations/webhook", {"channel": "#wrong"})


class TestMergeValidation:
    """Tests for schema validation on merge()."""

    def test_merge_validates_result(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
            },
        )

        admin_config.set("flags/test", {"enabled": True})

        with pytest.raises(ConfigValidationError):
            admin_config.merge("flags/test", {"enabled": "not-a-boolean"})

    def test_merge_validates_new_key(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "required": ["enabled"],
            },
        )

        with pytest.raises(ConfigValidationError):
            admin_config.merge("flags/new", {"rollout": 50})

    def test_merge_valid_value_succeeds(self, admin_config):
        admin_config.set_schema(
            "flags/",
            {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
            },
        )

        initial_version = admin_config.set("flags/test", {"enabled": True})

        new_version = admin_config.merge("flags/test", {"rollout": 50})
        assert new_version == initial_version + 1

        result = admin_config.get("flags/test")
        assert result["value"]["enabled"] is True
        assert result["value"]["rollout"] == 50
