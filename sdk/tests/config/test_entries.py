"""Tests for config entries (set, get, activate, rollback, etc.)."""

import pytest
from postkit.config import ConfigValidationError


class TestSet:
    """Tests for config.set()"""

    def test_creates_first_version(self, config, test_helpers):
        """First set() creates version 1."""
        version = config.set("prompts/bot", {"template": "Hello"})

        assert version == 1
        assert test_helpers.count_versions("prompts/bot") == 1

    def test_increments_version(self, config, test_helpers):
        """Each set() increments the version."""
        v1 = config.set("prompts/bot", {"template": "v1"})
        v2 = config.set("prompts/bot", {"template": "v2"})
        v3 = config.set("prompts/bot", {"template": "v3"})

        assert v1 == 1
        assert v2 == 2
        assert v3 == 3
        assert test_helpers.count_versions("prompts/bot") == 3

    def test_activates_new_version(self, config, test_helpers):
        """New version is automatically activated."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})

        active = test_helpers.get_active_version("prompts/bot")
        assert active == 2

    def test_stores_jsonb_value(self, config):
        """Values are stored as JSONB."""
        config.set("settings/limits", {"max_upload": 100, "rate_limit": 60})

        result = config.get("settings/limits")
        assert result["value"]["max_upload"] == 100
        assert result["value"]["rate_limit"] == 60

    def test_stores_primitive_values(self, config):
        """Primitive values work (string, number, boolean)."""
        config.set("flags/enabled", True)
        config.set("settings/count", 42)
        config.set("settings/name", "acme")

        assert config.get_value("flags/enabled") is True
        assert config.get_value("settings/count") == 42
        assert config.get_value("settings/name") == "acme"

    def test_validates_key_format(self, config):
        """Invalid key formats are rejected."""
        with pytest.raises(ConfigValidationError) as exc_info:
            config.set("/leading-slash", {"v": 1})
        assert exc_info.value.error_code == "VAL_KEY_FORMAT"

    def test_validates_key_no_double_slash(self, config):
        """Double slashes are rejected."""
        with pytest.raises(ConfigValidationError) as exc_info:
            config.set("prompts//bot", {"v": 1})
        assert exc_info.value.error_code == "VAL_KEY_SLASHES"

    def test_records_created_by(self, config, test_helpers):
        """created_by is populated from actor context."""
        config.set_actor("user:alice")
        config.set("prompts/bot", {"template": "hello"})

        entry = test_helpers.get_entry_raw("prompts/bot", 1)
        assert entry["created_by"] == "user:alice"


class TestGet:
    """Tests for config.get()"""

    def test_returns_active_version(self, config):
        """get() returns the active version by default."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})

        result = config.get("prompts/bot")
        assert result["value"]["template"] == "v2"
        assert result["version"] == 2

    def test_returns_specific_version(self, config):
        """get() with version returns that specific version."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})

        result = config.get("prompts/bot", version=1)
        assert result["value"]["template"] == "v1"
        assert result["version"] == 1

    def test_returns_none_for_missing_key(self, config):
        """get() returns None for non-existent key."""
        result = config.get("prompts/nonexistent")
        assert result is None

    def test_returns_none_for_missing_version(self, config):
        """get() returns None for non-existent version."""
        config.set("prompts/bot", {"template": "v1"})

        result = config.get("prompts/bot", version=999)
        assert result is None

    def test_includes_created_at(self, config):
        """get() returns created_at timestamp."""
        config.set("prompts/bot", {"template": "hello"})

        result = config.get("prompts/bot")
        assert result["created_at"] is not None


class TestGetBatch:
    """Tests for config.get_batch()"""

    def test_returns_multiple_entries(self, config):
        """get_batch() returns multiple entries in one query."""
        config.set("prompts/bot-a", {"template": "a"})
        config.set("prompts/bot-b", {"template": "b"})
        config.set("flags/feature", {"enabled": True})

        results = config.get_batch(["prompts/bot-a", "prompts/bot-b", "flags/feature"])

        assert len(results) == 3
        keys = {r["key"] for r in results}
        assert keys == {"prompts/bot-a", "prompts/bot-b", "flags/feature"}

    def test_returns_only_active_versions(self, config):
        """get_batch() returns active versions only."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        results = config.get_batch(["prompts/bot"])

        assert len(results) == 1
        assert results[0]["value"]["v"] == 2

    def test_ignores_missing_keys(self, config):
        """get_batch() returns empty for missing keys."""
        config.set("prompts/exists", {"v": 1})

        results = config.get_batch(["prompts/exists", "prompts/missing"])

        assert len(results) == 1
        assert results[0]["key"] == "prompts/exists"

    def test_empty_array(self, config):
        """get_batch() with empty array returns empty list."""
        results = config.get_batch([])
        assert results == []


class TestGetPath:
    """Tests for config.get_path()"""

    def test_gets_top_level_path(self, config):
        """get_path() retrieves top-level field."""
        config.set("flags/checkout", {"enabled": True, "rollout": 0.5})

        result = config.get_path("flags/checkout", "rollout")
        assert result == 0.5

    def test_gets_nested_path(self, config):
        """get_path() retrieves nested field."""
        config.set("prompts/bot", {"model": {"name": "claude", "version": "3"}})

        result = config.get_path("prompts/bot", "model", "name")
        assert result == "claude"

    def test_returns_none_for_missing_path(self, config):
        """get_path() returns None for non-existent path."""
        config.set("flags/checkout", {"enabled": True})

        result = config.get_path("flags/checkout", "missing")
        assert result is None

    def test_returns_none_for_missing_key(self, config):
        """get_path() returns None for non-existent key."""
        result = config.get_path("flags/missing", "enabled")
        assert result is None


class TestMerge:
    """Tests for config.merge()"""

    def test_merges_into_existing(self, config):
        """merge() combines with existing value."""
        config.set("flags/checkout", {"enabled": True, "rollout": 0.5})

        version = config.merge("flags/checkout", {"rollout": 0.75})

        assert version == 2
        result = config.get("flags/checkout")
        assert result["value"]["enabled"] is True  # preserved
        assert result["value"]["rollout"] == 0.75  # updated

    def test_adds_new_fields(self, config):
        """merge() adds new fields."""
        config.set("flags/checkout", {"enabled": True})

        config.merge("flags/checkout", {"rollout": 0.5, "variant": "A"})

        result = config.get("flags/checkout")
        assert result["value"]["enabled"] is True
        assert result["value"]["rollout"] == 0.5
        assert result["value"]["variant"] == "A"

    def test_creates_if_not_exists(self, config):
        """merge() creates new entry if key doesn't exist."""
        version = config.merge("flags/new", {"enabled": True})

        assert version == 1
        assert config.get_value("flags/new") == {"enabled": True}

    def test_shallow_merge_replaces_nested(self, config):
        """merge() does shallow merge - nested objects are replaced, not merged."""
        config.set("prompts/bot", {"model": {"name": "claude", "version": "3"}})

        config.merge("prompts/bot", {"model": {"name": "gpt"}})

        result = config.get_value("prompts/bot")
        # Entire "model" object replaced, not deep merged
        assert result["model"] == {"name": "gpt"}  # "version" is gone


class TestSearch:
    """Tests for config.search()"""

    def test_finds_by_field_value(self, config):
        """search() finds entries containing field value."""
        config.set("flags/a", {"enabled": True, "name": "a"})
        config.set("flags/b", {"enabled": False, "name": "b"})
        config.set("flags/c", {"enabled": True, "name": "c"})

        results = config.search({"enabled": True})

        keys = {r["key"] for r in results}
        assert keys == {"flags/a", "flags/c"}

    def test_filters_by_prefix(self, config):
        """search() respects prefix filter."""
        config.set("flags/checkout", {"enabled": True})
        config.set("settings/feature", {"enabled": True})

        results = config.search({"enabled": True}, prefix="flags/")

        keys = [r["key"] for r in results]
        assert keys == ["flags/checkout"]

    def test_empty_results(self, config):
        """search() returns empty list when nothing matches."""
        config.set("flags/checkout", {"enabled": False})

        results = config.search({"enabled": True})

        assert results == []

    def test_includes_created_at(self, config):
        """search() returns created_at for each result."""
        config.set("flags/checkout", {"enabled": True})

        results = config.search({"enabled": True})

        assert len(results) == 1
        assert results[0]["created_at"] is not None

    def test_prefix_underscores_escaped(self, config):
        """search() escapes SQL underscore wildcard in prefix."""
        config.set("test_exact", {"enabled": True})
        config.set("testXother", {"enabled": True})  # _ wildcard would match this

        # Underscore should be literal, not single-char wildcard
        results = config.search({"enabled": True}, prefix="test_")
        keys = [r["key"] for r in results]
        assert keys == ["test_exact"]
        assert "testXother" not in keys


class TestGetValue:
    """Tests for config.get_value()"""

    def test_returns_just_value(self, config):
        """get_value() returns only the value, not metadata."""
        config.set("prompts/bot", {"template": "hello"})

        value = config.get_value("prompts/bot")
        assert value == {"template": "hello"}

    def test_returns_default_for_missing(self, config):
        """get_value() returns default for missing key."""
        value = config.get_value("prompts/missing", default={"fallback": True})
        assert value == {"fallback": True}


class TestActivate:
    """Tests for config.activate()"""

    def test_activates_specific_version(self, config, test_helpers):
        """activate() makes a specific version active."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        result = config.activate("prompts/bot", 2)

        assert result is True
        assert test_helpers.get_active_version("prompts/bot") == 2
        assert config.get("prompts/bot")["value"]["v"] == 2

    def test_returns_false_for_missing_version(self, config):
        """activate() returns False for non-existent version."""
        config.set("prompts/bot", {"v": 1})

        result = config.activate("prompts/bot", 999)
        assert result is False

    def test_idempotent_activation(self, config, test_helpers):
        """Activating already-active version is fine."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        # Activate v2 again (it's already active)
        result = config.activate("prompts/bot", 2)

        assert result is True
        assert test_helpers.get_active_version("prompts/bot") == 2


class TestSetAfterActivate:
    """Tests for set() after activate() - version collision regression."""

    def test_set_after_activate_old_version(self, config, test_helpers):
        """set() after activate(old) uses MAX(version), not active version."""
        # Create v1, v2, v3
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        # Activate v1 (oldest)
        config.activate("prompts/bot", 1)

        # set() should create v4, not v2 (which would collide)
        new_version = config.set("prompts/bot", {"v": 4})

        assert new_version == 4
        assert test_helpers.count_versions("prompts/bot") == 4

    def test_set_after_delete_all(self, config, test_helpers):
        """set() after delete() continues version sequence."""
        # Create v1, v2, v3
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        # Delete all versions
        config.delete("prompts/bot")

        # set() should create v4 (continues sequence for audit clarity)
        new_version = config.set("prompts/bot", {"v": "new"})

        assert new_version == 4
        assert test_helpers.count_versions("prompts/bot") == 1


class TestRollback:
    """Tests for config.rollback()"""

    def test_activates_previous_version(self, config, test_helpers):
        """rollback() activates the previous version."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        result = config.rollback("prompts/bot")

        assert result == 2
        assert test_helpers.get_active_version("prompts/bot") == 2

    def test_returns_none_for_single_version(self, config):
        """rollback() returns None when there's only one version."""
        config.set("prompts/bot", {"v": 1})

        result = config.rollback("prompts/bot")
        assert result is None

    def test_returns_none_for_missing_key(self, config):
        """rollback() returns None for non-existent key."""
        result = config.rollback("prompts/nonexistent")
        assert result is None

    def test_consecutive_rollbacks(self, config, test_helpers):
        """Multiple rollbacks work correctly."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        config.rollback("prompts/bot")  # -> v2
        config.rollback("prompts/bot")  # -> v1

        assert test_helpers.get_active_version("prompts/bot") == 1


class TestList:
    """Tests for config.list()"""

    def test_lists_all_active_entries(self, config):
        """list() returns all active entries."""
        config.set("prompts/bot-a", {"template": "a"})
        config.set("prompts/bot-b", {"template": "b"})
        config.set("flags/feature", {"enabled": True})

        results = config.list()

        keys = [r["key"] for r in results]
        assert "prompts/bot-a" in keys
        assert "prompts/bot-b" in keys
        assert "flags/feature" in keys

    def test_filters_by_prefix(self, config):
        """list() with prefix filters results."""
        config.set("prompts/bot-a", {"template": "a"})
        config.set("prompts/bot-b", {"template": "b"})
        config.set("flags/feature", {"enabled": True})

        results = config.list(prefix="prompts/")

        keys = [r["key"] for r in results]
        assert "prompts/bot-a" in keys
        assert "prompts/bot-b" in keys
        assert "flags/feature" not in keys

    def test_pagination_with_cursor(self, config):
        """list() supports cursor-based pagination."""
        # Create entries with predictable order
        config.set("a/1", {"v": 1})
        config.set("a/2", {"v": 2})
        config.set("a/3", {"v": 3})

        # Get first page
        page1 = config.list(limit=2)
        assert len(page1) == 2

        # Get second page using cursor
        cursor = page1[-1]["key"]
        page2 = config.list(limit=2, cursor=cursor)
        assert len(page2) == 1

    def test_prefix_underscores_escaped(self, config):
        """list() escapes SQL underscore wildcard in prefix."""
        # Underscore in SQL LIKE is a single-char wildcard
        # Ensure it's treated as a literal underscore
        config.set("test_exact", {"v": 1})
        config.set("testXother", {"v": 2})  # Would match test_ as wildcard

        # Prefix with _ should only match literal underscore, not any char
        results = config.list(prefix="test_")
        keys = [r["key"] for r in results]
        assert keys == ["test_exact"]
        assert "testXother" not in keys


class TestHistory:
    """Tests for config.history()"""

    def test_returns_version_history(self, config):
        """history() returns all versions in descending order."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        history = config.history("prompts/bot")

        assert len(history) == 3
        assert history[0]["version"] == 3
        assert history[1]["version"] == 2
        assert history[2]["version"] == 1

    def test_shows_active_flag(self, config):
        """history() shows which version is active."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        history = config.history("prompts/bot")

        assert history[0]["is_active"] is True  # v2 is active
        assert history[1]["is_active"] is False  # v1 is not

    def test_includes_created_by(self, config):
        """history() includes created_by for each version."""
        config.set_actor("user:alice")
        config.set("prompts/bot", {"v": 1})
        config.set_actor("user:bob")
        config.set("prompts/bot", {"v": 2})

        history = config.history("prompts/bot")

        assert history[0]["created_by"] == "user:bob"
        assert history[1]["created_by"] == "user:alice"


class TestDelete:
    """Tests for config.delete()"""

    def test_deletes_all_versions(self, config, test_helpers):
        """delete() removes all versions of a key."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        count = config.delete("prompts/bot")

        assert count == 3
        assert test_helpers.count_versions("prompts/bot") == 0

    def test_returns_zero_for_missing_key(self, config):
        """delete() returns 0 for non-existent key."""
        count = config.delete("prompts/nonexistent")
        assert count == 0


class TestDeleteVersion:
    """Tests for config.delete_version()"""

    def test_deletes_inactive_version(self, config, test_helpers):
        """delete_version() removes an inactive version."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        result = config.delete_version("prompts/bot", 1)

        assert result is True
        assert test_helpers.count_versions("prompts/bot") == 1

    def test_cannot_delete_active_version(self, config):
        """delete_version() cannot delete the active version."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        with pytest.raises(ConfigValidationError) as exc_info:
            config.delete_version("prompts/bot", 2)
        assert exc_info.value.error_code == "BIZ_DELETE_ACTIVE_VERSION"

    def test_returns_false_for_missing_version(self, config):
        """delete_version() returns False for non-existent version."""
        config.set("prompts/bot", {"v": 1})

        result = config.delete_version("prompts/bot", 999)
        assert result is False


class TestExists:
    """Tests for config.exists()"""

    def test_returns_true_for_existing_key(self, config):
        """exists() returns True for existing key with active version."""
        config.set("prompts/bot", {"v": 1})

        assert config.exists("prompts/bot") is True

    def test_returns_false_for_missing_key(self, config):
        """exists() returns False for non-existent key."""
        assert config.exists("prompts/nonexistent") is False


class TestKeyNamingConventions:
    """Tests for key naming conventions (prompts/, flags/, secrets/, settings/)"""

    def test_prompts_prefix(self, config):
        """prompts/ keys work for LLM prompts."""
        config.set(
            "prompts/support-bot",
            {
                "template": "You are a support agent",
                "model": "claude-sonnet-4-20250514",
                "temperature": 0.7,
            },
        )

        value = config.get_value("prompts/support-bot")
        assert value["template"] == "You are a support agent"

    def test_flags_prefix(self, config):
        """flags/ keys work for feature flags."""
        config.set(
            "flags/new-checkout",
            {
                "enabled": True,
                "rollout": 0.5,
                "allowlist": ["user-123"],
            },
        )

        value = config.get_value("flags/new-checkout")
        assert value["enabled"] is True
        assert value["rollout"] == 0.5

    def test_secrets_prefix(self, config):
        """secrets/ keys work for encrypted secrets."""
        config.set(
            "secrets/OPENAI_API_KEY",
            {
                "encrypted": "aes256gcm:nonce:ciphertext",
                "key_id": "key-2024-01",
            },
        )

        value = config.get_value("secrets/OPENAI_API_KEY")
        assert value["encrypted"].startswith("aes256gcm:")

    def test_settings_prefix(self, config):
        """settings/ keys work for app configuration."""
        config.set(
            "settings/email",
            {
                "from": "support@acme.com",
                "reply_to": "help@acme.com",
            },
        )

        value = config.get_value("settings/email")
        assert value["from"] == "support@acme.com"


class TestSetDefault:
    """Tests for config.set_default() - set only if not exists."""

    def test_creates_new_key(self, config):
        """set_default creates key if it doesn't exist."""
        version, created = config.set_default("plans/free", {"tokens": 10000})

        assert version == 1
        assert created is True
        assert config.get_value("plans/free")["tokens"] == 10000

    def test_does_not_overwrite_existing(self, config):
        """set_default does not overwrite existing value."""
        config.set("plans/free", {"tokens": 10000})

        version, created = config.set_default("plans/free", {"tokens": 5000})

        assert version == 1  # Still version 1
        assert created is False
        # Original value preserved
        assert config.get_value("plans/free")["tokens"] == 10000

    def test_returns_existing_version(self, config):
        """set_default returns existing version number."""
        config.set("plans/free", {"tokens": 10000})
        config.set("plans/free", {"tokens": 20000})  # Version 2

        version, created = config.set_default("plans/free", {"tokens": 5000})

        assert version == 2  # Current active version
        assert created is False

    def test_multiple_defaults_safe(self, config):
        """Calling set_default multiple times is safe."""
        v1, c1 = config.set_default("plans/free", {"tokens": 10000})
        v2, c2 = config.set_default("plans/free", {"tokens": 5000})
        v3, c3 = config.set_default("plans/free", {"tokens": 1000})

        assert v1 == 1
        assert c1 is True  # First call created
        assert c2 is False  # Second call did not create
        assert c3 is False  # Third call did not create
        # Value still the original
        assert config.get_value("plans/free")["tokens"] == 10000

    def test_respects_schema_validation(self, config):
        """set_default validates against schema if exists."""
        # Register a schema
        config.set_schema(
            "defaults/",
            {
                "type": "object",
                "required": ["tokens"],
                "properties": {"tokens": {"type": "integer", "minimum": 0}},
            },
        )

        try:
            # Invalid value should fail
            with pytest.raises(ConfigValidationError):
                config.set_default("defaults/invalid", {"tokens": "not-a-number"})
        finally:
            # Clean up schema to avoid affecting other tests
            config.delete_schema("defaults/")

    def test_different_namespaces_independent(self, make_config):
        """set_default respects namespace isolation."""
        tenant_a = make_config("tenant_a")
        tenant_b = make_config("tenant_b")

        v_a, c_a = tenant_a.set_default("plans/free", {"tokens": 1000})
        v_b, c_b = tenant_b.set_default("plans/free", {"tokens": 2000})

        assert c_a is True
        assert c_b is True
        # Each tenant has their own value
        assert tenant_a.get_value("plans/free")["tokens"] == 1000
        assert tenant_b.get_value("plans/free")["tokens"] == 2000

    def test_use_case_seeding_defaults(self, config):
        """Demonstrates seeding default configs on app startup."""
        DEFAULT_PLANS = {
            "plans/free": {"tokens": 10000, "rate_limit": 10},
            "plans/pro": {"tokens": 100000, "rate_limit": 100},
            "plans/enterprise": {"tokens": 1000000, "rate_limit": 1000},
        }

        # First run: all created
        results = {}
        for key, value in DEFAULT_PLANS.items():
            version, created = config.set_default(key, value)
            results[key] = created

        assert all(results.values())

        # Second run: none created
        for key, value in DEFAULT_PLANS.items():
            version, created = config.set_default(key, value)
            assert created is False


class TestSqlValidationErrors:
    """Tests for SQL-level validation errors raising ConfigValidationError."""

    def test_invalid_key_raises_config_validation_error(self, config):
        """Invalid key format raises ConfigValidationError (not ConfigError)."""
        with pytest.raises(ConfigValidationError) as exc_info:
            config.set("/leading-slash", {"v": 1})

        assert exc_info.value.sqlstate == "22023"

    def test_delete_active_version_raises_config_validation_error(self, config):
        """Cannot delete active version raises ConfigValidationError."""
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        with pytest.raises(ConfigValidationError) as exc_info:
            config.delete_version("prompts/bot", 2)  # v2 is active

        assert exc_info.value.sqlstate == "22023"
        assert "active" in str(exc_info.value).lower()
