"""Postkit Config SDK - Versioned configuration management."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import jsonschema

from postkit.base import BaseClient, PostkitError


class ConfigError(PostkitError):
    """Exception for config operations."""


class ConfigValidationError(ConfigError):
    """Raised when validation fails (schema or SQL-level)."""

    pass


class SchemaViolationError(ConfigError):
    """Raised when schema change would invalidate existing configs."""

    def __init__(self, message: str, invalid_configs: list[dict]):
        self.invalid_configs = invalid_configs
        super().__init__(message)


@dataclass
class ValidationResult:
    """Result of JSON Schema validation."""

    valid: bool
    errors: list[str]


class ConfigClient(BaseClient):
    """Client for Postkit config module.

    Manages versioned configuration including prompts, feature flags, secrets,
    and settings. All config types use the same API — differentiate by key
    naming conventions.

    Example:
        config = ConfigClient(cursor, namespace="acme")

        # Prompts
        config.set("prompts/support-bot", {
            "template": "You are a helpful assistant...",
            "model": "claude-sonnet-4-20250514",
            "temperature": 0.7
        })

        # Feature flags
        config.set("flags/new-checkout", {"enabled": True, "rollout": 0.5})

        # Secrets (caller encrypts)
        config.set("secrets/OPENAI_API_KEY", {"encrypted": "aes256gcm:..."})

        # Get active version
        prompt = config.get("prompts/support-bot")

        # Rollback to previous version
        config.rollback("prompts/support-bot")
    """

    _schema = "config"
    _error_class = ConfigError
    _module_sqlstate_map = {
        "22023": ConfigValidationError,  # invalid_parameter_value
        "22004": ConfigValidationError,  # null_value_not_allowed
        "22001": ConfigValidationError,  # string_data_right_truncation
        "22026": ConfigValidationError,  # string_data_length_mismatch
    }

    def __init__(self, cursor, namespace: str):
        """Initialize the config client.

        Args:
            cursor: A DB-API 2.0 cursor (psycopg2, psycopg3, etc.)
            namespace: Tenant namespace for multi-tenancy
        """
        super().__init__(cursor, namespace)

    def _apply_actor_context(self) -> None:
        self.cursor.execute(
            """SELECT config.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def set(self, key: str, value: Any) -> int:
        """Create a new version and activate it.

        Validates against schema if one exists for this key pattern.

        Args:
            key: Config key (e.g., 'prompts/support-bot', 'flags/checkout')
            value: Config value (will be stored as JSONB)

        Returns:
            New version number

        Raises:
            ConfigValidationError: If value doesn't match the schema for this key
        """
        schema = self.get_schema(key)
        if schema is not None:
            result = self._validate_value(value, schema)
            if not result.valid:
                raise ConfigValidationError(
                    f"Validation failed for '{key}': {result.errors}"
                )

        return self._fetch_val(
            "SELECT config.set(%s, %s::jsonb, %s)",
            (key, json.dumps(value), self.namespace),
            write=True,
        )

    def set_default(self, key: str, value: Any) -> tuple[int, bool]:
        """Set a config value only if the key doesn't exist.

        Use for seeding defaults without overwriting user customizations.

        Args:
            key: Config key (e.g., 'plans/free', 'flags/default-feature')
            value: Default config value (will be stored as JSONB)

        Returns:
            Tuple of (version, was_created) where version is 1 if created.

        Raises:
            ConfigValidationError: If value doesn't match the schema for this key

        Example:
            version, created = config.set_default("plans/free", {"tokens": 10000})
        """
        schema = self.get_schema(key)
        if schema is not None:
            result = self._validate_value(value, schema)
            if not result.valid:
                raise ConfigValidationError(
                    f"Validation failed for '{key}': {result.errors}"
                )

        row = self._fetch_one(
            "SELECT * FROM config.set_default(%s, %s::jsonb, %s)",
            (key, json.dumps(value), self.namespace),
            write=True,
        )
        if row is None:
            raise ConfigError("Failed to set default config")
        return row["version"], row["created"]

    def get(self, key: str, version: int | None = None) -> dict | None:
        """Get config entry.

        Args:
            key: Config key
            version: Specific version (default: active version)

        Returns:
            Dict with 'value', 'version', 'created_at' or None if not found
        """
        return self._fetch_one(
            "SELECT value, version, created_at FROM config.get(%s, %s, %s)",
            (key, version, self.namespace),
        )

    def get_value(self, key: str, default: Any = None) -> Any:
        """Get just the value (convenience method).

        Args:
            key: Config key
            default: Default value if key doesn't exist

        Returns:
            The config value, or default if not found
        """
        result = self.get(key)
        if result is None:
            return default
        return result["value"]

    def get_batch(self, keys: list[str]) -> list[dict]:
        """Get multiple config entries in one query.

        Args:
            keys: List of config keys to fetch

        Returns:
            List of dicts with 'key', 'value', 'version', 'created_at'
        """
        return self._fetch_all(
            "SELECT key, value, version, created_at FROM config.get_batch(%s, %s)",
            (keys, self.namespace),
        )

    def get_path(self, key: str, *path: str) -> Any:
        """Get a specific path within a config value.

        Args:
            key: Config key
            *path: Path segments (e.g., "model", "name" for {"model": {"name": ...}})

        Returns:
            The value at the path, or None if not found

        Example:
            config.get_path("prompts/bot", "temperature")
            config.get_path("flags/checkout", "rollout")
            config.get_path("settings/model", "params", "temperature")
        """
        return self._fetch_val(
            "SELECT config.get_path(%s, %s, %s)",
            (key, list(path), self.namespace),
        )

    def merge(self, key: str, changes: dict) -> int:
        """Merge changes into config, creating new version.

        Performs a shallow merge - top-level keys in changes overwrite
        existing keys, other keys are preserved.

        Validates the merged result against schema if one exists.

        Args:
            key: Config key
            changes: Dict of fields to merge

        Returns:
            New version number

        Raises:
            ConfigValidationError: If merged result doesn't match the schema

        Example:
            config.merge("flags/checkout", {"rollout": 0.75})
            config.merge("prompts/bot", {"temperature": 0.8, "max_tokens": 2000})
        """
        schema = self.get_schema(key)
        if schema is not None:
            current = self.get_value(key, default={})
            merged = {**current, **changes}
            result = self._validate_value(merged, schema)
            if not result.valid:
                raise ConfigValidationError(
                    f"Validation failed for '{key}': {result.errors}"
                )

        return self._fetch_val(
            "SELECT config.merge(%s, %s::jsonb, %s)",
            (key, json.dumps(changes), self.namespace),
            write=True,
        )

    def search(
        self, contains: dict, prefix: str | None = None, limit: int = 100
    ) -> list[dict]:
        """Find configs where value contains given JSON.

        Args:
            contains: JSON object to search for (uses containment)
            prefix: Optional key prefix filter
            limit: Max results (default 100)

        Returns:
            List of dicts with 'key', 'value', 'version', 'created_at'

        Example:
            config.search({"enabled": True})  # All enabled flags
            config.search({"model": "claude-sonnet-4-20250514"}, prefix="prompts/")
        """
        return self._fetch_all(
            "SELECT key, value, version, created_at FROM config.search(%s::jsonb, %s, %s, %s)",
            (json.dumps(contains), prefix, self.namespace, limit),
        )

    def activate(self, key: str, version: int) -> bool:
        """Activate a specific version.

        Args:
            key: Config key
            version: Version to activate

        Returns:
            True if version was found and activated
        """
        return self._fetch_val(
            "SELECT config.activate(%s, %s, %s)",
            (key, version, self.namespace),
            write=True,
        )

    def rollback(self, key: str) -> int | None:
        """Rollback to previous version.

        Args:
            key: Config key

        Returns:
            New active version number, or None if no previous version
        """
        return self._fetch_val(
            "SELECT config.rollback(%s, %s)",
            (key, self.namespace),
            write=True,
        )

    def list(
        self,
        prefix: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> list[dict]:
        """List active config entries.

        Args:
            prefix: Filter by key prefix (e.g., 'prompts/')
            limit: Max results (default 100, max 1000)
            cursor: Pagination cursor (last key from previous page)

        Returns:
            List of dicts with 'key', 'value', 'version', 'created_at'
        """
        return self._fetch_all(
            "SELECT key, value, version, created_at FROM config.list(%s, %s, %s, %s)",
            (prefix, self.namespace, limit, cursor),
        )

    def history(self, key: str, limit: int = 50) -> list[dict]:
        """Get version history for a key.

        Args:
            key: Config key
            limit: Max versions to return

        Returns:
            List of dicts with 'version', 'value', 'is_active', 'created_at', 'created_by'
        """
        return self._fetch_all(
            "SELECT version, value, is_active, created_at, created_by FROM config.history(%s, %s, %s)",
            (key, self.namespace, limit),
        )

    def delete(self, key: str) -> int:
        """Delete all versions of a config entry.

        Args:
            key: Config key

        Returns:
            Count of versions deleted
        """
        return self._fetch_val(
            "SELECT config.delete(%s, %s)", (key, self.namespace), write=True
        )

    def delete_version(self, key: str, version: int) -> bool:
        """Delete a specific version (cannot delete active version).

        Args:
            key: Config key
            version: Version to delete

        Returns:
            True if deleted
        """
        return self._fetch_val(
            "SELECT config.delete_version(%s, %s, %s)",
            (key, version, self.namespace),
            write=True,
        )

    def exists(self, key: str) -> bool:
        """Check if a config key exists.

        Args:
            key: Config key

        Returns:
            True if key exists and has an active version
        """
        return self._fetch_val("SELECT config.exists(%s, %s)", (key, self.namespace))

    def get_stats(self) -> dict:
        """Get namespace statistics.

        Returns:
            Dict with 'total_keys', 'total_versions', 'keys_by_prefix'
        """
        row = self._fetch_one(
            "SELECT total_keys, total_versions, keys_by_prefix FROM config.get_stats(%s)",
            (self.namespace,),
        )
        if row is None:
            return {"total_keys": 0, "total_versions": 0, "keys_by_prefix": {}}
        # Handle NULL keys_by_prefix from SQL
        return {**row, "keys_by_prefix": row["keys_by_prefix"] or {}}

    def cleanup_old_versions(self, keep_versions: int = 10) -> int:
        """Delete old inactive versions, keeping N most recent per key.

        Args:
            keep_versions: Number of inactive versions to keep per key (default 10)

        Returns:
            Count of versions deleted
        """
        return self._fetch_val(
            "SELECT config.cleanup_old_versions(%s, %s)",
            (keep_versions, self.namespace),
            write=True,
        )

    def get_audit_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        actor_id: str | None = None,
        key: str | None = None,
        before: str | None = None,
    ) -> list[dict]:
        """Query audit events with optional filters.

        Args:
            limit: Maximum number of events to return (default 100)
            event_type: Filter by event type (e.g., 'entry_created', 'entry_deleted')
            actor_id: Filter by actor ID (who made the change)
            key: Filter by config key
            before: Opaque cursor from a previous response's event['cursor']

        Returns:
            List of audit event dictionaries. Each event includes a 'cursor' field
            that can be passed to 'before' for pagination.

        Example:
            events = config.get_audit_events(limit=50)
            if events:
                more = config.get_audit_events(limit=50, before=events[-1]["cursor"])
        """
        return super().get_audit_events(
            limit=limit,
            event_type=event_type,
            actor_id=actor_id,
            before=before,
            key=key,
        )

    # Schema management

    def set_schema(
        self, key_pattern: str, schema: dict, description: str | None = None
    ) -> None:
        """Register a JSON Schema for validating config values.

        Pattern types:
            Prefix (trailing /):  'flags/'               - Homogeneous collections
            Exact (no trailing /): 'integrations/webhook' - Unique schemas

        Use prefix for collections where all items share structure:
            - flags/*       : All have {enabled: bool, rollout?: number}
            - rate_limits/* : All have {max: number, window_seconds: number}

        Use exact for items with unique structure:
            - integrations/webhook : {url, secret, headers}
            - integrations/slack   : {workspace_id, channel, bot_token}

        Args:
            key_pattern: Prefix ending in '/' or exact key
            schema: JSON Schema document (Draft 7)
            description: Human-readable description

        Raises:
            SchemaViolationError: If existing configs don't comply with schema

        Note:
            Requires admin connection. Validates ALL existing configs across
            all namespaces before saving.
        """
        # Get all matching configs across all namespaces
        matching = self._fetch_all(
            "SELECT namespace, key, value FROM config._get_configs_for_pattern(%s)",
            (key_pattern,),
        )

        # Validate each against new schema
        invalid = []
        for config in matching:
            result = self._validate_value(config["value"], schema)
            if not result.valid:
                invalid.append(
                    {
                        "namespace": config["namespace"],
                        "key": config["key"],
                        "errors": result.errors,
                    }
                )

        if invalid:
            raise SchemaViolationError(
                f"{len(invalid)} existing configs don't comply with schema",
                invalid_configs=invalid,
            )

        self._fetch_val(
            "SELECT config._set_schema(%s, %s::jsonb, %s)",
            (key_pattern, json.dumps(schema), description),
            write=True,
        )

    def get_schema(self, key: str) -> dict | None:
        """Get the JSON Schema that applies to a config key.

        Matching precedence:
            1. Exact match wins over prefix
            2. Longer prefix wins over shorter
            3. No match = returns None (no validation required)

        Args:
            key: Config key to find schema for

        Returns:
            JSON Schema document, or None if no matching schema

        Note:
            All connections (admin and tenant) can read schemas.
        """
        return self._fetch_val("SELECT config.get_schema(%s)", (key,))

    def delete_schema(self, key_pattern: str) -> bool:
        """Delete a schema by its key pattern.

        Args:
            key_pattern: Pattern to delete

        Returns:
            True if deleted, False if not found

        Note:
            Requires admin connection that bypasses RLS.
        """
        return self._fetch_val(
            "SELECT config.delete_schema(%s)", (key_pattern,), write=True
        )

    def list_schemas(self, prefix: str | None = None, limit: int = 100) -> list[dict]:
        """List all schemas, optionally filtered by prefix.

        Args:
            prefix: Optional prefix to filter by
            limit: Maximum number of results (default 100)

        Returns:
            List of dicts with 'key_pattern', 'schema', 'description',
            'created_at', 'updated_at'
        """
        return self._fetch_all(
            "SELECT key_pattern, schema, description, created_at, updated_at "
            "FROM config.list_schemas(%s, %s)",
            (prefix, limit),
        )

    def _validate_value(self, value: Any, schema: dict) -> ValidationResult:
        """Validate value against JSON Schema (Draft 7)."""
        validator = jsonschema.Draft7Validator(schema)
        errors = [error.message for error in validator.iter_errors(value)]
        return ValidationResult(valid=len(errors) == 0, errors=errors)
