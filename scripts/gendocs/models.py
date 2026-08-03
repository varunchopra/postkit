"""Data models for documentation extraction."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FunctionDoc:
    """Extracted function documentation."""

    name: str  # "authz.check" or "check"
    module: str  # "authz" | "authn"
    language: str  # "python" | "sql"
    signature: str  # Full signature (auto-extracted)
    brief: str  # One-line description
    source_file: str
    line_number: int
    group: str | None = None  # From @group tag
    params: dict[str, str] = field(default_factory=dict)  # param -> description
    returns: str | None = None  # Return description
    return_type: str | None = None  # "boolean", "bigint", "TABLE"
    examples: list[str] = field(default_factory=list)  # From @example tags


@dataclass
class ValidationResult:
    """Results from documentation validation."""

    errors: list[str] = field(default_factory=list)  # Build fails if non-empty
    warnings: list[str] = field(default_factory=list)  # Printed but allowed


@dataclass
class ExtractionResult:
    """Results from extracting documentation."""

    functions: list[FunctionDoc]
    all_public_functions: list[str]
    overview: str = ""
