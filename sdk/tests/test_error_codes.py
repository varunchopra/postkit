"""Verify SDK error code constants stay in sync with SQL HINT annotations."""

import re
from pathlib import Path

from postkit.errors import (
    AuthnErrorCode,
    AuthzErrorCode,
    ConfigErrorCode,
    MeterErrorCode,
    QueueErrorCode,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

MODULE_CONFIG = {
    "authn": {"sql_dir": REPO_ROOT / "authn" / "src", "cls": AuthnErrorCode},
    "authz": {"sql_dir": REPO_ROOT / "authz" / "src", "cls": AuthzErrorCode},
    "config": {"sql_dir": REPO_ROOT / "config" / "src", "cls": ConfigErrorCode},
    "meter": {"sql_dir": REPO_ROOT / "meter" / "src", "cls": MeterErrorCode},
    "queue": {"sql_dir": REPO_ROOT / "queue" / "src", "cls": QueueErrorCode},
}

HINT_PATTERN = re.compile(r"HINT\s*=\s*'postkit:(\w+):(\w+)'")


def _sql_error_codes(sql_dir: Path, module: str) -> set[str]:
    codes: set[str] = set()
    mismatched: list[str] = []
    for sql_file in sql_dir.rglob("*.sql"):
        for match in HINT_PATTERN.finditer(sql_file.read_text()):
            if match.group(1) != module:
                mismatched.append(f"  {sql_file.name}: {match.group(0)}")
            else:
                codes.add(match.group(2))
    assert not mismatched, f"HINT module prefix mismatch in {module}:\n" + "\n".join(
        mismatched
    )
    return codes


def _class_constants(cls: type) -> set[str]:
    return {
        k for k, v in vars(cls).items() if not k.startswith("_") and isinstance(v, str)
    }


class TestErrorCodeSync:
    """SDK error code constants must match SQL HINT annotations."""

    def test_sql_and_sdk_codes_match(self):
        missing: dict[str, set[str]] = {}
        orphaned: dict[str, set[str]] = {}

        for module, cfg in MODULE_CONFIG.items():
            sql_codes = _sql_error_codes(cfg["sql_dir"], module)
            cls_codes = _class_constants(cfg["cls"])

            sql_only = sql_codes - cls_codes
            if sql_only:
                missing[module] = sql_only

            sdk_only = cls_codes - sql_codes
            if sdk_only:
                orphaned[module] = sdk_only

        errors = []
        if missing:
            errors.append(
                "SQL error codes missing from SDK:\n"
                + "\n".join(
                    f"  {mod}: {sorted(codes)}" for mod, codes in missing.items()
                )
            )
        if orphaned:
            errors.append(
                "SDK constants with no SQL error code:\n"
                + "\n".join(
                    f"  {mod}: {sorted(codes)}" for mod, codes in orphaned.items()
                )
            )
        assert not errors, "\n\n".join(errors)
