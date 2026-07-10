"""Every name-rule error code in the SQL must be tested by its module.

All name fields share the same validation rules. This test scans the SQL
for *_INVALID_CHARS error codes and fails if a module's tests never mention
one of them, so nobody can add a new name field and forget to test its
validation. The test cases themselves live in each module's
test_validation.py, built from name_error_cases() in tests/helpers.py.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TESTS_DIR = Path(__file__).resolve().parent

MODULES = ["authn", "authz", "config", "lease", "meter", "outbox", "presence", "queue"]

CODE_PATTERN = re.compile(r"HINT\s*=\s*'postkit:\w+:(VAL_\w+?)_INVALID_CHARS'")


def _code_prefixes(module: str) -> set[str]:
    prefixes: set[str] = set()
    for sql_file in (REPO_ROOT / module / "src").rglob("*.sql"):
        prefixes.update(CODE_PATTERN.findall(sql_file.read_text()))
    return prefixes


def _test_text(module: str) -> str:
    return "\n".join(
        p.read_text() for p in (TESTS_DIR / module).rglob("*.py") if p.is_file()
    )


class TestNameRuleCoverage:
    def test_every_name_rule_code_family_is_tested(self):
        missing: list[str] = []
        for module in MODULES:
            text = _test_text(module)
            for prefix in sorted(_code_prefixes(module)):
                # Namespace codes are covered by the shared NAMESPACE_ERROR_CASES
                # parametrization every module consumes.
                if prefix == "VAL_NAMESPACE":
                    if "NAMESPACE_ERROR_CASES" not in text:
                        missing.append(f"{module}: NAMESPACE_ERROR_CASES not consumed")
                elif prefix not in text:
                    missing.append(f"{module}: {prefix}_INVALID_CHARS")
        assert not missing, (
            "The SQL defines name-rule error codes that no test mentions; add "
            "name_error_cases('<prefix>') cases in the module's test_validation.py:\n"
            + "\n".join(f"  {m}" for m in missing)
        )
