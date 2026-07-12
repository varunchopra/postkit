"""Documentation generator for postkit.

Generates:
    docs/README.md           - Overview and generation instructions
    docs/{module}/README.md  - Index with deep links
    docs/{module}/sdk.md     - Python SDK reference
    docs/{module}/sql.md     - SQL function reference
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .extractors import extract_python_docs, extract_sql_docs
from .generators import (
    generate_docs_readme,
    generate_module_readme,
    generate_python_markdown,
    generate_sql_markdown,
)
from .models import ExtractionResult
from .validators import compute_coverage, validate_docs


def _discover_modules(root: Path) -> list[str]:
    """Discover modules: top-level directories with SQL sources.

    Every SQL module must have an SDK client and vice versa, so a module
    missing one half fails generation instead of silently losing its docs.
    """
    sql_modules = sorted(p.parent.parent.name for p in root.glob("*/src/functions"))
    sdk_modules = sorted(
        p.parent.name for p in (root / "sdk" / "src" / "postkit").glob("*/client.py")
    )
    if sql_modules != sdk_modules:
        missing_sdk = set(sql_modules) - set(sdk_modules)
        missing_sql = set(sdk_modules) - set(sql_modules)
        for module in sorted(missing_sdk):
            print(
                f"  ✗ {module}: no sdk/src/postkit/{module}/client.py", file=sys.stderr
            )
        for module in sorted(missing_sql):
            print(f"  ✗ {module}: no {module}/src/functions/", file=sys.stderr)
        sys.exit(1)
    if not sql_modules:
        print("No modules found", file=sys.stderr)
        sys.exit(1)
    return sql_modules


def main():
    """Generate all documentation."""
    root = Path(__file__).resolve().parent.parent.parent
    docs_dir = root / "docs"
    modules = _discover_modules(root)

    # Clean and recreate docs directory
    if docs_dir.exists():
        shutil.rmtree(docs_dir)
    for module in modules:
        (docs_dir / module).mkdir(parents=True)

    print("Extracting Python docs...")

    python_results: dict[str, ExtractionResult] = {}
    sql_results: dict[str, ExtractionResult] = {}

    for module in modules:
        client = root / "sdk" / "src" / "postkit" / module / "client.py"
        result = extract_python_docs(client, root)
        python_results[module] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(
            f"  ✓ {module}: {documented}/{len(result.all_public_functions)} functions"
        )

    print("Extracting SQL docs...")

    for module in modules:
        result = extract_sql_docs(root / module / "src" / "functions", root)
        sql_results[module] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ {module}: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # Validation
    all_python = list(python_results.values())
    all_sql = list(sql_results.values())

    validation = validate_docs(all_python, all_sql, strict=False)
    if validation.errors:
        print("\nValidation errors:")
        for err in validation.errors:
            print(f"  ✗ {err}")
        sys.exit(1)

    coverage = compute_coverage(all_python, all_sql)
    print(f"\nCoverage: Python {coverage['python']:.0%}, SQL {coverage['sql']:.0%}")

    print("\nGenerated:")

    # docs/README.md
    readme = generate_docs_readme(modules)
    (docs_dir / "README.md").write_text(readme)
    print("  docs/README.md")

    # Per-module files
    for module in modules:
        module_dir = docs_dir / module
        py_result = python_results.get(module)
        sql_result = sql_results.get(module)

        # Module README with deep links
        module_readme = generate_module_readme(module, py_result, sql_result)
        (module_dir / "README.md").write_text(module_readme)
        print(f"  docs/{module}/README.md")

        # SDK docs
        if py_result:
            sdk_md = generate_python_markdown(module, py_result)
            (module_dir / "sdk.md").write_text(sdk_md)
            print(f"  docs/{module}/sdk.md")

        # SQL docs
        if sql_result:
            sql_md = generate_sql_markdown(module, sql_result)
            (module_dir / "sql.md").write_text(sql_md)
            print(f"  docs/{module}/sql.md")

    print("\nDone!")


if __name__ == "__main__":
    main()
