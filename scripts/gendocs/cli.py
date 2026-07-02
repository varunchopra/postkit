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


def main():
    """Generate all documentation."""
    root = Path(__file__).resolve().parent.parent.parent
    docs_dir = root / "docs"

    # Clean and recreate docs directory
    if docs_dir.exists():
        shutil.rmtree(docs_dir)
    (docs_dir / "authz").mkdir(parents=True)
    (docs_dir / "authn").mkdir(parents=True)
    (docs_dir / "config").mkdir(parents=True)
    (docs_dir / "lease").mkdir(parents=True)
    (docs_dir / "meter").mkdir(parents=True)
    (docs_dir / "queue").mkdir(parents=True)

    print("Extracting Python docs...")

    python_results: dict[str, ExtractionResult] = {}
    sql_results: dict[str, ExtractionResult] = {}

    # authz Python
    authz_client = root / "sdk" / "src" / "postkit" / "authz" / "client.py"
    if authz_client.exists():
        result = extract_python_docs(authz_client, root)
        python_results["authz"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ authz: {documented}/{len(result.all_public_functions)} functions")

    # authn Python
    authn_client = root / "sdk" / "src" / "postkit" / "authn" / "client.py"
    if authn_client.exists():
        result = extract_python_docs(authn_client, root)
        python_results["authn"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ authn: {documented}/{len(result.all_public_functions)} functions")

    # config Python
    config_client = root / "sdk" / "src" / "postkit" / "config" / "client.py"
    if config_client.exists():
        result = extract_python_docs(config_client, root)
        python_results["config"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ config: {documented}/{len(result.all_public_functions)} functions")

    # lease Python
    lease_client = root / "sdk" / "src" / "postkit" / "lease" / "client.py"
    if lease_client.exists():
        result = extract_python_docs(lease_client, root)
        python_results["lease"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ lease: {documented}/{len(result.all_public_functions)} functions")

    # meter Python
    meter_client = root / "sdk" / "src" / "postkit" / "meter" / "client.py"
    if meter_client.exists():
        result = extract_python_docs(meter_client, root)
        python_results["meter"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ meter: {documented}/{len(result.all_public_functions)} functions")

    # queue Python
    queue_client = root / "sdk" / "src" / "postkit" / "queue" / "client.py"
    if queue_client.exists():
        result = extract_python_docs(queue_client, root)
        python_results["queue"] = result
        documented = sum(1 for f in result.functions if f.brief)
        print(f"  ✓ queue: {documented}/{len(result.all_public_functions)} functions")

    print("Extracting SQL docs...")

    # authz SQL
    authz_sql_dir = root / "authz" / "src" / "functions"
    if authz_sql_dir.exists():
        result = extract_sql_docs(authz_sql_dir, root)
        sql_results["authz"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ authz: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # authn SQL
    authn_sql_dir = root / "authn" / "src" / "functions"
    if authn_sql_dir.exists():
        result = extract_sql_docs(authn_sql_dir, root)
        sql_results["authn"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ authn: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # config SQL
    config_sql_dir = root / "config" / "src" / "functions"
    if config_sql_dir.exists():
        result = extract_sql_docs(config_sql_dir, root)
        sql_results["config"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ config: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # lease SQL
    lease_sql_dir = root / "lease" / "src" / "functions"
    if lease_sql_dir.exists():
        result = extract_sql_docs(lease_sql_dir, root)
        sql_results["lease"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ lease: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # meter SQL
    meter_sql_dir = root / "meter" / "src" / "functions"
    if meter_sql_dir.exists():
        result = extract_sql_docs(meter_sql_dir, root)
        sql_results["meter"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ meter: {documented}/{len(result.all_public_functions)} SQL functions"
        )
        if groups:
            print(f"    Groups: {', '.join(groups)}")

    # queue SQL
    queue_sql_dir = root / "queue" / "src" / "functions"
    if queue_sql_dir.exists():
        result = extract_sql_docs(queue_sql_dir, root)
        sql_results["queue"] = result
        documented = sum(1 for f in result.functions if f.brief)
        groups = sorted(set(f.group for f in result.functions if f.group))
        print(
            f"  ✓ queue: {documented}/{len(result.all_public_functions)} SQL functions"
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
    modules = sorted(set(python_results.keys()) | set(sql_results.keys()))
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
