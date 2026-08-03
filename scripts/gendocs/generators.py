"""Output generators for documentation."""

from __future__ import annotations

from collections import defaultdict

from .models import ExtractionResult, FunctionDoc


def _slugify(name: str) -> str:
    """Convert function name to markdown anchor slug."""
    return name.lower().replace(".", "").replace(" ", "-")


def generate_docs_readme(modules: list[str]) -> str:
    """Generate docs/README.md with overview and generation instructions."""
    lines = [
        "# postkit Documentation",
        "",
        "API reference documentation for postkit modules.",
        "",
        "## Modules",
        "",
    ]

    for module in sorted(modules):
        lines.append(f"- [{module}]({module}/README.md)")

    lines.extend(
        [
            "",
            "## Generating Documentation",
            "",
            "Documentation is auto-generated from source code:",
            "",
            "```bash",
            "make docs",
            "```",
            "",
            "This extracts documentation from:",
            "- Python SDK: docstrings in `sdk/src/postkit/*/client.py`",
            "- SQL functions: `@function` blocks in `*/src/functions/*.sql`",
            "",
            "Do not edit generated files directly. Update the source code instead.",
            "",
        ]
    )

    return "\n".join(lines)


def generate_module_readme(
    module: str,
    python_result: ExtractionResult | None,
    sql_result: ExtractionResult | None,
) -> str:
    """Generate module README.md with deep links to functions."""
    lines = [
        f"# {module.title()} API Reference",
        "",
    ]

    # Python SDK section
    if python_result and python_result.functions:
        lines.extend(
            [
                "## Python SDK",
                "",
                "| Function | Description |",
                "|----------|-------------|",
            ]
        )

        # Group by group tag
        grouped: dict[str | None, list[FunctionDoc]] = defaultdict(list)
        for f in python_result.functions:
            grouped[f.group].append(f)

        for group in sorted(grouped.keys(), key=lambda x: (x is None, x or "")):
            funcs = grouped[group]
            for f in sorted(funcs, key=lambda x: x.name):
                slug = _slugify(f.name)
                # Use first line only for table summary
                desc = (f.brief or "").split("\n")[0].replace("|", "\\|")
                lines.append(f"| [`{f.name}`](sdk.md#{slug}) | {desc} |")

        lines.append("")

    # SQL section
    if sql_result:
        documented = [f for f in sql_result.functions if f.brief]
        if documented:
            lines.extend(
                [
                    "## SQL Functions",
                    "",
                    "| Function | Description |",
                    "|----------|-------------|",
                ]
            )

            # Group by group tag
            grouped: dict[str | None, list[FunctionDoc]] = defaultdict(list)
            for f in documented:
                grouped[f.group].append(f)

            for group in sorted(grouped.keys(), key=lambda x: (x is None, x or "")):
                funcs = grouped[group]
                for f in sorted(funcs, key=lambda x: x.name):
                    slug = _slugify(f.name)
                    # Use first line only for table summary
                    desc = (f.brief or "").split("\n")[0].replace("|", "\\|")
                    lines.append(f"| [`{f.name}`](sql.md#{slug}) | {desc} |")

            lines.append("")

    return "\n".join(lines)


def generate_python_markdown(module: str, results: ExtractionResult) -> str:
    """Generate Python SDK reference markdown, grouped by domain."""
    lines = [
        "<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->",
        "",
        f"# {module.title()} Python SDK",
        "",
    ]

    # Group by group tag
    grouped: dict[str | None, list[FunctionDoc]] = defaultdict(list)
    for f in results.functions:
        grouped[f.group].append(f)

    for group in sorted(grouped.keys(), key=lambda x: (x is None, x or "")):
        funcs = grouped[group]

        if group:
            lines.append(f"## {group}")
            lines.append("")

        for f in sorted(funcs, key=lambda x: x.name):
            lines.extend(
                [
                    f"### {f.name}",
                    "",
                    "```python",
                    f.signature,
                    "```",
                    "",
                ]
            )

            if f.brief:
                lines.append(f.brief)
                lines.append("")

            if f.params:
                lines.append("**Parameters:**")
                for name, desc in f.params.items():
                    lines.append(f"- `{name}`: {desc}")
                lines.append("")

            if f.returns:
                lines.append(f"**Returns:** {f.returns}")
                lines.append("")

            if f.examples:
                lines.append("**Example:**")
                lines.append("```python")
                for ex in f.examples:
                    lines.append(ex)
                lines.append("```")
                lines.append("")

            lines.append(f"*Source: {f.source_file}:{f.line_number}*")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)


def generate_sql_markdown(module: str, results: ExtractionResult) -> str:
    """Generate SQL API reference markdown, grouped by domain."""
    lines = [
        "<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->",
        "",
        f"# {module.title()} SQL API",
        "",
    ]

    if results.overview:
        lines.append(results.overview)
        lines.append("")

    # Only include documented functions
    documented = [f for f in results.functions if f.brief]

    if not documented:
        lines.append("*No documented functions yet. Add @function tags to SQL files.*")
        lines.append("")
        return "\n".join(lines)

    # Group by group tag
    grouped: dict[str | None, list[FunctionDoc]] = defaultdict(list)
    for f in documented:
        grouped[f.group].append(f)

    for group in sorted(grouped.keys(), key=lambda x: (x is None, x or "")):
        funcs = grouped[group]

        if group:
            lines.append(f"## {group}")
            lines.append("")

        for f in sorted(funcs, key=lambda x: x.name):
            lines.extend(
                [
                    f"### {f.name}",
                    "",
                    "```sql",
                    f.signature,
                    "```",
                    "",
                ]
            )

            if f.brief:
                lines.append(f.brief)
                lines.append("")

            if f.params:
                lines.append("**Parameters:**")
                for name, desc in f.params.items():
                    lines.append(f"- `{name}`: {desc}")
                lines.append("")

            if f.returns:
                lines.append(f"**Returns:** {f.returns}")
                lines.append("")

            if f.examples:
                lines.append("**Example:**")
                lines.append("```sql")
                for ex in f.examples:
                    lines.append(ex)
                lines.append("```")
                lines.append("")

            lines.append(f"*Source: {f.source_file}:{f.line_number}*")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)
