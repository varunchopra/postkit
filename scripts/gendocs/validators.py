"""Documentation validation and quality checks."""

from __future__ import annotations

from .models import ExtractionResult, FunctionDoc, ValidationResult


def validate_docs(
    python_results: list[ExtractionResult],
    sql_results: list[ExtractionResult],
    strict: bool = False,
) -> ValidationResult:
    """Validate extracted documentation.

    Checks:
    1. Public functions should have @brief (warning in normal mode, error in strict)
    2. Documented functions should have params/returns (warning)

    Args:
        python_results: Extraction results from Python files
        sql_results: Extraction results from SQL files
        strict: If True, missing docs are errors instead of warnings

    Returns:
        ValidationResult with errors and warnings
    """
    result = ValidationResult()

    all_docs: list[FunctionDoc] = []
    for r in python_results:
        all_docs.extend(r.functions)
    for r in sql_results:
        all_docs.extend(r.functions)

    for doc in all_docs:
        # Check for missing brief
        if not doc.brief:
            msg = f"{doc.name}: missing @brief (undocumented)"
            if strict:
                result.errors.append(msg)
            else:
                result.warnings.append(msg)
            continue

        # Check for missing params/returns (just a warning)
        if (
            doc.language == "sql"
            and doc.return_type
            and doc.return_type != "void"
            and not doc.returns
        ):
            result.warnings.append(f"{doc.name}: documented but missing @returns")

    return result


def compute_coverage(
    python_results: list[ExtractionResult],
    sql_results: list[ExtractionResult],
) -> dict[str, float]:
    """Compute documentation coverage by language.

    Returns:
        Dict with 'python' and 'sql' coverage (0.0 - 1.0)
    """
    py_total = sum(len(r.all_public_functions) for r in python_results)
    py_documented = sum(sum(1 for f in r.functions if f.brief) for r in python_results)

    sql_total = sum(len(r.all_public_functions) for r in sql_results)
    sql_documented = sum(sum(1 for f in r.functions if f.brief) for r in sql_results)

    return {
        "python": py_documented / py_total if py_total > 0 else 1.0,
        "sql": sql_documented / sql_total if sql_total > 0 else 1.0,
    }
