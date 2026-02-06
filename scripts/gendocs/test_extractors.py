"""Tests for docstring and SQL doc block parsers."""

from gendocs.extractors import (
    _extract_examples,
    _extract_params,
    _extract_tag,
    _parse_docstring,
)


def test_brief():
    doc = """Short description."""
    result = _parse_docstring(doc)
    assert result.brief == "Short description."


def test_multiline_brief():
    doc = """
    First line of description
    continues here.

    Args:
        x: A parameter
    """
    result = _parse_docstring(doc)
    assert result.brief == "First line of description continues here."


def test_multiparagraph_brief():
    """Multi-paragraph briefs preserve paragraph breaks."""
    doc = """
    First paragraph here.

    Second paragraph with more details.

    Args:
        x: A parameter
    """
    result = _parse_docstring(doc)
    assert (
        result.brief == "First paragraph here.\n\nSecond paragraph with more details."
    )


def test_brief_with_list():
    """List items in brief are preserved on separate lines."""
    doc = """
    Returns None if:
    - Token not found
    - Token expired
    - Already used

    Args:
        x: A parameter
    """
    result = _parse_docstring(doc)
    assert (
        result.brief
        == "Returns None if:\n- Token not found\n- Token expired\n- Already used"
    )


def test_brief_with_indented_definitions():
    """Indented definition lists are preserved based on indentation."""
    doc = """
    Register a schema for validation.

    Pattern types:
        Prefix (trailing /): for collections
        Exact (no trailing /): for unique items

    Args:
        x: A parameter
    """
    result = _parse_docstring(doc)
    assert result.brief == (
        "Register a schema for validation.\n\n"
        "Pattern types:\n"
        "Prefix (trailing /): for collections\n"
        "Exact (no trailing /): for unique items"
    )


def test_params():
    doc = """
    Do something.

    Args:
        name: The name
        value: The value to set
    """
    result = _parse_docstring(doc)
    assert result.params == {"name": "The name", "value": "The value to set"}


def test_returns_simple():
    doc = """
    Do something.

    Returns:
        The result value
    """
    result = _parse_docstring(doc)
    assert result.returns == "The result value"


def test_returns_multiline():
    doc = """
    Get statistics.

    Returns:
        Dictionary with:
        - count: Number of items
        - total: Total value

    Example:
        stats = get_stats()
    """
    result = _parse_docstring(doc)
    assert "Dictionary with:" in result.returns
    assert "- count: Number of items" in result.returns
    assert "- total: Total value" in result.returns


def test_example():
    doc = """
    Do something.

    Example:
        result = do_something()
        print(result)
    """
    result = _parse_docstring(doc)
    assert len(result.examples) == 1
    assert "result = do_something()" in result.examples[0]
    assert "print(result)" in result.examples[0]


def test_example_multiline_code():
    doc = """
    Grant permission.

    Example:
        authz.grant("admin", resource=("repo", "api"),
                   subject=("team", "eng"))
    """
    result = _parse_docstring(doc)
    assert len(result.examples) == 1
    assert 'authz.grant("admin"' in result.examples[0]


def test_full_docstring():
    doc = """
    Grant a permission on a resource.

    Args:
        permission: The permission to grant
        resource: The resource tuple

    Returns:
        The tuple ID

    Example:
        authz.grant("read", resource=("doc", "1"))
    """
    result = _parse_docstring(doc)
    assert result.brief == "Grant a permission on a resource."
    assert result.params == {
        "permission": "The permission to grant",
        "resource": "The resource tuple",
    }
    assert result.returns == "The tuple ID"
    assert len(result.examples) == 1


def test_empty_docstring():
    result = _parse_docstring(None)
    assert result.brief == ""
    assert result.params == {}
    assert result.returns is None
    assert result.examples == []

    result = _parse_docstring("")
    assert result.brief == ""


def test_example_with_if_else():
    """Regression test: Python keywords in Example shouldn't become params."""
    doc = """
    Get current balance.

    Args:
        user_id: User ID
        event_type: Event type

    Returns:
        Dict with balance info

    Example:
        balance = meter.get_balance(user_id, "llm_call", "tokens")
        if balance["available"] >= needed:
            proceed()
        else:
            raise QuotaExceeded()
    """
    result = _parse_docstring(doc)
    assert result.params == {
        "user_id": "User ID",
        "event_type": "Event type",
    }
    assert "if" not in result.params
    assert "else" not in result.params


def test_example_with_for_loop():
    """Regression test: for keyword in Example shouldn't become param."""
    doc = """
    List items.

    Args:
        resource: The resource tuple

    Returns:
        List of grants

    Example:
        grants = authz.list_grants(("api_key", key_id))
        for grant in grants:
            print(grant['relation'])
    """
    result = _parse_docstring(doc)
    assert result.params == {"resource": "The resource tuple"}
    assert "for" not in result.params


def test_multiline_param_description():
    """Multi-line param descriptions should be preserved."""
    doc = """
    Do something.

    Args:
        param: This is a long description
            that continues on the next line
            and even a third line
        other: Another param
    """
    result = _parse_docstring(doc)
    assert (
        result.params["param"]
        == "This is a long description that continues on the next line and even a third line"
    )
    assert result.params["other"] == "Another param"


# =============================================================================
# SQL doc block extraction tests
# =============================================================================


def test_extract_tag_simple():
    """Extract a simple @returns tag."""
    block = "-- @returns True if acknowledged\n"
    assert _extract_tag(block, "returns") == "True if acknowledged"


def test_extract_tag_stops_at_blank_comment_line():
    """@returns does not bleed into extended description after a blank -- line."""
    block = (
        "-- @brief Do something.\n"
        "-- @returns True if acknowledged, false if not found\n"
        "--\n"
        "-- Job is either deleted or archived.\n"
    )
    assert _extract_tag(block, "returns") == "True if acknowledged, false if not found"


def test_extract_tag_stops_at_next_tag():
    """@brief stops at the next @param tag."""
    block = "-- @brief Do something.\n-- @param p_id The ID\n-- @returns The result\n"
    assert _extract_tag(block, "brief") == "Do something."


def test_extract_tag_multiline_before_blank():
    """Multi-line tag content is joined until the blank -- line."""
    block = (
        "-- @returns Row per queue with status counts,\n"
        "-- oldest pending age, and dead letter count\n"
        "--\n"
        "-- Unlike get_stats, this breaks down by queue.\n"
    )
    result = _extract_tag(block, "returns")
    assert (
        result
        == "Row per queue with status counts, oldest pending age, and dead letter count"
    )


def test_extract_params_last_param_stops_at_blank_line():
    """Last @param does not bleed into extended description."""
    block = (
        "-- @param p_namespace Tenant namespace\n"
        "-- @param p_reason Optional reason for the action\n"
        "--\n"
        "-- Actor context is captured when jobs are pushed.\n"
    )
    params = _extract_params(block)
    assert params["p_namespace"] == "Tenant namespace"
    assert params["p_reason"] == "Optional reason for the action"


def test_extract_params_stops_at_next_tag():
    """@param stops at @returns."""
    block = "-- @param p_id The ID\n-- @returns The result\n"
    params = _extract_params(block)
    assert params["p_id"] == "The ID"


def test_extract_examples_simple():
    """Extract a single-line @example."""
    block = "-- @brief Do something.\n-- @example SELECT do_something();\n"
    examples = _extract_examples(block)
    assert len(examples) == 1
    assert examples[0] == "SELECT do_something();"


def test_extract_examples_stops_at_blank_comment_line():
    """@example does not bleed through a blank -- line into prose below."""
    block = (
        "-- @example SELECT do_something();\n"
        "--\n"
        "-- This is extended prose, not part of the example.\n"
    )
    examples = _extract_examples(block)
    assert len(examples) == 1
    assert examples[0] == "SELECT do_something();"
