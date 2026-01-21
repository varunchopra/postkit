"""Tests for docstring parser."""

from gendocs.extractors import _parse_docstring


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
