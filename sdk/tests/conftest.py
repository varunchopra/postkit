"""Shared pytest configuration for postkit SDK tests."""

import os
from pathlib import Path

import pytest

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/postgres"
)

_TESTS_DIR = Path(__file__).resolve().parent
_MODULE_DIRS = {
    p.name for p in _TESTS_DIR.iterdir() if p.is_dir() and p.name != "__pycache__"
}


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Assign xdist_group marks based on parent directory.

    Must run before xdist's own hook (which reads these marks and appends
    @groupname to node IDs), so we use tryfirst.
    """
    for item in items:
        try:
            rel = Path(item.fspath).resolve().relative_to(_TESTS_DIR)
        except ValueError:
            continue
        module_dir = rel.parts[0] if rel.parts else None
        if module_dir in _MODULE_DIRS:
            item.add_marker(pytest.mark.xdist_group(module_dir))
