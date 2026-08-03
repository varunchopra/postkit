"""Tests for generated API reference structure."""

from gendocs.generators import generate_sql_markdown
from gendocs.models import ExtractionResult, FunctionDoc


def test_sql_overview_appears_once_before_function_groups():
    result = ExtractionResult(
        functions=[
            FunctionDoc(
                name="queue.work",
                module="queue",
                language="sql",
                signature="queue.work() -> void",
                brief="Do work.",
                source_file="queue/src/functions/010_api.sql",
                line_number=1,
                group="Jobs",
            )
        ],
        all_public_functions=["queue.work"],
        overview="Shared SQL contract.",
    )

    generated = generate_sql_markdown("queue", result)

    assert generated.count("Shared SQL contract.") == 1
    assert generated.index("Shared SQL contract.") < generated.index("## Jobs")
