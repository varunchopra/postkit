"""Input validation across the memory surface."""

import pytest
from postkit.memory import MemoryError, MemoryErrorCode, MemoryValidationError

from tests.helpers import (
    NAMESPACE_ERROR_CASES,
    name_error_cases,
)


class TestNamespaceValidation:
    """Namespace is validated when the client sets tenant context."""

    @pytest.mark.parametrize(("ns", "error_code_name"), NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_memory, ns, error_code_name
    ):
        with pytest.raises(MemoryValidationError) as exc_info:
            make_memory(ns)
        assert exc_info.value.error_code == getattr(MemoryErrorCode, error_code_name)

    def test_error_hierarchy(self):
        assert issubclass(MemoryValidationError, MemoryError)


class TestNameFieldValidation:
    @pytest.mark.parametrize(
        ("session", "code"),
        [
            (None, MemoryErrorCode.VAL_SESSION_NULL),
            ("", MemoryErrorCode.VAL_SESSION_EMPTY),
            ("a" * 1025, MemoryErrorCode.VAL_SESSION_TOO_LONG),
        ],
    )
    def test_bad_session(self, memory, session, code):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record(session, "user", "hello")
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(("session", "code_name"), name_error_cases("VAL_SESSION"))
    def test_session_violations(self, memory, session, code_name):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record(session, "user", "hello")
        assert exc_info.value.error_code == getattr(MemoryErrorCode, code_name)

    @pytest.mark.parametrize(
        ("role", "code"),
        [
            (None, MemoryErrorCode.VAL_ROLE_NULL),
            ("", MemoryErrorCode.VAL_ROLE_EMPTY),
            ("a" * 257, MemoryErrorCode.VAL_ROLE_TOO_LONG),
        ],
    )
    def test_bad_role(self, memory, role, code):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record("s1", role, "hello")
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(("role", "code_name"), name_error_cases("VAL_ROLE"))
    def test_role_violations(self, memory, role, code_name):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record("s1", role, "hello")
        assert exc_info.value.error_code == getattr(MemoryErrorCode, code_name)

    @pytest.mark.parametrize(
        ("model", "code_name"), name_error_cases("VAL_EMBED_MODEL")
    )
    def test_embed_model_violations(self, memory, model, code_name):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record(
                "s1", "user", "hello", embedding=[1, 0, 0, 0], embed_model=model
            )
        assert exc_info.value.error_code == getattr(MemoryErrorCode, code_name)


class TestContentValidation:
    @pytest.mark.parametrize(
        ("content", "code"),
        [
            (None, MemoryErrorCode.VAL_CONTENT_NULL),
            ("", MemoryErrorCode.VAL_CONTENT_EMPTY),
            ("   ", MemoryErrorCode.VAL_CONTENT_EMPTY),
        ],
    )
    def test_bad_content(self, memory, content, code):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.record("s1", "user", content)
        assert exc_info.value.error_code == code


class TestRecallValidation:
    def test_no_query_rejected(self, memory):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.recall()
        assert exc_info.value.error_code == MemoryErrorCode.VAL_RECALL_NO_QUERY

    def test_non_positive_k(self, memory):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.recall(keywords=["hi"], k=0)
        assert exc_info.value.error_code == MemoryErrorCode.VAL_NOT_POSITIVE


class TestConsolidateValidation:
    def test_bad_kind(self, memory):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.consolidate(
                [{"content": "x", "kind": "opinion"}], [], source_episodes=[]
            )
        assert exc_info.value.error_code == MemoryErrorCode.VAL_KIND_INVALID

    def test_bad_relation(self, memory):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.consolidate(
                [{"content": "a"}, {"content": "b"}],
                [{"from": "n0", "to": "n1", "relation": "sibling"}],
                source_episodes=[],
            )
        assert exc_info.value.error_code == MemoryErrorCode.VAL_RELATION_INVALID


class TestConsolidationDueValidation:
    def test_non_positive_batch(self, memory):
        with pytest.raises(MemoryValidationError) as exc_info:
            memory.consolidation_due(batch_size=0)
        assert exc_info.value.error_code == MemoryErrorCode.VAL_NOT_POSITIVE
