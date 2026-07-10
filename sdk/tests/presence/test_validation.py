"""Input validation across the presence surface, via the SDK client."""

from datetime import timedelta

import psycopg
import pytest
from postkit.presence import (
    PresenceClient,
    PresenceError,
    PresenceErrorCode,
    PresenceValidationError,
)

from tests.helpers import (
    ACCEPTED_NAMES,
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
    name_error_cases,
)
from tests.presence.helpers import cleanup_namespace


@pytest.fixture
def make_presence(db_connection):
    """Factory fixture creating PresenceClients with namespace cleanup."""
    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> PresenceClient:
        created.append(namespace)
        return PresenceClient(cursor, namespace)

    yield _make

    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


class TestNamespaceValidation:
    def test_valid_namespaces(self, make_presence):
        for ns in VALID_NAMESPACES:
            client = make_presence(ns)
            assert client.register("w1")["status"] == "unknown"

    @pytest.mark.parametrize(("ns", "error_code_name"), NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_presence, ns, error_code_name
    ):
        with pytest.raises(PresenceValidationError) as exc_info:
            make_presence(ns)
        assert exc_info.value.error_code == getattr(PresenceErrorCode, error_code_name)

    def test_error_hierarchy(self):
        assert issubclass(PresenceValidationError, PresenceError)


class TestInputValidation:
    @pytest.mark.parametrize(
        ("entity", "code"),
        [
            (None, PresenceErrorCode.VAL_ENTITY_NULL),
            ("", PresenceErrorCode.VAL_ENTITY_EMPTY),
            ("a" * 1025, PresenceErrorCode.VAL_ENTITY_TOO_LONG),
        ],
    )
    def test_bad_entity_ids(self, presence, entity, code):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.register(entity)
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(
        ("kind", "code"),
        [
            ("", PresenceErrorCode.VAL_KIND_EMPTY),
            ("a" * 257, PresenceErrorCode.VAL_KIND_TOO_LONG),
        ],
    )
    def test_bad_kinds(self, presence, kind, code):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.register("w1", kind=kind)
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(("entity", "code_name"), name_error_cases("VAL_ENTITY"))
    def test_entity_violations(self, presence, entity, code_name):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.register(entity)
        assert exc_info.value.error_code == getattr(PresenceErrorCode, code_name)

    @pytest.mark.parametrize(("kind", "code_name"), name_error_cases("VAL_KIND"))
    def test_kind_violations(self, presence, kind, code_name):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.register("w1", kind=kind)
        assert exc_info.value.error_code == getattr(PresenceErrorCode, code_name)

    @pytest.mark.parametrize(
        ("queue_name", "code_name"), name_error_cases("VAL_HOOK_QUEUE")
    )
    def test_hook_queue_violations(self, test_helpers, queue_name, code_name):
        """Hook queues have no SDK write path; the config trigger validates."""
        with pytest.raises(psycopg.errors.DataError) as exc_info:
            test_helpers.set_config(on_death_queue=queue_name)
        assert exc_info.value.diag.message_hint == f"postkit:presence:{code_name}"

    @pytest.mark.parametrize("kind", ACCEPTED_NAMES)
    def test_flexible_kinds_accepted(self, presence, kind):
        assert presence.register("w1", kind=kind)["kind"] == kind
        assert presence.register(kind)["status"] == "unknown"

    def test_negative_timeout(self, presence):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.register("w1", timeout=timedelta(seconds=-5))
        assert exc_info.value.error_code == PresenceErrorCode.VAL_TIMEOUT_NOT_POSITIVE

    def test_bad_status_filter(self, presence):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.list_entities(status="zombie")
        assert exc_info.value.error_code == PresenceErrorCode.VAL_STATUS_INVALID

    def test_zero_limit(self, presence):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.get_transitions(limit=0)
        assert exc_info.value.error_code == PresenceErrorCode.VAL_NOT_POSITIVE

    def test_null_entities_array(self, presence):
        with pytest.raises(PresenceValidationError) as exc_info:
            presence.heartbeat_many(None)
        assert exc_info.value.error_code == PresenceErrorCode.VAL_ENTITIES_NULL
