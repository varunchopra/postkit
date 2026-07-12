"""Input validation across the outbox surface, via the SDK client."""

import pytest
from postkit.outbox import (
    OutboxClient,
    OutboxCursorLostError,
    OutboxError,
    OutboxErrorCode,
    OutboxValidationError,
)

from tests.helpers import (
    ACCEPTED_NAMES,
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
    name_error_cases,
)


@pytest.fixture
def make_outbox(db_connection):
    """Factory fixture creating OutboxClients with namespace cleanup."""
    from tests.outbox.helpers import cleanup_namespace

    created = []
    cursor = db_connection.cursor()

    def _make(namespace: str) -> OutboxClient:
        created.append(namespace)
        return OutboxClient(cursor, namespace)

    yield _make

    for ns in created:
        cleanup_namespace(cursor, ns)
    cursor.close()


class TestNamespaceValidation:
    def test_valid_namespaces(self, make_outbox, db_connection):
        for ns in VALID_NAMESPACES:
            client = make_outbox(ns)
            with db_connection.transaction():
                assert client.emit("t", "e.created", {"n": 1}) > 0

    @pytest.mark.parametrize(("ns", "error_code_name"), NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_outbox, ns, error_code_name
    ):
        with pytest.raises(OutboxValidationError) as exc_info:
            make_outbox(ns)
        assert exc_info.value.error_code == getattr(OutboxErrorCode, error_code_name)

    def test_error_hierarchy(self):
        assert issubclass(OutboxValidationError, OutboxError)
        assert issubclass(OutboxCursorLostError, OutboxError)


class TestTopicAndInputValidation:
    def test_star_topic_reserved(self, outbox, db_connection):
        with pytest.raises(OutboxValidationError) as exc_info:
            with db_connection.transaction():
                outbox.emit("*", "e.created", {})
        assert exc_info.value.error_code == OutboxErrorCode.VAL_TOPIC_RESERVED

    @pytest.mark.parametrize(
        ("topic", "code"),
        [
            (None, OutboxErrorCode.VAL_TOPIC_NULL),
            ("", OutboxErrorCode.VAL_TOPIC_EMPTY),
            ("a" * 257, OutboxErrorCode.VAL_TOPIC_TOO_LONG),
        ],
    )
    def test_bad_topics(self, outbox, db_connection, topic, code):
        with pytest.raises(OutboxValidationError) as exc_info:
            with db_connection.transaction():
                outbox.emit(topic, "e.created", {})
        assert exc_info.value.error_code == code


class TestNameRules:
    """Topics, consumers, and event types follow the shared name rules."""

    @pytest.mark.parametrize(("topic", "code_name"), name_error_cases("VAL_TOPIC"))
    def test_topic_violations(self, outbox, db_connection, topic, code_name):
        with pytest.raises(OutboxValidationError) as exc_info:
            with db_connection.transaction():
                outbox.emit(topic, "e.created", {})
        assert exc_info.value.error_code == getattr(OutboxErrorCode, code_name)

    @pytest.mark.parametrize(
        ("consumer", "code_name"), name_error_cases("VAL_CONSUMER")
    )
    def test_consumer_violations(self, outbox, consumer, code_name):
        with pytest.raises(OutboxValidationError) as exc_info:
            outbox.subscribe("orders", consumer, from_="start")
        assert exc_info.value.error_code == getattr(OutboxErrorCode, code_name)

    @pytest.mark.parametrize(
        ("event_type", "code_name"), name_error_cases("VAL_EVENT_TYPE")
    )
    def test_event_type_violations(self, outbox, db_connection, event_type, code_name):
        with pytest.raises(OutboxValidationError) as exc_info:
            with db_connection.transaction():
                outbox.emit("orders", event_type, {})
        assert exc_info.value.error_code == getattr(OutboxErrorCode, code_name)

    @pytest.mark.parametrize("name", ACCEPTED_NAMES)
    def test_flexible_names_accepted(self, outbox, db_connection, name):
        with db_connection.transaction():
            assert outbox.emit(name, name, {}) > 0
        assert outbox.subscribe(name, name, from_="start") is not None

    def test_negative_position(self, outbox):
        outbox.subscribe("orders", "billing", from_="start")
        with pytest.raises(OutboxValidationError) as exc_info:
            outbox.ack("orders", "billing", 0, -1)
        assert exc_info.value.error_code == OutboxErrorCode.VAL_POSITION_INVALID

    def test_zero_limit(self, outbox):
        outbox.subscribe("orders", "billing", from_="start")
        with pytest.raises(OutboxValidationError) as exc_info:
            outbox.poll("orders", "billing", limit=0)
        assert exc_info.value.error_code == OutboxErrorCode.VAL_NOT_POSITIVE


class TestEmitTransactionGuard:
    """emit() outside an open transaction would commit alone, describing no
    state change, so the client refuses to run it."""

    def test_emit_without_transaction_raises(self, outbox):
        with pytest.raises(OutboxError, match="requires an open transaction"):
            outbox.emit("orders", "order.created", {"n": 1})

    def test_emit_inside_transaction_succeeds(self, outbox, db_connection):
        with db_connection.transaction():
            assert outbox.emit("orders", "order.created", {"n": 1}) > 0


class TestCursorLostMapping:
    def test_cursor_lost_maps_to_dedicated_error(
        self, outbox, db_connection, test_helpers
    ):
        from datetime import timedelta

        test_helpers.set_config(protect_cursors=False)
        outbox.subscribe("orders", "slow", from_="start")
        with db_connection.transaction():
            event_id = outbox.emit("orders", "order.created", {})
        test_helpers.wait_readable("orders", event_id)
        test_helpers.age_events("40 days")
        outbox.trim(timedelta(days=30))

        with pytest.raises(OutboxCursorLostError) as exc_info:
            outbox.poll("orders", "slow")
        assert exc_info.value.error_code == OutboxErrorCode.BIZ_CURSOR_LOST

    def test_plain_validation_is_not_cursor_lost(self, outbox, db_connection):
        """Both share SQLSTATE 22023; only the hint may distinguish them."""
        with pytest.raises(OutboxValidationError) as exc_info:
            with db_connection.transaction():
                outbox.emit("*", "e.created", {})
        assert not isinstance(exc_info.value, OutboxCursorLostError)
