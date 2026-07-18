import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from postkit.authn import (
    AuthnClient,
    AuthnErrorCode,
    AuthnValidationError,
)


def _deleted_total(result: dict) -> int:
    return sum(result.values())


def _seed_public_cleanup_work(client: AuthnClient, count: int, prefix: str) -> int:
    user_id = client.create_user(f"{prefix}@example.com", "hash")

    for i in range(count):
        session_hash = f"{prefix}-session-{i}"
        client.create_session(user_id, session_hash)
        client.revoke_session(session_hash)

        token_hash = f"{prefix}-token-{i}"
        client.create_token(user_id, token_hash, "password_reset")
        client.consume_token(token_hash, "password_reset")

        key_id = client.create_api_key(user_id, f"{prefix}-key-{i}", f"Key {i}")
        client.revoke_api_key(key_id)

    return count * 3


def _seed_expired_refresh_tokens(client: AuthnClient, count: int, prefix: str):
    user_id = client.create_user(f"{prefix}@example.com", "hash")
    session_id = client.create_session(user_id, f"{prefix}-session")
    for i in range(count):
        client.create_refresh_token(
            session_id,
            f"{prefix}-refresh-{i}",
            expires_in=timedelta(milliseconds=50),
        )


def _seed_revoked_sessions(client: AuthnClient, count: int, prefix: str):
    user_id = client.create_user(f"{prefix}@example.com", "hash")
    for i in range(count):
        token_hash = f"{prefix}-session-{i}"
        client.create_session(user_id, token_hash)
        client.revoke_session(token_hash)


def _seed_expired_api_keys(client: AuthnClient, count: int, prefix: str):
    user_id = client.create_user(f"{prefix}@example.com", "hash")
    for i in range(count):
        client.create_api_key(
            user_id,
            f"{prefix}-key-{i}",
            f"Key {i}",
            expires_in=timedelta(milliseconds=50),
        )


def test_cleanup_uses_one_fair_shared_budget(authn):
    expected = _seed_public_cleanup_work(authn, 4, "fair-share")

    first = authn.cleanup_expired(batch_size=12)

    assert _deleted_total(first) <= 12
    assert first["sessions_deleted"] > 0
    assert first["tokens_deleted"] > 0
    assert first["api_keys_deleted"] > 0

    deleted = _deleted_total(first)
    for _ in range(expected + 1):
        result = authn.cleanup_expired(batch_size=12)
        count = _deleted_total(result)
        deleted += count
        if count == 0:
            break
    else:
        pytest.fail("cleanup did not drain a static public fixture")

    assert deleted == expected


@pytest.mark.parametrize(
    ("category", "result_key", "seed"),
    [
        ("refresh_tokens", "refresh_tokens_deleted", _seed_expired_refresh_tokens),
        ("sessions", "sessions_deleted", _seed_revoked_sessions),
        ("api_keys", "api_keys_deleted", _seed_expired_api_keys),
    ],
)
def test_concentrated_category_uses_the_full_budget(authn, category, result_key, seed):
    batch_size = 22
    seed(authn, batch_size + 5, f"concentrated-{category}")
    if category in {"refresh_tokens", "api_keys"}:
        time.sleep(0.1)

    result = authn.cleanup_expired(batch_size=batch_size)

    assert _deleted_total(result) == batch_size
    assert result[result_key] == batch_size


@pytest.mark.parametrize("category", ["ended", "expired"])
def test_operator_cleanup_concentrated_category_uses_full_budget(make_authn, category):
    platform = make_authn(f"operator_fill_{category}")
    customer = make_authn(f"operator_fill_{category}_target")
    operator_id = platform.create_user(f"operator-{category}@example.com", "hash")
    operator_session = platform.create_session(
        operator_id, f"operator-{category}-session"
    )
    target_id = customer.create_user(f"target-{category}@example.com", "hash")
    batch_size = 10

    for i in range(batch_size + 3):
        impersonation = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace=customer.namespace,
            token_hash=f"operator-{category}-token-{i}",
            reason="Cleanup budget test",
            duration=(timedelta(milliseconds=50) if category == "expired" else None),
        )
        if category == "ended":
            platform.end_operator_impersonation(str(impersonation["impersonation_id"]))

    if category == "expired":
        time.sleep(0.1)

    assert (
        platform.cleanup_expired_operator_sessions(batch_size=batch_size) == batch_size
    )
    remaining = platform.list_operator_impersonations_by_operator(
        operator_id, platform.namespace
    )
    assert len(remaining) == 3
    assert platform.cleanup_expired_operator_sessions(batch_size=batch_size) == 3
    assert (
        platform.list_operator_impersonations_by_operator(
            operator_id, platform.namespace
        )
        == []
    )


@pytest.mark.parametrize(
    ("batch_size", "error_code"),
    [
        (None, AuthnErrorCode.VAL_NOT_POSITIVE),
        (0, AuthnErrorCode.VAL_NOT_POSITIVE),
        (-1, AuthnErrorCode.VAL_NOT_POSITIVE),
        (10001, AuthnErrorCode.VAL_LIMIT_TOO_LARGE),
    ],
)
def test_cleanup_rejects_invalid_total_budgets(authn, batch_size, error_code):
    with pytest.raises(AuthnValidationError) as exc_info:
        authn.cleanup_expired(batch_size=batch_size)

    assert exc_info.value.sqlstate == "22023"
    assert exc_info.value.error_code == error_code


def test_concurrent_cleanup_calls_never_double_count(authn, connect):
    expected = _seed_public_cleanup_work(authn, 30, "concurrent")
    connections = [connect(), connect()]
    clients = [
        AuthnClient(connection.cursor(), authn.namespace) for connection in connections
    ]
    start = Barrier(2)

    def cleanup(client, connection):
        start.wait()
        result = client.cleanup_expired(batch_size=45)
        connection.commit()
        return _deleted_total(result)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(cleanup, client, connection)
            for client, connection in zip(clients, connections)
        ]
        deleted = sum(future.result() for future in futures)

    for _ in range(expected + 1):
        result = authn.cleanup_expired(batch_size=45)
        count = _deleted_total(result)
        deleted += count
        if count == 0:
            break
    else:
        pytest.fail("concurrent cleanup left a non-draining public fixture")

    assert deleted == expected
