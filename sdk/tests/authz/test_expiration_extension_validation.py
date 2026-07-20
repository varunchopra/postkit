from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from postkit.authz import AuthzErrorCode, AuthzValidationError


def test_expiration_extension_must_be_positive(authz):
    original = datetime.now(timezone.utc) + timedelta(days=7)
    authz.grant(
        "read",
        resource=("doc", "one"),
        subject=("user", "alice"),
        expires_at=original,
    )
    invalid_extensions = [
        timedelta(0),
        timedelta(seconds=-1),
        cast(timedelta, None),
    ]
    for extension in invalid_extensions:
        with pytest.raises(AuthzValidationError) as exc_info:
            authz.extend_expiration(
                "read",
                resource=("doc", "one"),
                subject=("user", "alice"),
                extension=extension,
            )
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == AuthzErrorCode.VAL_INTERVAL_NOT_POSITIVE
        [grant] = authz.list_expiring(within=timedelta(days=8))
        assert grant["expires_at"] == original

    extended = authz.extend_expiration(
        "read",
        resource=("doc", "one"),
        subject=("user", "alice"),
        extension=timedelta(days=1),
    )
    assert extended == original + timedelta(days=1)
