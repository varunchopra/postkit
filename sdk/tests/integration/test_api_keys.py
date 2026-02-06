"""Integration tests for API keys with scoped permissions."""

import hashlib
import secrets
from datetime import timedelta


def hash_key(raw_key: str) -> str:
    """Hash a raw key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


class TestApiKeyWithScopedPermissions:
    """API keys with authz-backed scopes."""

    def test_direct_permissions(self, clients):
        """API key gets direct permission grants."""
        authn, authz, _ = clients

        user_id = authn.create_user("alice@example.com", hash_key("password123"))
        raw_key = secrets.token_urlsafe(32)
        key_id = authn.create_api_key(
            user_id,
            hash_key(raw_key),
            name="Production",
            expires_in=timedelta(days=365),
        )

        authz.grant("read", resource=("repo", "api"), subject=("api_key", key_id))
        authz.grant("write", resource=("repo", "api"), subject=("api_key", key_id))

        key_info = authn.validate_api_key(hash_key(raw_key))
        assert key_info is not None
        assert key_info["user_id"] == user_id
        assert key_info["name"] == "Production"

        assert authz.check(("api_key", key_id), "read", ("repo", "api"))
        assert authz.check(("api_key", key_id), "write", ("repo", "api"))
        assert not authz.check(("api_key", key_id), "admin", ("repo", "api"))

    def test_authn_revocation_preserves_authz_grants(self, clients):
        """Revoking an API key in authn does not cascade to authz grants.

        Authn and authz have no FK or trigger relationship. Revoking a key
        invalidates the credential but leaves its authz grants intact. The
        application layer must call revoke_all_grants separately if cleanup
        is desired.
        """
        authn, authz, _ = clients

        user_id = authn.create_user("eve@example.com", hash_key("password"))
        raw_key = secrets.token_urlsafe(32)
        key_id = authn.create_api_key(user_id, hash_key(raw_key))

        authz.grant("read", resource=("doc", "secret"), subject=("api_key", key_id))

        assert authn.validate_api_key(hash_key(raw_key)) is not None
        assert authn.revoke_api_key(key_id)
        assert authn.validate_api_key(hash_key(raw_key)) is None

        # Authz grants survive authn revocation -- no cross-schema cascade.
        assert authz.check(("api_key", key_id), "read", ("doc", "secret"))

    def test_expired_key_denied(self, authn):
        """Expired API key fails validation."""
        user_id = authn.create_user("frank@example.com", hash_key("password"))
        raw_key = secrets.token_urlsafe(32)

        authn.create_api_key(
            user_id, hash_key(raw_key), expires_in=timedelta(seconds=-1)
        )

        assert authn.validate_api_key(hash_key(raw_key)) is None


class TestRealWorldScenarios:
    """End-to-end scenarios."""

    def test_scoped_api_key_flow(self, clients):
        """API key with scoped permissions and rate limits."""
        authn, authz, config = clients

        owner_id = authn.create_user("owner@acme.com", hash_key("secure-password"))
        raw_key = secrets.token_urlsafe(32)
        key_id = authn.create_api_key(
            owner_id, hash_key(raw_key), name="Production API Key"
        )

        authz.grant(
            "read", resource=("resource_type", "customers"), subject=("api_key", key_id)
        )
        authz.grant(
            "create", resource=("resource_type", "charges"), subject=("api_key", key_id)
        )
        config.set(f"limits/api_key/{key_id}", {"requests_per_minute": 100})

        def handle_request(key_hash: str, action: str, resource_type: str) -> dict:
            key_info = authn.validate_api_key(key_hash)
            if not key_info:
                return {"status": 401}

            if not authz.check(
                ("api_key", key_info["key_id"]),
                action,
                ("resource_type", resource_type),
            ):
                return {"status": 403}

            limits = config.get_value(f"limits/api_key/{key_info['key_id']}")
            return {
                "status": 200,
                "rate_limit": limits["requests_per_minute"] if limits else 60,
            }

        assert handle_request(hash_key(raw_key), "read", "customers")["status"] == 200
        assert handle_request(hash_key(raw_key), "create", "charges")["status"] == 200
        assert handle_request(hash_key(raw_key), "delete", "customers")["status"] == 403
        assert (
            handle_request(hash_key("wrong-key"), "read", "customers")["status"] == 401
        )

    def test_api_key_limited_to_subset_of_user_permissions(self, clients):
        """API key receives narrower grants than its owning user.

        The user has admin on two repos. The API key gets read+write on one.
        Authz treats the user and key as independent subjects, so the key
        never inherits the user's broader grants.
        """
        authn, authz, _ = clients

        dev_id = authn.create_user("dev@example.com", hash_key("password"))

        # User has admin on multiple repos.
        authz.grant("admin", resource=("repo", "frontend"), subject=("user", dev_id))
        authz.grant("admin", resource=("repo", "backend"), subject=("user", dev_id))

        # API key only gets limited access to one repo.
        raw_key = secrets.token_urlsafe(32)
        key_id = authn.create_api_key(dev_id, hash_key(raw_key))
        authz.grant("read", resource=("repo", "frontend"), subject=("api_key", key_id))
        authz.grant("write", resource=("repo", "frontend"), subject=("api_key", key_id))

        # API key is limited to its own grants.
        assert authz.check(("api_key", key_id), "write", ("repo", "frontend"))
        assert not authz.check(("api_key", key_id), "admin", ("repo", "frontend"))
        assert not authz.check(("api_key", key_id), "read", ("repo", "backend"))

        # User still has full access.
        assert authz.check(("user", dev_id), "admin", ("repo", "frontend"))
        assert authz.check(("user", dev_id), "admin", ("repo", "backend"))
