"""postkit.authn - Authentication client for PostgreSQL-native auth."""

from postkit.authn.client import (
    AuthnClient,
    AuthnError,
)

__all__ = [
    "AuthnClient",
    "AuthnError",
]
