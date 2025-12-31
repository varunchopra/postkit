"""
End-to-End Demo: Authentication for a B2B SaaS Application

This test demonstrates two things:

1. The postkit/authn SDK (AuthnClient) - the generic auth API
2. Domain-specific helpers (AcmeAuth) - how customers layer their own abstractions

SCENARIO: Acme Corp SaaS
========================
Acme builds a B2B project management tool. They need:

- User signup with email verification
- Login with session management
- Password reset flows
- MFA for enterprise customers
- Brute-force protection

postkit/authn handles the data layer. Acme's code handles the crypto
(password hashing with argon2, token generation, TOTP verification).
"""

import hashlib
import secrets
from datetime import timedelta

from postkit.authn import AuthnClient

# Domain-specific helpers - how customers wrap the generic SDK with their
# own domain language. The SDK deals in users and sessions; this layer
# deals in signups, logins, and password resets.


def hash_password(password: str) -> str:
    """Simulate argon2 hashing. Real code: PasswordHasher().hash(password)"""
    return f"argon2id${hashlib.sha256(password.encode()).hexdigest()}"


def verify_password(password: str, hash: str) -> bool:
    """Simulate argon2 verification. Real code: PasswordHasher().verify(hash, password)"""
    return hash == hash_password(password)


def generate_token() -> tuple[str, str]:
    """Generate a token and its SHA-256 hash."""
    raw = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


class AcmeAuth:
    """
    Acme's domain-specific authentication helpers.

    Built on top of AuthnClient, this provides Acme-specific conveniences
    like signup() and login(). Every company would build their own version.
    """

    def __init__(self, client: AuthnClient):
        self.client = client

    def signup(self, email: str, password: str) -> dict:
        """Create account and send verification email."""
        password_hash = hash_password(password)
        user_id = self.client.create_user(email, password_hash)

        raw_token, token_hash = generate_token()
        self.client.create_token(user_id, token_hash, "email_verify")

        return {"user_id": user_id, "verify_token": raw_token}

    def verify_email(self, token: str) -> bool:
        """Verify email from the link we sent."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self.client.verify_email(token_hash) is not None

    def login(self, email: str, password: str, ip_address: str = None) -> dict | None:
        """Attempt login. Returns session info or None."""
        if self.client.is_locked_out(email):
            return None

        creds = self.client.get_credentials(email)
        if not creds or creds.get("disabled_at"):
            self.client.record_login_attempt(
                email, success=False, ip_address=ip_address
            )
            return None

        if not verify_password(password, creds["password_hash"]):
            self.client.record_login_attempt(
                email, success=False, ip_address=ip_address
            )
            return None

        self.client.record_login_attempt(email, success=True, ip_address=ip_address)
        raw_token, token_hash = generate_token()

        session_id = self.client.create_session(
            creds["user_id"],
            token_hash,
            expires_in=timedelta(days=7),
            ip_address=ip_address,
        )

        return {
            "user_id": creds["user_id"],
            "session_id": session_id,
            "token": raw_token,
            "token_hash": token_hash,
        }

    def request_password_reset(self, email: str) -> str | None:
        """Request password reset. Returns token to email to user."""
        user = self.client.get_user_by_email(email)
        if not user:
            return None

        # Invalidate any existing reset tokens
        self.client.invalidate_tokens(user["user_id"], "password_reset")

        raw_token, token_hash = generate_token()
        self.client.create_token(
            user["user_id"], token_hash, "password_reset", expires_in=timedelta(hours=1)
        )
        return raw_token

    def reset_password(self, token: str, new_password: str) -> bool:
        """Reset password using a token."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        result = self.client.consume_token(token_hash, "password_reset")
        if not result:
            return False

        self.client.update_password(result["user_id"], hash_password(new_password))
        self.client.revoke_all_sessions(result["user_id"])
        return True


class TestSaaSAuthentication:
    """
    Acme Corp's SaaS application uses postkit/authn as their
    authentication backend.
    """

    def test_complete_user_journey(self, authn: AuthnClient):
        """
        Full workflow demonstrating postkit/authn for a SaaS app.

        Shows both the generic SDK (authn) and domain helpers (acme).
        """
        # Wrap the SDK with Acme's domain helpers
        acme = AcmeAuth(authn)

        # 1. User signup
        # Alice signs up for Acme's project management tool.
        # She gets an email with a verification link.
        result = acme.signup("alice@company.com", "correct-horse-battery-staple")
        user_id = result["user_id"]

        user = authn.get_user(user_id)
        assert user["email"] == "alice@company.com"
        assert user["email_verified_at"] is None

        # 2. Email verification
        # Alice clicks the link in her email.
        assert acme.verify_email(result["verify_token"])

        user = authn.get_user(user_id)
        assert user["email_verified_at"] is not None

        # 3. Login
        # Next day, Alice comes back and logs in.
        session = acme.login("alice@company.com", "correct-horse-battery-staple")
        assert session is not None

        # 4. Session validation
        # On every request, Acme validates Alice's session.
        validated = authn.validate_session(session["token_hash"])
        assert validated["email"] == "alice@company.com"

        # 5. Multiple devices
        # Alice also logs in from her phone.
        phone_session = acme.login("alice@company.com", "correct-horse-battery-staple")

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 2

        # 6. Extend session
        # Alice checks "keep me logged in" on her laptop.
        authn.extend_session(session["token_hash"], timedelta(days=30))

        # 7. Logout
        # Alice logs out from her phone.
        authn.revoke_session(phone_session["token_hash"])
        assert authn.validate_session(phone_session["token_hash"]) is None

        # Laptop session still works
        assert authn.validate_session(session["token_hash"]) is not None

        # 8. Password reset
        # Alice forgot her password. She requests a reset.
        reset_token = acme.request_password_reset("alice@company.com")

        # She clicks the link and sets a new password.
        # This revokes all her sessions for security.
        assert acme.reset_password(reset_token, "new-password-2024")
        assert authn.validate_session(session["token_hash"]) is None

        # Old password doesn't work
        assert acme.login("alice@company.com", "correct-horse-battery-staple") is None

        # New password works
        assert acme.login("alice@company.com", "new-password-2024") is not None

        # 9. Email change
        # Alice got married and changed her email.
        authn.update_email(user_id, "alice.smith@company.com")

        user = authn.get_user(user_id)
        assert user["email"] == "alice.smith@company.com"
        assert user["email_verified_at"] is None  # needs re-verification

    def test_security_features(self, authn: AuthnClient):
        """
        Security features: brute-force protection, MFA, account disable.
        """
        acme = AcmeAuth(authn)

        # 1. Brute-force protection
        # An attacker tries to guess Bob's password.
        acme.signup("bob@company.com", "secure-password-123")

        for _ in range(5):
            acme.login("bob@company.com", "wrong-guess", ip_address="203.0.113.1")

        # Account is now locked
        assert authn.is_locked_out("bob@company.com")

        # Security team reviews the attempts
        attempts = authn.get_recent_attempts("bob@company.com")
        assert len(attempts) == 5
        assert all(a["success"] is False for a in attempts)

        # Even correct password is rejected during lockout
        assert acme.login("bob@company.com", "secure-password-123") is None

        # Admin clears the lockout after verifying it's really Bob
        authn.clear_attempts("bob@company.com")
        assert acme.login("bob@company.com", "secure-password-123") is not None

        # 2. MFA setup
        # Carol enables TOTP for extra security.
        result = acme.signup("carol@company.com", "password")
        carol_id = result["user_id"]

        assert not authn.has_mfa(carol_id)

        # She scans the QR code and adds her authenticator app
        totp_secret = "JBSWY3DPEHPK3PXP"
        mfa_id = authn.add_mfa(
            carol_id, "totp", totp_secret, name="Google Authenticator"
        )

        assert authn.has_mfa(carol_id)

        # During login, Acme fetches the secret to verify her TOTP code
        secrets_list = authn.get_mfa(carol_id, "totp")
        assert secrets_list[0]["secret"] == totp_secret

        # Record that MFA was used (for audit)
        authn.record_mfa_use(mfa_id)

        # Carol can also see her MFA methods (secrets hidden)
        methods = authn.list_mfa(carol_id)
        assert methods[0]["name"] == "Google Authenticator"
        assert "secret" not in methods[0]

        # 3. Account disable
        # Dave leaves the company. Admin disables his account.
        result = acme.signup("dave@company.com", "password")
        dave_id = result["user_id"]
        dave_session = acme.login("dave@company.com", "password")

        # Admin disables Dave's account
        authn.set_actor("admin@company.com", request_id="offboarding-dave")
        authn.disable_user(dave_id)
        authn.clear_actor()

        # Dave's session is immediately revoked
        assert authn.validate_session(dave_session["token_hash"]) is None

        # Dave can't log in
        assert acme.login("dave@company.com", "password") is None

        # Check audit trail
        events = authn.get_audit_events(limit=10)
        disable_event = next(e for e in events if e["event_type"] == "user_disabled")
        assert disable_event["actor_id"] == "admin@company.com"
        assert disable_event["request_id"] == "offboarding-dave"

        # Oops, Dave was just on leave. Admin re-enables.
        authn.enable_user(dave_id)
        assert acme.login("dave@company.com", "password") is not None
