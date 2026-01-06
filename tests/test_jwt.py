"""
Tests for ab0t_auth.jwt module.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from ab0t_auth.core import AuthConfig, AuthenticatedUser, TokenClaims
from ab0t_auth.errors import TokenExpiredError, TokenInvalidError
from ab0t_auth.jwt import (
    build_jwks_url,
    claims_to_token_claims,
    decode_token_unverified,
    is_token_expired,
    is_token_not_yet_valid,
    parse_token_header,
    should_introspect,
    token_claims_to_user,
)


class TestParseTokenHeader:
    """Tests for parse_token_header function."""

    def test_valid_bearer_token(self):
        """Test parsing valid Bearer token."""
        token = parse_token_header("Bearer eyJhbGciOiJSUzI1NiJ9.test.signature")

        assert token == "eyJhbGciOiJSUzI1NiJ9.test.signature"

    def test_case_insensitive_prefix(self):
        """Test prefix is case insensitive."""
        token = parse_token_header("bearer test_token")

        assert token == "test_token"

    def test_wrong_prefix(self):
        """Test wrong prefix returns None."""
        token = parse_token_header("Basic user:pass")

        assert token is None

    def test_empty_header(self):
        """Test empty header returns None."""
        assert parse_token_header("") is None
        assert parse_token_header(None) is None  # type: ignore

    def test_missing_token(self):
        """Test missing token part returns None."""
        assert parse_token_header("Bearer") is None
        assert parse_token_header("Bearer ") is None

    def test_custom_prefix(self):
        """Test custom prefix."""
        token = parse_token_header("ApiKey abc123", prefix="ApiKey")

        assert token == "abc123"


class TestClaimsToTokenClaims:
    """Tests for claims_to_token_claims function."""

    def test_basic_claims(self):
        """Test converting basic claims."""
        payload = {
            "sub": "user_123",
            "email": "test@example.com",
            "org_id": "org_456",
            "exp": 1700000000,
            "iat": 1699990000,
        }

        claims = claims_to_token_claims(payload)

        assert claims.sub == "user_123"
        assert claims.email == "test@example.com"
        assert claims.org_id == "org_456"
        assert claims.exp == 1700000000
        assert claims.user_id == "user_123"  # Falls back to sub

    def test_permissions_from_array(self):
        """Test parsing permissions from array."""
        payload = {
            "sub": "user_123",
            "permissions": ["read", "write", "delete"],
        }

        claims = claims_to_token_claims(payload)

        assert claims.permissions == ("read", "write", "delete")

    def test_permissions_from_scope_string(self):
        """Test parsing permissions from scope string."""
        payload = {
            "sub": "user_123",
            "scope": "read write admin",
        }

        claims = claims_to_token_claims(payload)

        assert claims.permissions == ("read", "write", "admin")

    def test_roles_from_array(self):
        """Test parsing roles."""
        payload = {
            "sub": "user_123",
            "roles": ["admin", "user"],
        }

        claims = claims_to_token_claims(payload)

        assert claims.roles == ("admin", "user")

    def test_audience_as_string(self):
        """Test audience as string."""
        payload = {"sub": "user_123", "aud": "my-api"}

        claims = claims_to_token_claims(payload)

        assert claims.aud == "my-api"

    def test_audience_as_list(self):
        """Test audience as list becomes tuple."""
        payload = {"sub": "user_123", "aud": ["api1", "api2"]}

        claims = claims_to_token_claims(payload)

        assert claims.aud == ("api1", "api2")

    def test_user_id_takes_precedence(self):
        """Test user_id takes precedence over sub."""
        payload = {
            "sub": "sub_123",
            "user_id": "user_456",
        }

        claims = claims_to_token_claims(payload)

        assert claims.user_id == "user_456"


class TestTokenClaimsToUser:
    """Tests for token_claims_to_user function."""

    def test_convert_claims_to_user(self, test_claims: TokenClaims):
        """Test converting claims to user."""
        user = token_claims_to_user(test_claims)

        assert isinstance(user, AuthenticatedUser)
        assert user.user_id == test_claims.user_id
        assert user.email == test_claims.email
        assert user.permissions == test_claims.permissions
        assert user.claims == test_claims

    def test_missing_user_id_raises(self):
        """Test raises when no user identifier."""
        claims = TokenClaims(email="test@example.com")

        with pytest.raises(TokenInvalidError) as exc_info:
            token_claims_to_user(claims)

        assert "user identifier" in str(exc_info.value).lower()


class TestIsTokenExpired:
    """Tests for is_token_expired function."""

    def test_not_expired(self):
        """Test non-expired token."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) + 3600,
        )

        assert not is_token_expired(claims)

    def test_expired(self):
        """Test expired token."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) - 100,
        )

        assert is_token_expired(claims)

    def test_with_leeway(self):
        """Test leeway handling."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) - 5,  # Expired 5 seconds ago
        )

        # Without leeway - expired
        assert is_token_expired(claims, leeway=0)

        # With 10 second leeway - not expired
        assert not is_token_expired(claims, leeway=10)

    def test_no_exp_claim(self):
        """Test token without exp claim is never expired."""
        claims = TokenClaims(sub="user")

        assert not is_token_expired(claims)


class TestIsTokenNotYetValid:
    """Tests for is_token_not_yet_valid function."""

    def test_valid_now(self):
        """Test token valid now."""
        claims = TokenClaims(
            sub="user",
            nbf=int(time.time()) - 100,
        )

        assert not is_token_not_yet_valid(claims)

    def test_not_yet_valid(self):
        """Test token not yet valid."""
        claims = TokenClaims(
            sub="user",
            nbf=int(time.time()) + 100,
        )

        assert is_token_not_yet_valid(claims)

    def test_no_nbf_claim(self):
        """Test token without nbf is always valid."""
        claims = TokenClaims(sub="user")

        assert not is_token_not_yet_valid(claims)


class TestBuildJwksUrl:
    """Tests for build_jwks_url function."""

    def test_without_org_id(self, auth_config: AuthConfig):
        """Test JWKS URL without org_id."""
        config = AuthConfig(auth_url="https://auth.example.com")

        url = build_jwks_url(config)

        assert url == "https://auth.example.com/.well-known/jwks.json"

    def test_with_org_id(self):
        """Test JWKS URL with org_id."""
        config = AuthConfig(
            auth_url="https://auth.example.com",
            org_id="my_org",
        )

        url = build_jwks_url(config)

        assert url == "https://auth.example.com/organizations/my_org/.well-known/jwks.json"


class TestShouldIntrospect:
    """Tests for should_introspect function."""

    def test_no_exp_should_introspect(self):
        """Test tokens without exp should be introspected."""
        claims = TokenClaims(sub="user")

        assert should_introspect(claims)

    def test_close_to_expiration(self):
        """Test tokens close to expiration should be introspected."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) + 60,  # Expires in 1 minute
        )

        assert should_introspect(claims, introspect_threshold=300)

    def test_far_from_expiration(self):
        """Test tokens far from expiration don't need introspection."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) + 3600,  # Expires in 1 hour
            iat=int(time.time()),  # Just issued
        )

        assert not should_introspect(claims, introspect_threshold=300)

    def test_long_lived_token(self):
        """Test long-lived tokens should be introspected."""
        claims = TokenClaims(
            sub="user",
            exp=int(time.time()) + 86400,  # Expires in 1 day
            iat=int(time.time()) - 7200,  # Issued 2 hours ago
        )

        assert should_introspect(claims)


class TestDecodeTokenUnverified:
    """Tests for decode_token_unverified function."""

    def test_decode_valid_structure(self):
        """Test decoding a properly structured token."""
        # This is a properly structured JWT with sub claim
        # Note: signature is fake, but structure is valid
        with patch("ab0t_auth.jwt.jwt.decode") as mock_decode:
            mock_decode.return_value = {
                "sub": "user_123",
                "email": "test@example.com",
            }

            claims = decode_token_unverified("fake.jwt.token")

            assert claims.sub == "user_123"
            assert claims.email == "test@example.com"
            mock_decode.assert_called_once_with(
                "fake.jwt.token",
                options={"verify_signature": False},
            )

    def test_decode_invalid_token(self):
        """Test decoding invalid token raises."""
        with patch("ab0t_auth.jwt.jwt.decode") as mock_decode:
            import jwt
            mock_decode.side_effect = jwt.DecodeError("Invalid token")

            with pytest.raises(TokenInvalidError):
                decode_token_unverified("invalid_token")
