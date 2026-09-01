"""
Tests for the "no data evaporates" guarantee (preserve unknown response fields).

Background: the client parses auth-service responses with response.json() and
builds frozen slotted dataclasses via selective data.get("field") extraction.
Any field the auth service ADDS that the library does not model was previously
silently discarded — no error, no warning, no way for a caller to read it.

Each response dataclass built from a server JSON dict now carries a ``raw``
field holding the complete, unmodified dict. These tests prove that when a
response contains an unknown/extra field, the model still (a) constructs and
(b) exposes that field via ``.raw["new_field"]`` — while the modeled fields
keep parsing exactly as before.
"""

import httpx
import pytest
import respx

from ab0t_auth.client import (
    introspect_token,
    login,
    refresh_token,
    validate_api_key,
    validate_token,
)
from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    IntrospectionResponse,
    LoginResponse,
    PermissionCheckResponse,
    TokenValidationResponse,
)

AUTH_URL = "https://auth.test.ab0t.com"


@pytest.fixture
def auth_config() -> AuthConfig:
    return AuthConfig(
        auth_url=AUTH_URL,
        org_id="test_org",
        algorithms=("RS256",),
        audience="test-api",
        issuer=AUTH_URL,
        debug=True,
    )


# =============================================================================
# Dataclass-level: raw defaults to {} and is a declared slots field
# =============================================================================


class TestRawFieldDeclared:
    """The raw field must be a real, defaulted, backward-compatible field."""

    def test_all_response_types_default_raw_to_empty_dict(self):
        """Positional construction still works; raw defaults to {}."""
        assert LoginResponse(access_token="tok").raw == {}
        assert TokenValidationResponse(valid=True).raw == {}
        assert PermissionCheckResponse(allowed=True, permission="x").raw == {}
        assert ApiKeyValidationResponse(valid=True).raw == {}
        assert IntrospectionResponse().raw == {}

    def test_raw_is_settable_at_construction_on_slots_dataclass(self):
        """raw must be a DECLARED field — slotted dataclasses reject stray attrs."""
        payload = {"access_token": "tok", "brand_new_field": 42}
        resp = LoginResponse(access_token="tok", raw=payload)
        assert resp.raw["brand_new_field"] == 42

        # And confirm arbitrary attributes are still rejected (slots intact).
        with pytest.raises((AttributeError, TypeError)):
            resp.some_undeclared_attr = 1  # type: ignore[attr-defined]


# =============================================================================
# login()
# =============================================================================


class TestLoginPreservesUnknownFields:
    @pytest.mark.asyncio
    async def test_login_exposes_unknown_field_via_raw(self, auth_config):
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/login").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "access_token": "acc",
                        "refresh_token": "ref",
                        "user_id": "user_1",
                        "permissions": ["read"],
                        # Field the library does NOT model yet:
                        "mfa_level": "totp",
                        "session_id": "sess_abc",
                    },
                )
            )
            async with httpx.AsyncClient() as client:
                result = await login(client, auth_config, "e@x.com", "pw")

        # (a) still constructs, modeled fields intact
        assert result.access_token == "acc"
        assert result.user_id == "user_1"
        assert result.permissions == ("read",)
        # (b) unknown fields preserved and readable
        assert result.raw["mfa_level"] == "totp"
        assert result.raw["session_id"] == "sess_abc"


# =============================================================================
# refresh_token()
# =============================================================================


class TestRefreshPreservesUnknownFields:
    @pytest.mark.asyncio
    async def test_refresh_exposes_unknown_field_via_raw(self, auth_config):
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/refresh").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "access_token": "acc2",
                        "refresh_token": "ref2",
                        "rotated_from": "ref1",  # unmodeled
                    },
                )
            )
            async with httpx.AsyncClient() as client:
                result = await refresh_token(client, auth_config, "ref1")

        assert result.access_token == "acc2"
        assert result.raw["rotated_from"] == "ref1"


# =============================================================================
# validate_token()
# =============================================================================


class TestValidateTokenPreservesUnknownFields:
    @pytest.mark.asyncio
    async def test_validate_token_exposes_unknown_field_via_raw(self, auth_config):
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/validate").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "valid": True,
                        "user_id": "user_1",
                        "permissions": ["read"],
                        "risk_score": 0.02,  # unmodeled
                        "device_trusted": True,  # unmodeled
                    },
                )
            )
            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "tok")

        assert result.valid is True
        assert result.raw["risk_score"] == 0.02
        assert result.raw["device_trusted"] is True

    @pytest.mark.asyncio
    async def test_401_synthetic_response_has_empty_raw(self, auth_config):
        """Locally-synthesized responses (no server body) default raw to {}."""
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/validate").mock(
                return_value=httpx.Response(401, json={"error": "nope"})
            )
            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "tok")

        assert result.valid is False
        assert result.raw == {}


# =============================================================================
# validate_api_key()
# =============================================================================


class TestValidateApiKeyPreservesUnknownFields:
    @pytest.mark.asyncio
    async def test_api_key_exposes_unknown_field_via_raw(self, auth_config):
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/validate-api-key").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "valid": True,
                        "user_id": "svc_1",
                        "permissions": ["read"],
                        "key_scope": "service",  # unmodeled
                        "rate_limit_tier": "gold",  # unmodeled
                    },
                )
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "real_key")

        assert result.valid is True
        assert result.user_id == "svc_1"
        assert result.raw["key_scope"] == "service"
        assert result.raw["rate_limit_tier"] == "gold"


# =============================================================================
# introspect_token()
# =============================================================================


class TestIntrospectPreservesUnknownFields:
    @pytest.mark.asyncio
    async def test_introspect_exposes_unknown_field_via_raw(self, auth_config):
        with respx.mock:
            respx.post(f"{AUTH_URL}/token/introspect").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "active": True,
                        "sub": "user_1",
                        "permissions": ["read"],
                        "token_binding": "abc123",  # unmodeled, non-RFC-7662
                    },
                )
            )
            async with httpx.AsyncClient() as client:
                result = await introspect_token(client, auth_config, "tok")

        assert result.active is True
        assert result.raw["token_binding"] == "abc123"
