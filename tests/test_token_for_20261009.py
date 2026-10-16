"""
Tests for token_for — the P3 OAuth 2.0 Token Exchange (RFC 8693) helper.

token_for mints a token for a signed-in person at another mesh service: the
person's token is the subject_token, the SDK's own client credentials are the
client authentication, exactly one resource is requested, and NO actor_token is
sent. It is the Python twin of the Go SDK's TokenFor (person-present pattern).

These tests use respx to script the /auth/oauth/token endpoint and assert the
exact wire shape, the typed-error mapping, and the caching behaviour.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx

from ab0t_auth.cache import MeshTokenCache, create_mesh_token_cache_key
from ab0t_auth.core import AuthConfig, MeshToken
from ab0t_auth.errors import (
    AuthServiceError,
    ClientAuthError,
    ClientNotEnabledError,
    ConfigurationError,
    ConsentRequiredError,
    NoConnectionError,
    ReauthenticateRequired,
    ScopeNotAllowedError,
)
from ab0t_auth.token_for import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    new_pkce,
    normalize_scope,
    token_for,
)

TOKEN_URL = "https://auth.example.com/auth/oauth/token"


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(auth_url="https://auth.example.com")


@pytest.fixture
def subject() -> str:
    """A person's access token (readable exp, unverified)."""
    return jwt.encode({"sub": "user_123", "exp": int(time.time()) + 3600}, "k", algorithm="HS256")


def _form(route: respx.Route) -> dict[str, list[str]]:
    return parse_qs(route.calls.last.request.content.decode())


# =============================================================================
# Happy path — the target P3 wire shape
# =============================================================================


class TestHappyExchange:
    @pytest.mark.asyncio
    @respx.mock
    async def test_target_wire_shape_and_token(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "resource-token-abc",
                    "token_type": "Bearer",
                    "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                    "expires_in": 900,
                    "scope": "users.read",
                },
            )
        )
        async with httpx.AsyncClient() as client:
            tok = await token_for(
                client,
                config,
                "https://b.service.example",
                "users.read",
                subject,
                client_id="cid",
                client_secret="sec",
            )

        assert isinstance(tok, MeshToken)
        assert tok.access_token == "resource-token-abc"
        assert tok.token_type == "Bearer"
        assert tok.resource == "https://b.service.example"
        assert tok.scope == "users.read"
        assert tok.expires_at is not None and tok.expires_at > time.time()
        assert tok.authorization_header == "Bearer resource-token-abc"

        form = _form(route)
        assert form["grant_type"] == [GRANT_TYPE_TOKEN_EXCHANGE]
        assert form["subject_token"] == [subject]
        assert form["subject_token_type"] == [TOKEN_TYPE_ACCESS_TOKEN]
        assert form["resource"] == ["https://b.service.example"]
        assert form["scope"] == ["users.read"]
        # P3: NO actor_token
        assert "actor_token" not in form
        # client authenticates with HTTP Basic by default (RFC 6749 §2.3.1)
        assert route.calls.last.request.headers["Authorization"].startswith("Basic ")
        # no refresh token is ever exposed by token_for
        assert not hasattr(tok, "refresh_token")

    @pytest.mark.asyncio
    @respx.mock
    async def test_exactly_one_resource(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        async with httpx.AsyncClient() as client:
            await token_for(
                client,
                config,
                "https://b.example",
                "a",
                subject,
                client_id="cid",
                client_secret="sec",
            )
        body = route.calls.last.request.content.decode()
        assert body.count("resource=") == 1
        assert _form(route)["resource"] == ["https://b.example"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_client_secret_post_auth(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        async with httpx.AsyncClient() as client:
            await token_for(
                client,
                config,
                "https://b.example",
                "a",
                subject,
                client_id="cid",
                client_secret="sec",
                client_auth="post",
            )
        form = _form(route)
        assert form["client_id"] == ["cid"]
        assert form["client_secret"] == ["sec"]
        assert "Authorization" not in route.calls.last.request.headers

    @pytest.mark.asyncio
    @respx.mock
    async def test_granted_scope_falls_back_to_requested(self, config: AuthConfig, subject: str):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        async with httpx.AsyncClient() as client:
            tok = await token_for(
                client,
                config,
                "https://b.example",
                "users.read",
                subject,
                client_id="cid",
                client_secret="sec",
            )
        assert tok.scope == "users.read"

    @pytest.mark.asyncio
    @respx.mock
    async def test_2xx_without_access_token_is_unavailable(self, config: AuthConfig, subject: str):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"token_type": "Bearer"}))
        async with httpx.AsyncClient() as client:
            with pytest.raises(AuthServiceError):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "a",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                )


# =============================================================================
# Typed error mapping — classified by status + error + suberror only
# =============================================================================


class TestErrorMapping:
    @pytest.mark.parametrize(
        "status,body,expected",
        [
            (401, {"error": "invalid_client"}, ClientAuthError),
            (400, {"error": "invalid_client"}, ClientAuthError),
            (400, {"error": "unauthorized_client"}, ClientNotEnabledError),
            (400, {"error": "invalid_scope"}, ScopeNotAllowedError),
            (400, {"error": "invalid_target"}, NoConnectionError),
            (400, {"error": "invalid_request"}, ReauthenticateRequired),
            (400, {"error": "invalid_grant"}, ReauthenticateRequired),
            (503, {"detail": "Service temporarily unavailable"}, AuthServiceError),
            (500, {"error": "server_error"}, AuthServiceError),
            (429, {"error": "rate_limited"}, AuthServiceError),
        ],
    )
    @pytest.mark.asyncio
    @respx.mock
    async def test_wire_code_maps_to_exception(
        self, config: AuthConfig, subject: str, status, body, expected
    ):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(status, json=body))
        async with httpx.AsyncClient() as client:
            with pytest.raises(expected):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "a",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_consent_required_variant(self, config: AuthConfig, subject: str):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400, json={"error": "invalid_target", "suberror": "consent_required"}
            )
        )
        # metadata lookup for the authorization endpoint (best-effort)
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200, json={"authorization_endpoint": "https://auth.example.com/auth/authorize"}
            )
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(ConsentRequiredError) as ei:
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "users.read",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                )
        err = ei.value
        # consent is NOT a plain "no connection" (parity with Go errors.Is semantics)
        assert not isinstance(err, NoConnectionError)
        assert err.resource == "https://b.example"
        assert err.scope == "users.read"
        assert err.client_id == "cid"
        url = err.authorization_url("https://app.example/cb", state="xyz", code_challenge="chal")
        assert url.startswith("https://auth.example.com/auth/authorize?")
        assert "response_type=code" in url
        assert "prompt=consent" in url
        assert "code_challenge_method=S256" in url

    @pytest.mark.asyncio
    @respx.mock
    async def test_network_failure_is_unavailable(self, config: AuthConfig, subject: str):
        respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("boom"))
        async with httpx.AsyncClient() as client:
            with pytest.raises(AuthServiceError):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "a",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                )

    @pytest.mark.asyncio
    async def test_missing_client_credentials(self, config: AuthConfig, subject: str):
        async with httpx.AsyncClient() as client:
            with pytest.raises(ConfigurationError):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "a",
                    subject,
                    client_id="",
                    client_secret="sec",
                )

    @pytest.mark.asyncio
    async def test_empty_subject_is_reauthenticate(self, config: AuthConfig):
        async with httpx.AsyncClient() as client:
            with pytest.raises(ReauthenticateRequired):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "a",
                    "",
                    client_id="cid",
                    client_secret="sec",
                )

    @pytest.mark.asyncio
    async def test_empty_resource_rejected(self, config: AuthConfig, subject: str):
        async with httpx.AsyncClient() as client:
            with pytest.raises(ValueError):
                await token_for(
                    client,
                    config,
                    "",
                    "a",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                )


# =============================================================================
# Caching — hit, no error caching, expiry capping
# =============================================================================


class TestCaching:
    @pytest.mark.asyncio
    @respx.mock
    async def test_cache_hit_on_second_call(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "cached-tok", "expires_in": 900})
        )
        cache = MeshTokenCache()
        async with httpx.AsyncClient() as client:
            a = await token_for(
                client,
                config,
                "https://b.example",
                "s",
                subject,
                client_id="cid",
                client_secret="sec",
                cache=cache,
            )
            b = await token_for(
                client,
                config,
                "https://b.example",
                "s",
                subject,
                client_id="cid",
                client_secret="sec",
                cache=cache,
            )
        assert route.call_count == 1
        assert a.access_token == b.access_token == "cached-tok"

    @pytest.mark.asyncio
    @respx.mock
    async def test_errors_are_not_cached(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[
                httpx.Response(400, json={"error": "invalid_scope"}),
                httpx.Response(200, json={"access_token": "ok-tok", "expires_in": 900}),
            ]
        )
        cache = MeshTokenCache()
        async with httpx.AsyncClient() as client:
            with pytest.raises(ScopeNotAllowedError):
                await token_for(
                    client,
                    config,
                    "https://b.example",
                    "s",
                    subject,
                    client_id="cid",
                    client_secret="sec",
                    cache=cache,
                )
            tok = await token_for(
                client,
                config,
                "https://b.example",
                "s",
                subject,
                client_id="cid",
                client_secret="sec",
                cache=cache,
            )
        assert route.call_count == 2
        assert tok.access_token == "ok-tok"

    @pytest.mark.asyncio
    @respx.mock
    async def test_scope_order_shares_cache_entry(self, config: AuthConfig, subject: str):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        cache = MeshTokenCache()
        async with httpx.AsyncClient() as client:
            await token_for(
                client,
                config,
                "https://b.example",
                "a b",
                subject,
                client_id="cid",
                client_secret="sec",
                cache=cache,
            )
            await token_for(
                client,
                config,
                "https://b.example",
                "b a",
                subject,
                client_id="cid",
                client_secret="sec",
                cache=cache,
            )
        assert route.call_count == 1


class TestMeshTokenCacheUnit:
    def test_no_expiry_is_not_cached(self):
        cache = MeshTokenCache()
        key = create_mesh_token_cache_key("cid", "r", "s", "subj")
        cache.set(key, MeshToken(access_token="t", expires_at=None), None)
        assert cache.get(key) is None

    def test_capped_at_subject_expiry(self):
        cache = MeshTokenCache(margin=30.0)
        key = create_mesh_token_cache_key("cid", "r", "s", "subj")
        now = time.time()
        # token valid 1h, but the subject token expires in 10s -> entry must be stale by ~10s
        cache.set(key, MeshToken(access_token="t", expires_at=now + 3600), subject_exp=now + 10)
        assert cache.get(key) is not None
        entry = cache._cache[key]
        assert entry.fresh_until <= now + 10 + 0.01

    def test_margin_makes_near_expiry_stale(self):
        cache = MeshTokenCache(margin=30.0)
        key = create_mesh_token_cache_key("cid", "r", "s", "subj")
        now = time.time()
        # expires in 10s, margin 30s -> already stale, must not cache
        cache.set(key, MeshToken(access_token="t", expires_at=now + 10), None)
        assert cache.get(key) is None

    def test_subject_token_never_stored_verbatim(self):
        k1 = create_mesh_token_cache_key("cid", "r", "s", "super-secret-subject")
        assert "super-secret-subject" not in k1
        k2 = create_mesh_token_cache_key("cid", "r", "s", "a-different-subject")
        assert k1 != k2


class TestNormalizeScope:
    def test_sort_and_dedupe(self):
        assert normalize_scope("b a a") == "a b"
        assert normalize_scope("") == ""
        assert normalize_scope("one") == "one"
        assert normalize_scope("  a   b ") == "a b"


class TestPKCE:
    def test_new_pkce_shapes(self):
        verifier, challenge = new_pkce()
        assert 43 <= len(verifier) <= 128
        assert "=" not in verifier and "=" not in challenge
        # deterministic challenge from verifier
        import base64
        import hashlib

        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert challenge == expected
