"""
token_for — a token to act for a signed-in person at another mesh service (P3).

An app on the ab0t mesh that needs to call another service FOR a signed-in
person performs an OAuth 2.0 Token Exchange (RFC 8693): the person's token is
the ``subject_token``, the app proves who it is with its OWN client credentials,
exactly one ``resource`` is requested, and NO ``actor_token`` is sent — the
authenticated client IS the actor. ``token_for`` does that in one call:

    tok = await token_for(
        client, config,
        "https://b.service.example", "b.documents.read", person_token,
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
    )
    headers = {"Authorization": tok.authorization_header}

It is the Python twin of the Go SDK's ``TokenFor`` (person-present pattern).

- **One resource per token.** Send it only to the resource it was requested for.
  Never forward a token you received on to another service — get your own.
- **Cached** (pass a ``MeshTokenCache``): served from memory until 30 s before it
  expires and never past the person's own token expiry; keyed by the client, the
  resource, the sorted scope set and a hash of the person's token — a new sign-in
  is a new key. Errors are never cached.
- **No refresh tokens.** Renewing is simply calling again.
- **Only client credentials reach the token endpoint** (HTTP Basic by default, or
  ``client_secret_post``). The service API key is never sent here.

Errors are classified from the HTTP status and the OAuth ``error`` / ``suberror``
members only (never the free-text ``error_description``) onto the typed
exceptions in ``errors.py``.
"""

from __future__ import annotations

import time
from typing import Any, Literal

import httpx
import jwt

from ab0t_auth.cache import MeshTokenCache, create_mesh_token_cache_key
from ab0t_auth.core import AuthConfig, MeshToken
from ab0t_auth.errors import (
    AuthServiceError,
    ClientAuthError,
    ClientNotEnabledError,
    ConfigurationError,
    ConsentRequiredError,
    MeshTokenError,
    NoConnectionError,
    ReauthenticateRequired,
    ScopeNotAllowedError,
)

# RFC 8693 / RFC 8707 wire constants (match the Go SDK and the auth service).
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_ENDPOINT_PATH = "/auth/oauth/token"
# A cached token is replaced this long before it expires (matches the Go SDK and
# the browser SDK 0.4.1 early-refresh rule).
TOKEN_REFRESH_MARGIN_SECONDS = 30.0


# =============================================================================
# Helpers (pure)
# =============================================================================


def normalize_scope(scope: str) -> str:
    """Sort and de-duplicate a space-delimited scope.

    RFC 6749 §3.3: scope is an unordered set, so ``"a b"`` and ``"b a"`` share a
    cache entry. Pure function.
    """
    fields = scope.split()
    if len(fields) <= 1:
        return fields[0] if fields else ""
    return " ".join(sorted(set(fields)))


def new_pkce() -> tuple[str, str]:
    """Return a fresh RFC 7636 ``(code_verifier, code_challenge)`` pair.

    The verifier is 43 URL-safe chars (256 bits of randomness); the challenge is
    its S256 hash. Keep the verifier for the code exchange at your redirect URI.
    Pair with ``ConsentRequiredError.authorization_url``.
    """
    import base64
    import hashlib
    import secrets

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


def _unverified_subject_exp(subject_token: str) -> float | None:
    """Read ``exp`` from the subject token WITHOUT verifying it.

    Used only to stop a cached derived token outliving the person's own token —
    never for an authorization decision. None when unreadable.
    """
    try:
        payload = jwt.decode(subject_token, options={"verify_signature": False})
    except Exception:
        return None
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp > 0:
        return float(exp)
    return None


def _expires_at(expires_in: Any) -> float | None:
    """Convert an ``expires_in`` (seconds) into an absolute epoch, or None."""
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        return time.time() + float(expires_in)
    return None


# =============================================================================
# token_for
# =============================================================================


async def token_for(
    client: httpx.AsyncClient,
    config: AuthConfig,
    resource: str,
    scope: str,
    subject_token: str,
    *,
    client_id: str,
    client_secret: str,
    client_auth: Literal["basic", "post"] = "basic",
    cache: MeshTokenCache | None = None,
) -> MeshToken:
    """Mint a token to act for a signed-in person at ``resource`` (P3 exchange).

    Posts the RFC 8693 token-exchange request to ``/auth/oauth/token`` with the
    person's ``subject_token``, the app's own client credentials as client
    authentication (HTTP Basic by default, or ``client_auth="post"`` for
    ``client_secret_post``), exactly one ``resource`` (RFC 8707), the requested
    ``scope``, and NO ``actor_token``.

    Returns a :class:`MeshToken` for that one resource. Raises a typed
    :class:`MeshTokenError` (or :class:`AuthServiceError` when a dependency is
    unavailable) classified from the wire. Pass a :class:`MeshTokenCache` to reuse
    a token until shortly before it expires.

    Args mirror the Go SDK's ``TokenFor(ctx, resource, scope, session)`` as
    closely as Python idiom allows; the person's token is passed directly rather
    than through a Session object.
    """
    if not client_id or not client_secret:
        raise ConfigurationError(
            "token_for requires client_id and client_secret",
            config_key="client_credentials",
        )
    if not subject_token:
        raise ReauthenticateRequired("The person's session returned no token")
    if not resource:
        raise ValueError("token_for requires exactly one resource")

    scope = normalize_scope(scope)

    key: str | None = None
    if cache is not None:
        key = create_mesh_token_cache_key(client_id, resource, scope, subject_token)
        hit = cache.get(key)
        if hit is not None:
            return hit

    form: dict[str, str] = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        "resource": resource,
    }
    if scope:
        form["scope"] = scope

    request_auth: httpx.Auth | None = None
    if client_auth == "post":
        form["client_id"] = client_id
        form["client_secret"] = client_secret
    else:
        request_auth = httpx.BasicAuth(client_id, client_secret)

    url = f"{config.auth_url}{TOKEN_ENDPOINT_PATH}"
    headers = {"User-Agent": _user_agent()}
    post_kwargs: dict[str, Any] = {"data": form, "headers": headers}
    if request_auth is not None:
        post_kwargs["auth"] = request_auth

    try:
        response = await client.post(url, **post_kwargs)
    except httpx.RequestError as e:
        # Transport failure: no answer was obtained — unavailable, never allowed.
        raise AuthServiceError(
            "Auth service unavailable",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e

    if response.status_code >= 400:
        raise await _classify_token_error(client, config, response, resource, scope, client_id)

    data = _json_or_empty(response)
    access_token = data.get("access_token")
    if not access_token:
        # A 2xx without an access_token is not a usable answer.
        raise AuthServiceError(
            "Token endpoint returned no access_token",
            service_url=config.auth_url,
        )

    token = MeshToken(
        access_token=access_token,
        token_type=data.get("token_type") or "Bearer",
        resource=resource,
        scope=data.get("scope") or scope,
        expires_at=_expires_at(data.get("expires_in")),
    )

    if cache is not None and key is not None and token.expires_at is not None:
        cache.set(key, token, _unverified_subject_exp(subject_token))

    return token


# =============================================================================
# Internal
# =============================================================================


def _user_agent() -> str:
    """``ab0t-auth/<version>`` — the token the auth service's SDK metric parses."""
    try:
        from ab0t_auth import __version__

        return f"ab0t-auth/{__version__}"
    except Exception:  # pragma: no cover - version import never fails in practice
        return "ab0t-auth"


def _json_or_empty(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


async def _classify_token_error(
    client: httpx.AsyncClient,
    config: AuthConfig,
    response: httpx.Response,
    resource: str,
    scope: str,
    client_id: str,
) -> Exception:
    """Map a non-2xx token-endpoint response onto a typed exception.

    Classifies by HTTP status and the OAuth ``error`` / ``suberror`` members
    only — never ``error_description``. 5xx / 429 / infra → AuthServiceError.
    """
    status = response.status_code
    if status >= 500 or status == 429:
        return AuthServiceError("Auth service unavailable", service_url=config.auth_url)

    body = _json_or_empty(response)
    error = body.get("error")
    suberror = body.get("suberror")
    request_id = response.headers.get("x-request-id") or response.headers.get("X-Request-ID")
    common: dict[str, Any] = {
        "wire_error": error if isinstance(error, str) else None,
        "status": status,
        "resource": resource,
        "scope": scope,
        "request_id": request_id,
    }

    if error == "invalid_client":
        return ClientAuthError(**common)
    if error == "unauthorized_client":
        return ClientNotEnabledError(**common)
    if error == "invalid_scope":
        return ScopeNotAllowedError(**common)
    if error == "invalid_target":
        if suberror == "consent_required":
            endpoint = await _authorization_endpoint(client, config)
            return ConsentRequiredError(
                client_id=client_id, authorization_endpoint=endpoint, **common
            )
        return NoConnectionError(**common)
    if error in ("invalid_request", "invalid_grant"):
        return ReauthenticateRequired(**common)

    # An unrecognised non-infra error: surface it, but never as "allowed".
    return MeshTokenError("Token exchange failed", **common)


async def _authorization_endpoint(client: httpx.AsyncClient, config: AuthConfig) -> str:
    """Best-effort ``authorization_endpoint`` from the RFC 8414 metadata.

    Falls back to ``<auth_url>/auth/authorize`` when the metadata cannot be read.
    The token endpoint never hands out a URL (so a ConsentRequiredError must
    build one from published metadata).
    """
    fallback = f"{config.auth_url}/auth/authorize"
    try:
        md = await client.get(f"{config.auth_url}/.well-known/oauth-authorization-server")
        if md.status_code < 400:
            doc = md.json()
            if isinstance(doc, dict) and doc.get("authorization_endpoint"):
                return str(doc["authorization_endpoint"])
    except Exception:
        pass
    return fallback
