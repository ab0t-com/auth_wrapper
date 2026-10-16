"""PermissionCache is keyed by CREDENTIAL + org, never by user id alone (0.1.2).

RED on 0.1.1: test_owner_allow_not_served_to_narrow_key, test_narrow_key_deny_does_not_lock_out_owner,
test_other_org_not_served, test_no_credential_is_never_cached, test_legacy_user_id_reader_misses.
"""

import asyncio

import pytest

from ab0t_auth import permissions as perms_mod
from ab0t_auth.cache import PermissionCache
from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod, PermissionCheckResponse

OWNER = "user-rita"
ORG = "org-r"


def _user(method=AuthMethod.JWT, org=ORG, perms=()):
    return AuthenticatedUser(
        user_id=OWNER,
        email="r@example.com",
        org_id=org,
        permissions=tuple(perms),
        auth_method=method,
    )


class _FakeAuth:
    """Stands in for auth /permissions/check: answers per CREDENTIAL (the fixed auth) and counts calls."""

    def __init__(self, answers):
        self.answers = answers  # {credential_string: {permission: bool}}
        self.calls = []

    async def __call__(self, client, config, token, request, *, api_key=None):
        cred = (token or "").replace("Bearer ", "") or api_key
        self.calls.append((cred, request.permission, request.org_id))
        allowed = self.answers.get(cred, {}).get(request.permission, False)
        return PermissionCheckResponse(
            allowed=allowed, permission=request.permission, user_id=request.user_id
        )


@pytest.fixture
def fake(monkeypatch):
    f = _FakeAuth(
        {
            "owner.jwt": {"billing.write": True, "billing.read": True},
            "ab0t_sk_narrow": {"billing.read": True},
        }
    )
    monkeypatch.setattr(perms_mod, "check_permission_remote", f)
    return f


def _verify(user, perm, *, token="", api_key=None, cache):
    cfg = AuthConfig(auth_url="http://auth.local")
    return asyncio.run(
        perms_mod.verify_permission(None, cfg, token, user, perm, cache=cache, api_key=api_key)
    )


def test_owner_allow_not_served_to_narrow_key(fake):
    cache = PermissionCache()
    assert _verify(_user(), "billing.write", token="Bearer owner.jwt", cache=cache).allowed
    r = _verify(
        _user(AuthMethod.API_KEY, perms=("billing.read",)),
        "billing.write",
        api_key="ab0t_sk_narrow",
        cache=cache,
    )
    assert (
        not r.allowed
    ), "the owner's cached allow was served to the narrow key (cache leak)"
    assert (
        len(fake.calls) == 2
    ), "the narrow key must be asked about itself, not answered from the owner's entry"


def test_narrow_key_deny_does_not_lock_out_owner(fake):
    cache = PermissionCache()
    assert not _verify(
        _user(AuthMethod.API_KEY), "billing.write", api_key="ab0t_sk_narrow", cache=cache
    ).allowed
    assert _verify(
        _user(), "billing.write", token="Bearer owner.jwt", cache=cache
    ).allowed, "the narrow key's cached deny locked the owner out"


def test_same_credential_is_cached(fake):
    cache = PermissionCache()
    for _ in range(3):
        assert _verify(_user(), "billing.write", token="Bearer owner.jwt", cache=cache).allowed
    assert (
        len(fake.calls) == 1
    ), "a repeat check by the SAME credential in the same org must still hit the cache"


def test_other_org_not_served(fake):
    cache = PermissionCache()
    assert _verify(
        _user(org="org-r"), "billing.write", token="Bearer owner.jwt", cache=cache
    ).allowed
    _verify(_user(org="org-other"), "billing.write", token="Bearer owner.jwt", cache=cache)
    assert (
        len(fake.calls) == 2 and fake.calls[1][2] == "org-other"
    ), "an answer for org R was reused for another org"


def test_no_credential_is_never_cached(fake):
    cache = PermissionCache()
    _verify(_user(), "billing.write", token="", api_key=None, cache=cache)
    assert len(cache._cache) == 0, "a result that cannot be attributed to a credential was cached"


def test_legacy_user_id_reader_misses(fake):
    """Service code that reads the cache by user id only (e.g. payment app/auth.py helpers) must never get an answer."""
    cache = PermissionCache()
    assert _verify(_user(), "billing.write", token="Bearer owner.jwt", cache=cache).allowed
    assert cache.get(OWNER, "billing.write") is None


def test_invalidate_user_clears_every_credential(fake):
    cache = PermissionCache()
    _verify(_user(), "billing.write", token="Bearer owner.jwt", cache=cache)
    _verify(_user(AuthMethod.API_KEY), "billing.read", api_key="ab0t_sk_narrow", cache=cache)
    assert cache.invalidate_user(OWNER) == 2
    assert len(cache._cache) == 0


def test_cache_never_stores_the_raw_credential(fake):
    cache = PermissionCache()
    _verify(_user(AuthMethod.API_KEY), "billing.read", api_key="ab0t_sk_narrow", cache=cache)
    _verify(_user(), "billing.write", token="Bearer owner.jwt", cache=cache)
    blob = " ".join(repr(k) for k in cache._cache.keys())  # keys are tuples since 0.1.5 (P-2)
    assert blob, "no cache entries were written — this assertion would be vacuous"
    assert "ab0t_sk_narrow" not in blob and "owner.jwt" not in blob
