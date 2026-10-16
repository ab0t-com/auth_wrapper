"""
The decision-cache TTL env vars work however the guard is built.

The 0.1.4 migration notes tell operators to switch a cache off (or restore the old windows) with env vars such as
AB0T_AUTH_API_KEY_CACHE_TTL=0. Most services build their guard with AuthGuard(auth_url=...) or create_config(...),
which never go through AuthSettings — so before this fix the documented opt-out was silently ignored there and the
cache stayed on. These tests pin: explicit config > env var > derived default, on every construction path, and a
typo in an opt-out fails loudly instead of leaving the cache on.
"""

from __future__ import annotations

import pytest

from ab0t_auth import AuthGuard
from ab0t_auth.cache import resolve_cache_ttls
from ab0t_auth.config import AuthConfig, create_config

AUTH_URL = "https://auth.example"

ENV_VARS = (
    "AB0T_AUTH_PERMISSION_CACHE_TTL",
    "AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL",
    "AB0T_AUTH_API_KEY_CACHE_TTL",
    "AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class TestEnvOptOutWorksOnEveryConstructionPath:
    def test_auth_url_guard_honours_api_key_opt_out(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "0")
        stats = AuthGuard(auth_url=AUTH_URL).cache_stats()
        assert stats["api_key"]["ttl"] == 0, "AB0T_AUTH_API_KEY_CACHE_TTL=0 must disable the API-key cache"

    def test_create_config_honours_permission_window(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CACHE_TTL", "30")
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL", "30")
        ttls = resolve_cache_ttls(create_config(AUTH_URL))
        assert (ttls.permission, ttls.permission_negative) == (30, 30)

    def test_plain_auth_config_honours_negative_api_key_opt_out(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL", "0")
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
        assert (ttls.api_key, ttls.api_key_negative) == (60, 0)


class TestPrecedence:
    def test_explicit_config_beats_env(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "0")
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, api_key_cache_ttl=45))
        assert ttls.api_key == 45

    def test_unset_env_keeps_the_defaults(self):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
        assert (ttls.permission, ttls.permission_negative, ttls.api_key, ttls.api_key_negative) == (15, 5, 60, 10)

    def test_blank_env_is_unset(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "  ")
        assert resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL)).api_key == 60

    def test_token_ttl_zero_still_disables_everything(self):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, token_cache_ttl=0))
        assert (ttls.permission, ttls.api_key) == (0, 0)


class TestTyposFailLoudly:
    @pytest.mark.parametrize("value", ["off", "1.5", "60s"])
    def test_unparsable_value_raises_naming_the_var(self, monkeypatch, value):
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", value)
        with pytest.raises(ValueError, match="AB0T_AUTH_API_KEY_CACHE_TTL"):
            resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))

    @pytest.mark.parametrize("value", ["-1", "301"])
    def test_out_of_range_value_raises(self, monkeypatch, value):
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CACHE_TTL", value)
        with pytest.raises(ValueError, match="AB0T_AUTH_PERMISSION_CACHE_TTL"):
            resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
