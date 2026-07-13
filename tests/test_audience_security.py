"""
Tests for the audience-verification fail-closed guard (AuthGuard).

Security finding (resource-service audit R-M2, 2026-07): when ``audience`` is
unset, PyJWT does NOT verify the token's ``aud`` claim
(``validate_token_local``: ``verify_aud = verify_aud and audience is not None``),
so a JWT minted for ANY mesh service is accepted as this service's caller. This
is a library-wide exposure — every consumer that constructs an AuthGuard without
an audience is affected.

The fix is deliberately NON-BREAKING on upgrade: it ALWAYS warns when audience
verification is disabled, but only RAISES ``ConfigurationError`` when the service
declares a production/staging environment (ambient ``ENVIRONMENT`` /
``AB0T_AUTH_ENVIRONMENT``) and ``AB0T_AUTH_DEBUG`` is not set. A dev/test/unset
environment is warn-only, so existing consumers keep working.

Negative-control law: the prod-refusal assertion fails if
``_enforce_audience_security`` is reverted to a no-op.
"""
import pytest

from ab0t_auth.errors import ConfigurationError
from ab0t_auth.guard import AuthGuard

AUD = "LOCAL:020caf72-d9cd-48b1-bbfc-2bc8c67f0cc5"
URL = "https://auth.service.ab0t.com"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # Ensure no ambient env leaks into the tests.
    for k in ("AB0T_AUTH_DEBUG", "AB0T_AUTH_BYPASS", "ENVIRONMENT", "AB0T_AUTH_ENVIRONMENT"):
        monkeypatch.delenv(k, raising=False)


class TestAudienceSecurity:
    @pytest.mark.parametrize("env", ["production", "prod", "staging"])
    def test_prodlike_without_audience_is_refused(self, monkeypatch, env):
        """The core control: no audience in a prod-like env => refuse to construct.
        RED if the guard is reverted (constructs wide open)."""
        monkeypatch.setenv("ENVIRONMENT", env)
        with pytest.raises(ConfigurationError) as ei:
            AuthGuard(auth_url=URL)  # audience defaults to None
        assert ei.value.details == {"config_key": "audience"}

    def test_prod_via_ab0t_env_var_also_refused(self, monkeypatch):
        """The AB0T_AUTH_ENVIRONMENT signal is honored the same as ENVIRONMENT."""
        monkeypatch.setenv("AB0T_AUTH_ENVIRONMENT", "production")
        with pytest.raises(ConfigurationError):
            AuthGuard(auth_url=URL)

    def test_prodlike_with_audience_constructs(self, monkeypatch):
        """Fix does not over-block: a configured audience constructs fine in prod."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        guard = AuthGuard(auth_url=URL, audience=AUD)
        assert guard.config.audience == AUD
        assert guard.config.verify_aud is True

    def test_prod_with_debug_is_allowed(self, monkeypatch):
        """DEBUG escape hatch: audience-less is permitted even in prod when
        AB0T_AUTH_DEBUG=true (dev-on-prod-config), matching the bypass pattern."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("AB0T_AUTH_DEBUG", "true")
        guard = AuthGuard(auth_url=URL)
        assert guard.config.audience is None

    def test_dev_without_audience_is_allowed_warn_only(self):
        """NON-BREAKING: a dev/unset environment is warn-only, never a hard error —
        so existing consumers are not broken by upgrading the library."""
        guard = AuthGuard(auth_url=URL)  # no ENVIRONMENT, no audience
        assert guard.config.audience is None

    def test_prodlike_with_multi_audience_tuple_constructs(self, monkeypatch):
        """A tuple audience (multi-aud service) also satisfies the guard in prod."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        guard = AuthGuard(auth_url=URL, audience=(AUD, "LOCAL:other"))
        assert guard.config.audience == (AUD, "LOCAL:other")
