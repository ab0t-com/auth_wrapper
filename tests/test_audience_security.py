"""
Tests for the audience-verification safety net (AuthGuard).

Security finding (resource-service audit R-M2, 2026-07): when ``audience`` is
unset, PyJWT does NOT verify the token's ``aud`` claim (``validate_token_local``:
``verify_aud = verify_aud and audience is not None``), so a JWT minted for ANY
mesh service is accepted as this service's caller. This is a library-wide
exposure — every consumer that constructs an AuthGuard without an audience is
affected — and, before this change, it happened silently.

The fix is BACKWARD-COMPATIBLE (additive):
  * ALWAYS: a loud warning is logged when audience verification is disabled.
    Construction still succeeds — the default behaviour is unchanged, so upgrading
    the library cannot break any existing consumer.
  * OPT-IN fail-closed: ``require_audience=True`` (constructor) or the env var
    ``AB0T_AUTH_REQUIRE_AUDIENCE=true`` turns the audience-less configuration into
    a hard ``ConfigurationError`` at construction. Off by default, mirroring how
    auth-bypass is opt-in rather than imposed.

Negative-control law: the opt-in-refusal assertions fail if
``_warn_or_require_audience`` is reverted to a no-op.
"""
import pytest

from ab0t_auth.errors import ConfigurationError
from ab0t_auth.guard import AuthGuard

AUD = "LOCAL:020caf72-d9cd-48b1-bbfc-2bc8c67f0cc5"
URL = "https://auth.service.ab0t.com"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AB0T_AUTH_DEBUG", "AB0T_AUTH_BYPASS", "AB0T_AUTH_REQUIRE_AUDIENCE"):
        monkeypatch.delenv(k, raising=False)


class TestAudienceBackwardCompatible:
    """The DEFAULT must not change: audience-less construction still succeeds."""

    def test_default_no_audience_still_constructs(self):
        """No audience + no opt-in => constructs (warn-only). This is the contract
        every existing consumer relies on; it must not regress."""
        guard = AuthGuard(auth_url=URL)  # audience defaults to None
        assert guard.config.audience is None

    def test_default_with_audience_constructs(self):
        guard = AuthGuard(auth_url=URL, audience=AUD)
        assert guard.config.audience == AUD
        assert guard.config.verify_aud is True


class TestAudienceOptInStrict:
    """require_audience is an OPT-IN fail-closed knob."""

    def test_require_audience_kwarg_without_audience_raises(self):
        """The core control: opt-in strict + no audience => refuse to construct.
        RED if the guard is reverted to a no-op."""
        with pytest.raises(ConfigurationError) as ei:
            AuthGuard(auth_url=URL, require_audience=True)
        assert ei.value.details == {"config_key": "audience"}

    def test_require_audience_env_without_audience_raises(self, monkeypatch):
        """The AB0T_AUTH_REQUIRE_AUDIENCE env var is an equivalent opt-in signal."""
        monkeypatch.setenv("AB0T_AUTH_REQUIRE_AUDIENCE", "true")
        with pytest.raises(ConfigurationError):
            AuthGuard(auth_url=URL)

    def test_require_audience_with_audience_constructs(self):
        """Opt-in strict does not over-block once an audience is configured."""
        guard = AuthGuard(auth_url=URL, audience=AUD, require_audience=True)
        assert guard.config.audience == AUD

    def test_require_audience_with_tuple_audience_constructs(self):
        """A tuple audience (multi-aud service) satisfies the strict check."""
        guard = AuthGuard(auth_url=URL, audience=(AUD, "LOCAL:other"), require_audience=True)
        assert guard.config.audience == (AUD, "LOCAL:other")

    def test_require_audience_env_false_does_not_opt_in(self, monkeypatch):
        """Only an explicit 'true' opts in; other values leave the default (no raise)."""
        monkeypatch.setenv("AB0T_AUTH_REQUIRE_AUDIENCE", "false")
        guard = AuthGuard(auth_url=URL)  # not opted in
        assert guard.config.audience is None
