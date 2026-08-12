"""
Tests for AuthGuard.on_revocation_event (opt-in revocation propagation).

These verify the additive convenience mapper wires revocation events to the
existing invalidate_* methods and is safe on malformed/unrecognised input.
"""

import dataclasses
from types import MappingProxyType

import pytest

from ab0t_auth.core import AuthenticatedUser, TokenClaims
from ab0t_auth.guard import AuthGuard, RevocationResult


def _prime_token(guard: AuthGuard, token: str, user: AuthenticatedUser, claims: TokenClaims) -> None:
    guard._token_cache.set(token, user, claims)


def _prime_permissions(guard: AuthGuard, user_id: str, permissions: tuple[str, ...]) -> None:
    for perm in permissions:
        guard._permission_cache.set(user_id, perm, True)


class TestRevocationResult:
    """Tests for the RevocationResult summary type."""

    def test_handled_false_when_nothing_invalidated(self):
        result = RevocationResult(event_type="unknown")
        assert result.handled is False

    def test_handled_true_on_token(self):
        assert RevocationResult(event_type="token.revoked", token_invalidated=True).handled

    def test_handled_true_on_permissions(self):
        assert RevocationResult(event_type="permission.revoked", permissions_invalidated=2).handled

    def test_handled_true_on_clear(self):
        assert RevocationResult(event_type="caches.clear", caches_cleared=True).handled


class TestOnRevocationEvent:
    """Tests for AuthGuard.on_revocation_event."""

    def test_token_revoked_invalidates_token_cache(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        _prime_token(auth_guard, valid_token, test_user, test_claims)
        assert auth_guard._token_cache.get(valid_token) is not None

        result = auth_guard.on_revocation_event(
            {"type": "token.revoked", "token": valid_token}
        )

        assert result.token_invalidated is True
        assert result.handled is True
        assert result.event_type == "token.revoked"
        assert auth_guard._token_cache.get(valid_token) is None

    def test_apikey_revoked_by_token_field(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        _prime_token(auth_guard, valid_token, test_user, test_claims)

        result = auth_guard.on_revocation_event(
            {"type": "apikey.revoked", "access_token": valid_token}
        )

        assert result.token_invalidated is True
        assert auth_guard._token_cache.get(valid_token) is None

    def test_permission_revoked_invalidates_user_permissions(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read", "users:write"))

        result = auth_guard.on_revocation_event(
            {"type": "permission.revoked", "user_id": test_user.user_id}
        )

        assert result.permissions_invalidated == 2
        assert result.handled is True
        assert auth_guard._permission_cache.get(test_user.user_id, "users:read") is None

    def test_user_suspended_by_sub_alias(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event(
            {"type": "user.suspended", "sub": test_user.user_id}
        )

        assert result.permissions_invalidated == 1
        assert result.token_invalidated is False

    def test_event_with_token_and_user(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        _prime_token(auth_guard, valid_token, test_user, test_claims)
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event(
            {
                "type": "session.revoked",
                "token": valid_token,
                "user_id": test_user.user_id,
            }
        )

        assert result.token_invalidated is True
        assert result.permissions_invalidated == 1

    def test_clear_all_event_flushes_caches(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        _prime_token(auth_guard, valid_token, test_user, test_claims)
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event({"type": "caches.clear"})

        assert result.caches_cleared is True
        assert result.handled is True
        assert auth_guard._token_cache.get(valid_token) is None
        assert auth_guard._permission_cache.get(test_user.user_id, "users:read") is None

    def test_all_flag_flushes_caches(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event({"type": "org.changed", "all": True})

        assert result.caches_cleared is True

    def test_unrecognised_event_is_noop(self, auth_guard: AuthGuard):
        result = auth_guard.on_revocation_event({"type": "something.unrelated"})

        assert result.handled is False
        assert result.token_invalidated is False
        assert result.permissions_invalidated == 0
        assert result.caches_cleared is False

    def test_empty_event_does_not_raise(self, auth_guard: AuthGuard):
        result = auth_guard.on_revocation_event({})

        assert result.event_type is None
        assert result.handled is False

    def test_non_string_fields_ignored(self, auth_guard: AuthGuard):
        # user_id given as a non-string must not be dispatched
        result = auth_guard.on_revocation_event({"type": "permission.revoked", "user_id": 123})

        assert result.handled is False

    def test_token_not_in_cache_reports_not_invalidated(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
    ):
        # Nothing primed — invalidate_token returns False, event still safe.
        result = auth_guard.on_revocation_event(
            {"type": "token.revoked", "token": valid_token}
        )

        assert result.token_invalidated is False
        assert result.handled is False

    def test_event_field_alias(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        # "event" used instead of "type"
        result = auth_guard.on_revocation_event(
            {"event": "permission.revoked", "userId": test_user.user_id}
        )

        assert result.event_type == "permission.revoked"
        assert result.permissions_invalidated == 1


class TestOnRevocationEventContract:
    """Contract / regression guards for the opt-in additive behaviour."""

    def test_result_is_immutable(self):
        result = RevocationResult(event_type="token.revoked", token_invalidated=True)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.token_invalidated = False  # type: ignore[misc]

    def test_does_not_require_initialization_or_network(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        # A brand-new guard is not initialized and has no HTTP/JWKS client.
        assert auth_guard.is_initialized is False
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event(
            {"type": "permission.revoked", "user_id": test_user.user_id}
        )

        # No network I/O was needed and state is untouched aside from caches.
        assert result.permissions_invalidated == 1
        assert auth_guard.is_initialized is False
        assert auth_guard._http_client is None

    def test_idempotent_second_call_is_safe(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))
        event = {"type": "permission.revoked", "user_id": test_user.user_id}

        first = auth_guard.on_revocation_event(event)
        second = auth_guard.on_revocation_event(event)

        assert first.permissions_invalidated == 1
        # Already gone — second call invalidates nothing but does not raise.
        assert second.permissions_invalidated == 0
        assert second.handled is False

    def test_accepts_any_mapping_not_just_dict(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))
        event = MappingProxyType(
            {"type": "permission.revoked", "user_id": test_user.user_id}
        )

        result = auth_guard.on_revocation_event(event)

        assert result.permissions_invalidated == 1

    @pytest.mark.parametrize("clear_type", ["caches.clear", "cache.clear", "auth.reset"])
    def test_all_clear_all_aliases(
        self,
        auth_guard: AuthGuard,
        test_user: AuthenticatedUser,
        clear_type: str,
    ):
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event({"type": clear_type})

        assert result.caches_cleared is True

    def test_clear_all_takes_precedence_over_individual_fields(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        _prime_token(auth_guard, valid_token, test_user, test_claims)
        _prime_permissions(auth_guard, test_user.user_id, ("users:read",))

        result = auth_guard.on_revocation_event(
            {"type": "auth.reset", "token": valid_token, "user_id": test_user.user_id}
        )

        # Global flush wins; per-field counters stay at their defaults.
        assert result.caches_cleared is True
        assert result.token_invalidated is False
        assert result.permissions_invalidated == 0
        assert auth_guard._token_cache.get(valid_token) is None

    def test_empty_string_fields_are_ignored(self, auth_guard: AuthGuard):
        result = auth_guard.on_revocation_event(
            {"type": "permission.revoked", "user_id": "", "token": ""}
        )

        assert result.handled is False

    def test_existing_invalidate_methods_unchanged(
        self,
        auth_guard: AuthGuard,
        valid_token: str,
        test_user: AuthenticatedUser,
        test_claims: TokenClaims,
    ):
        # The mapper must not change the behaviour of the primitives it calls.
        _prime_token(auth_guard, valid_token, test_user, test_claims)
        assert auth_guard.invalidate_token(valid_token) is True
        assert auth_guard.invalidate_token(valid_token) is False

        _prime_permissions(auth_guard, test_user.user_id, ("a", "b", "c"))
        assert auth_guard.invalidate_user_permissions(test_user.user_id) == 3
