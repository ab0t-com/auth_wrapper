"""
Tests for AuthGuard.on_revocation_event (opt-in revocation propagation).

These verify the additive convenience mapper wires revocation events to the
existing invalidate_* methods and is safe on malformed/unrecognised input.
"""

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
