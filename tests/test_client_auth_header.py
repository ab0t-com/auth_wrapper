"""
Tests for Authorization header handling in client functions.

Tests that the client correctly handles tokens that may or may not
already include the "Bearer " prefix.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from ab0t_auth.client import (
    check_permission,
    get_user_permissions,
    validate_token,
)
from ab0t_auth.core import (
    AuthConfig,
    PermissionCheckRequest,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_config() -> AuthConfig:
    """Create a mock auth config."""
    return AuthConfig(
        auth_url="https://auth.example.com",
        audience="test-service",
    )


@pytest.fixture
def mock_client() -> AsyncMock:
    """Create a mock httpx AsyncClient."""
    return AsyncMock(spec=httpx.AsyncClient)


# =============================================================================
# Tests for Bearer Prefix Handling
# =============================================================================


class TestBearerPrefixHandling:
    """Tests that tokens with/without Bearer prefix are handled correctly."""

    @pytest.mark.asyncio
    async def test_check_permission_with_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """Token already has 'Bearer ' prefix - should NOT double it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"allowed": True, "reason": "direct"}
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
        request = PermissionCheckRequest(
            user_id="user_123",
            permission="resource.read",
            org_id="org_abc",
        )

        result = await check_permission(mock_client, mock_config, token, request)

        # Verify the Authorization header was NOT doubled
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        # Should be "Bearer eyJ..." NOT "Bearer Bearer eyJ..."
        assert auth_header == token
        assert not auth_header.startswith("Bearer Bearer")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_permission_without_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """Token without 'Bearer ' prefix - should add it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"allowed": True, "reason": "direct"}
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
        request = PermissionCheckRequest(
            user_id="user_123",
            permission="resource.read",
            org_id="org_abc",
        )

        result = await check_permission(mock_client, mock_config, token, request)

        # Verify the Authorization header was added
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        # Should be "Bearer eyJ..."
        assert auth_header == f"Bearer {token}"
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_validate_token_with_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """validate_token with Bearer prefix - should NOT double it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "user_id": "user_123",
            "email": "test@example.com",
            "org_id": "org_abc",
            "permissions": ["resource.read"],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

        result = await validate_token(mock_client, mock_config, token)

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        assert auth_header == token
        assert not auth_header.startswith("Bearer Bearer")

    @pytest.mark.asyncio
    async def test_validate_token_without_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """validate_token without Bearer prefix - should add it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "user_id": "user_123",
            "email": "test@example.com",
            "org_id": "org_abc",
            "permissions": ["resource.read"],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

        result = await validate_token(mock_client, mock_config, token)

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        assert auth_header == f"Bearer {token}"

    @pytest.mark.asyncio
    async def test_get_user_permissions_with_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """get_user_permissions with Bearer prefix - should NOT double it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "permissions": ["resource.read", "resource.write"],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response

        token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

        result = await get_user_permissions(mock_client, mock_config, token, "user_123")

        mock_client.get.assert_called_once()
        call_kwargs = mock_client.get.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        assert auth_header == token
        assert not auth_header.startswith("Bearer Bearer")
        assert result == ("resource.read", "resource.write")

    @pytest.mark.asyncio
    async def test_get_user_permissions_without_bearer_prefix(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """get_user_permissions without Bearer prefix - should add it."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "permissions": ["resource.read", "resource.write"],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response

        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

        result = await get_user_permissions(mock_client, mock_config, token, "user_123")

        mock_client.get.assert_called_once()
        call_kwargs = mock_client.get.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        assert auth_header == f"Bearer {token}"
        assert result == ("resource.read", "resource.write")


class TestBearerPrefixEdgeCases:
    """Edge cases for Bearer prefix handling."""

    @pytest.mark.asyncio
    async def test_bearer_lowercase(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """Token with lowercase 'bearer ' - should add proper 'Bearer '."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"allowed": True}
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        # lowercase bearer - should NOT be treated as already having prefix
        token = "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
        request = PermissionCheckRequest(
            user_id="user_123",
            permission="resource.read",
        )

        await check_permission(mock_client, mock_config, token, request)

        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        # Current implementation only checks "Bearer " (case-sensitive)
        # So "bearer " would get prefixed again
        assert auth_header == f"Bearer {token}"

    @pytest.mark.asyncio
    async def test_empty_token(
        self, mock_client: AsyncMock, mock_config: AuthConfig
    ):
        """Empty token - should still add Bearer prefix."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"allowed": False, "reason": "invalid"}
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        token = ""
        request = PermissionCheckRequest(
            user_id="user_123",
            permission="resource.read",
        )

        await check_permission(mock_client, mock_config, token, request)

        call_kwargs = mock_client.post.call_args[1]
        auth_header = call_kwargs["headers"]["Authorization"]

        assert auth_header == "Bearer "
