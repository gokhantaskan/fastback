"""Tests for app/admin/auth.py - SQLAdmin authentication."""

from unittest.mock import MagicMock

import pytest

from app.admin.auth import AdminAuth
from app.core.settings import get_settings


@pytest.fixture
def admin_auth():
    """Create AdminAuth instance."""
    return AdminAuth()


@pytest.fixture
def mock_request():
    """Create a mock Starlette request with session."""
    request = MagicMock()
    request.session = {}
    return request


@pytest.mark.asyncio
async def test_admin_login_success(admin_auth, mock_request):
    """Test AdminAuth.login() with valid credentials returns True."""
    # Use real settings from environment
    settings = get_settings()

    async def mock_form():
        return {
            "username": settings.admin_username,
            "password": settings.admin_password,
        }

    mock_request.form = mock_form

    result = await admin_auth.login(mock_request)

    assert result is True
    assert mock_request.session["admin_user"] == settings.admin_username


@pytest.mark.asyncio
async def test_admin_login_with_email_field(admin_auth, mock_request):
    """Test AdminAuth.login() falls back to email field."""
    settings = get_settings()

    async def mock_form():
        return {"email": settings.admin_username, "password": settings.admin_password}

    mock_request.form = mock_form

    result = await admin_auth.login(mock_request)

    assert result is True
    assert mock_request.session["admin_user"] == settings.admin_username


@pytest.mark.asyncio
async def test_admin_login_invalid_username(admin_auth, mock_request):
    """Test AdminAuth.login() with invalid username returns False."""
    settings = get_settings()

    async def mock_form():
        return {"username": "wrong-user-name", "password": settings.admin_password}

    mock_request.form = mock_form

    result = await admin_auth.login(mock_request)

    assert result is False
    assert "admin_user" not in mock_request.session


@pytest.mark.asyncio
async def test_admin_login_invalid_password(admin_auth, mock_request):
    """Test AdminAuth.login() with invalid password returns False."""
    settings = get_settings()

    async def mock_form():
        return {"username": settings.admin_username, "password": "wrong-password"}

    mock_request.form = mock_form

    result = await admin_auth.login(mock_request)

    assert result is False
    assert "admin_user" not in mock_request.session


@pytest.mark.asyncio
async def test_admin_logout(admin_auth, mock_request):
    """Test AdminAuth.logout() clears session and returns True."""
    mock_request.session["admin_user"] = "admin"
    mock_request.session["other_data"] = "test"

    result = await admin_auth.logout(mock_request)

    assert result is True
    assert mock_request.session == {}


@pytest.mark.asyncio
async def test_admin_authenticate_with_session(admin_auth, mock_request):
    """Test AdminAuth.authenticate() returns True when admin_user in session."""
    mock_request.session["admin_user"] = "admin"

    result = await admin_auth.authenticate(mock_request)

    assert result is True


@pytest.mark.asyncio
async def test_admin_authenticate_without_session(admin_auth, mock_request):
    """Test AdminAuth.authenticate() returns False when no admin_user in session."""
    result = await admin_auth.authenticate(mock_request)

    assert result is False


@pytest.mark.asyncio
async def test_admin_login_strips_whitespace(admin_auth, mock_request):
    """Test AdminAuth.login() strips whitespace from username."""
    settings = get_settings()

    async def mock_form():
        return {
            "username": f"  {settings.admin_username}  ",
            "password": settings.admin_password,
        }

    mock_request.form = mock_form

    result = await admin_auth.login(mock_request)

    assert result is True
