"""Tests for app/core/auth.py - get_current_user dependency."""

from unittest.mock import MagicMock

import pytest

from app.core.auth import get_current_user
from app.core.exceptions import (
    AppException,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionCookieError,
    UserInactiveError,
    UserNotFoundError,
)
from app.services.firebase_auth import (
    FirebaseAuthService,
    TokenClaims,
)


def create_mock_firebase_service():
    """Create a mock FirebaseAuthService."""
    return MagicMock(spec=FirebaseAuthService)


def test_get_current_user_valid_bearer_token(session, test_user):
    """Test get_current_user with valid bearer token returns user."""
    mock_credentials = MagicMock()
    mock_credentials.credentials = "valid-token"
    mock_request = MagicMock()
    mock_request.cookies = {}

    mock_service = create_mock_firebase_service()
    mock_service.verify_id_token.return_value = TokenClaims(uid=test_user.firebase_uid)

    result = get_current_user(mock_request, session, mock_service, mock_credentials)

    assert result.id == test_user.id
    assert result.email == test_user.email
    mock_service.verify_id_token.assert_called_once_with("valid-token")


def test_get_current_user_invalid_bearer_token(session):
    """Test get_current_user with invalid bearer token raises InvalidTokenError."""
    mock_credentials = MagicMock()
    mock_credentials.credentials = "invalid-token"
    mock_request = MagicMock()
    mock_request.cookies = {}

    mock_service = create_mock_firebase_service()
    mock_service.verify_id_token.side_effect = AppException("Invalid token")

    with pytest.raises(InvalidTokenError) as exc_info:
        get_current_user(mock_request, session, mock_service, mock_credentials)

    assert exc_info.value.status_code == 401


def test_get_current_user_not_found(session):
    """Test get_current_user with valid token but user not in DB raises UserNotFoundError."""  # noqa: E501
    mock_credentials = MagicMock()
    mock_credentials.credentials = "valid-token"
    mock_request = MagicMock()
    mock_request.cookies = {}

    mock_service = create_mock_firebase_service()
    mock_service.verify_id_token.return_value = TokenClaims(uid="non-existent-uid")

    with pytest.raises(UserNotFoundError) as exc_info:
        get_current_user(mock_request, session, mock_service, mock_credentials)

    assert exc_info.value.status_code == 404


def test_get_current_user_inactive(session, inactive_user):
    """Test get_current_user with inactive user raises UserInactiveError."""
    mock_credentials = MagicMock()
    mock_credentials.credentials = "valid-token"
    mock_request = MagicMock()
    mock_request.cookies = {}

    mock_service = create_mock_firebase_service()
    mock_service.verify_id_token.return_value = TokenClaims(
        uid=inactive_user.firebase_uid
    )

    with pytest.raises(UserInactiveError) as exc_info:
        get_current_user(mock_request, session, mock_service, mock_credentials)

    assert exc_info.value.status_code == 403


def test_get_current_user_session_cookie_valid(session, test_user):
    """Test get_current_user with valid session cookie returns user."""
    mock_request = MagicMock()
    mock_request.cookies = {"session": "valid-session-cookie"}

    mock_service = create_mock_firebase_service()
    mock_service.verify_session_cookie.return_value = TokenClaims(
        uid=test_user.firebase_uid
    )

    result = get_current_user(mock_request, session, mock_service, None)

    assert result.id == test_user.id
    assert result.email == test_user.email
    mock_service.verify_session_cookie.assert_called_once_with(
        "valid-session-cookie", check_revoked=True
    )


def test_get_current_user_session_cookie_invalid(session):
    """Test get_current_user with invalid session cookie raises InvalidTokenError."""
    mock_request = MagicMock()
    mock_request.cookies = {"session": "invalid-session-cookie"}

    mock_service = create_mock_firebase_service()
    mock_service.verify_session_cookie.side_effect = SessionCookieError(
        "Invalid cookie"
    )

    with pytest.raises(InvalidTokenError) as exc_info:
        get_current_user(mock_request, session, mock_service, None)

    assert exc_info.value.status_code == 401


def test_get_current_user_not_authenticated(session):
    """Test get_current_user without cookie or bearer raises InvalidCredentialsError."""
    mock_request = MagicMock()
    mock_request.cookies = {}

    mock_service = create_mock_firebase_service()

    with pytest.raises(InvalidCredentialsError) as exc_info:
        get_current_user(mock_request, session, mock_service, None)

    assert exc_info.value.status_code == 401
    assert "Not authenticated" in exc_info.value.message


def test_get_current_user_session_cookie_priority_over_bearer(session, test_user):
    """Test that session cookie takes priority over bearer token."""
    mock_credentials = MagicMock()
    mock_credentials.credentials = "bearer-token"
    mock_request = MagicMock()
    mock_request.cookies = {"session": "session-cookie"}

    mock_service = create_mock_firebase_service()
    mock_service.verify_session_cookie.return_value = TokenClaims(
        uid=test_user.firebase_uid
    )

    result = get_current_user(mock_request, session, mock_service, mock_credentials)

    assert result.id == test_user.id
    # Session cookie should be verified, not the bearer token
    mock_service.verify_session_cookie.assert_called_once()
    mock_service.verify_id_token.assert_not_called()
