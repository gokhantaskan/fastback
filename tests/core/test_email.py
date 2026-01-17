"""Tests for app/core/email.py - email functionality."""

from unittest.mock import patch

from app.core.email import _extract_oob_code, init_resend, send_password_reset_email
from app.core.settings import get_settings


def test_init_resend():
    """Test init_resend() initializes Resend with API key from settings."""
    settings = get_settings()

    with patch("app.core.email.resend") as mock_resend:
        init_resend()

        if settings.resend_api_key:
            assert mock_resend.api_key == settings.resend_api_key
        else:
            # If no API key, init_resend returns early without setting api_key
            pass


def test_extract_oob_code_from_firebase_link():
    """Test _extract_oob_code() extracts oobCode from Firebase link."""
    firebase_link = (
        "https://app.firebaseapp.com/__/auth/action?"
        "mode=resetPassword&oobCode=ABC123&apiKey=xyz"
    )
    result = _extract_oob_code(firebase_link)
    assert result == "ABC123"


def test_extract_oob_code_missing():
    """Test _extract_oob_code() returns None when oobCode is missing."""
    firebase_link = "https://app.firebaseapp.com/__/auth/action?mode=resetPassword"
    result = _extract_oob_code(firebase_link)
    assert result is None


def test_extract_oob_code_empty_link():
    """Test _extract_oob_code() handles empty link."""
    result = _extract_oob_code("")
    assert result is None


def test_send_password_reset_email():
    """Test send_password_reset_email() sends email via Resend with correct data."""
    firebase_link = (
        "https://app.firebaseapp.com/__/auth/action?"
        "mode=resetPassword&oobCode=TEST_CODE&apiKey=xyz"
    )
    settings = get_settings()

    with patch("app.core.email.resend.Emails.send") as mock_send:
        send_password_reset_email("user@example.com", firebase_link)

        mock_send.assert_called_once()
        call_args = mock_send.call_args[0][0]
        assert call_args["from"] == f"noreply@{settings.app_domain}"
        assert call_args["to"] == "user@example.com"
        assert call_args["subject"] == "FastBack - Reset Your Password"
        expected_url = f"{settings.client_url}/auth/reset-password?oobCode=TEST_CODE"
        assert expected_url in call_args["html"]
