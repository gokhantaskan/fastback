"""Tests for app/auth/service.py - Firebase Auth Service.

Property-based tests for exception hierarchy and service behavior.
"""

from unittest.mock import patch

import pytest
from firebase_admin.exceptions import FirebaseError
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from app.auth.exceptions import WeakPasswordError
from app.auth.service import FirebaseAuthService
from app.core.exceptions import AppException
from app.user.exceptions import EmailExistsError, UserNotFoundError


# Feature: firebase-service-refactor, Property 2: Exception Hierarchy Invariant
# **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
@hypothesis_settings(max_examples=100)
@given(
    exception_class=st.sampled_from(
        [EmailExistsError, WeakPasswordError, UserNotFoundError]
    ),
    message=st.text(min_size=1, max_size=100),
)
def test_exception_hierarchy_invariant(exception_class, message):
    """Property 2: Exception Hierarchy Invariant.

    For any custom exception type defined in the exceptions module
    (EmailExistsError, WeakPasswordError, UserNotFoundError),
    it SHALL be a subclass of AppException.
    """
    # Verify the class is a subclass of AppException
    assert issubclass(exception_class, AppException)

    # Verify instances are also instances of AppException
    instance = exception_class(message)
    assert isinstance(instance, AppException)

    # Verify the message is preserved
    assert instance.message == message


# Feature: firebase-service-refactor, Property 4: Delete User Error Suppression
# **Validates: Requirements 2.3, 2.4**
@hypothesis_settings(max_examples=100)
@given(
    uid=st.text(
        min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"))
    ),
    error_code=st.sampled_from(
        [
            "USER_NOT_FOUND",
            "INTERNAL_ERROR",
            "INVALID_ARGUMENT",
            "PERMISSION_DENIED",
            "UNAVAILABLE",
        ]
    ),
    error_message=st.text(min_size=1, max_size=100),
)
def test_delete_user_error_suppression(uid, error_code, error_message):
    """Property 4: Delete User Error Suppression.

    For any error raised by Firebase Admin SDK during delete_user,
    the service method SHALL suppress the error and return normally
    (no exception propagates).

    Validates: Requirements 2.3, 2.4
    """
    service = FirebaseAuthService(api_key="test-api-key")

    with patch("app.auth.service.firebase_admin_auth") as mock_firebase_auth:
        # Simulate Firebase raising an error
        mock_error = FirebaseError(code=error_code, message=error_message)
        mock_firebase_auth.delete_user.side_effect = mock_error

        # delete_user should NOT raise - errors are suppressed
        # This should complete without raising any exception
        result = service.delete_user(uid)

        # Verify the method returns None (no exception)
        assert result is None

        # Verify delete_user was actually called
        mock_firebase_auth.delete_user.assert_called_once_with(uid)


class TestCreateUser:
    """Unit tests for create_user error mapping.

    Validates: Requirements 1.3, 1.4, 1.5
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.service = FirebaseAuthService(api_key="test-api-key")

    @patch("app.auth.service.firebase_admin_auth")
    def test_email_exists_raises_email_exists_error(self, mock_firebase_auth):
        """Test EMAIL_EXISTS error maps to EmailExistsError.

        Validates: Requirement 1.3
        """
        mock_error = FirebaseError(code="EMAIL_EXISTS", message="EMAIL_EXISTS")
        mock_firebase_auth.create_user.side_effect = mock_error

        with pytest.raises(EmailExistsError) as exc_info:
            self.service.create_user("existing@example.com", "password123")

        assert "already registered" in str(exc_info.value).lower()

    @patch("app.auth.service.firebase_admin_auth")
    def test_weak_password_raises_weak_password_error(self, mock_firebase_auth):
        """Test WEAK_PASSWORD error maps to WeakPasswordError.

        Validates: Requirement 1.4
        """
        mock_error = FirebaseError(code="WEAK_PASSWORD", message="WEAK_PASSWORD")
        mock_firebase_auth.create_user.side_effect = mock_error

        with pytest.raises(WeakPasswordError) as exc_info:
            self.service.create_user("user@example.com", "weak")

        assert "too weak" in str(exc_info.value).lower()

    @patch("app.auth.service.firebase_admin_auth")
    def test_other_errors_raise_app_exception(self, mock_firebase_auth):
        """Test other Firebase errors map to AppException.

        Validates: Requirement 1.5
        """
        mock_error = FirebaseError(
            code="INTERNAL_ERROR", message="Something went wrong"
        )
        mock_firebase_auth.create_user.side_effect = mock_error

        with pytest.raises(AppException) as exc_info:
            self.service.create_user("user@example.com", "password123")

        # Should be AppException but NOT EmailExistsError or WeakPasswordError
        assert not isinstance(exc_info.value, EmailExistsError)
        assert not isinstance(exc_info.value, WeakPasswordError)


class TestGeneratePasswordResetLink:
    """Unit tests for generate_password_reset_link method.

    Validates: Requirements 3.2, 3.3, 3.4
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.service = FirebaseAuthService(api_key="test-api-key")

    @patch("app.auth.service.firebase_admin_auth")
    def test_successful_link_generation(self, mock_firebase_auth):
        """Test successful password reset link generation.

        Validates: Requirement 3.2
        """
        expected_link = "https://example.com/reset?oobCode=abc123"
        mock_firebase_auth.generate_password_reset_link.return_value = expected_link

        result = self.service.generate_password_reset_link("user@example.com")

        assert result == expected_link
        mock_firebase_auth.generate_password_reset_link.assert_called_once_with(
            "user@example.com"
        )

    @patch("app.auth.service.firebase_admin_auth")
    def test_user_not_found_raises_user_not_found_error(self, mock_firebase_auth):
        """Test USER_NOT_FOUND error maps to UserNotFoundError.

        Validates: Requirement 3.3
        """
        mock_error = FirebaseError(code="USER_NOT_FOUND", message="USER_NOT_FOUND")
        mock_firebase_auth.generate_password_reset_link.side_effect = mock_error

        with pytest.raises(UserNotFoundError) as exc_info:
            self.service.generate_password_reset_link("nonexistent@example.com")

        assert "not found" in str(exc_info.value).lower()

    @patch("app.auth.service.firebase_admin_auth")
    def test_other_errors_raise_app_exception(self, mock_firebase_auth):
        """Test other Firebase errors map to AppException.

        Validates: Requirement 3.4
        """
        mock_error = FirebaseError(
            code="INTERNAL_ERROR", message="Something went wrong"
        )
        mock_firebase_auth.generate_password_reset_link.side_effect = mock_error

        with pytest.raises(AppException) as exc_info:
            self.service.generate_password_reset_link("user@example.com")

        # Should be AppException but NOT UserNotFoundError
        assert not isinstance(exc_info.value, UserNotFoundError)
