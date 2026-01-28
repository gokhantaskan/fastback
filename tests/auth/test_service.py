"""Tests for app/auth/service.py - Firebase Auth Service.

Property-based tests for exception hierarchy and service behavior.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from firebase_admin.exceptions import FirebaseError
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from app.auth.exceptions import WeakPasswordError
from app.auth.service import FirebaseAuthService
from app.core.exceptions import AppException, ProviderError, RateLimitError
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

    @pytest.mark.asyncio
    async def test_successful_link_generation(self):
        """Test successful password reset link generation.

        Validates: Requirement 3.2
        """
        expected_link = "https://example.com/reset?oobCode=abc123"

        with patch.object(
            self.service,
            "_make_admin_identity_toolkit_request",
            new_callable=AsyncMock,
        ) as mock_request:
            mock_request.return_value = {"oobLink": expected_link}

            result = await self.service.generate_password_reset_link("user@example.com")

            assert result == expected_link
            mock_request.assert_called_once_with(
                endpoint="v1/accounts:sendOobCode",
                payload={
                    "requestType": "PASSWORD_RESET",
                    "email": "user@example.com",
                    "returnOobLink": True,
                },
            )

    @pytest.mark.asyncio
    async def test_user_not_found_raises_user_not_found_error(self):
        """Test EMAIL_NOT_FOUND error maps to UserNotFoundError.

        Validates: Requirement 3.3
        """
        with patch.object(
            self.service,
            "_make_admin_identity_toolkit_request",
            new_callable=AsyncMock,
        ) as mock_request:
            mock_request.side_effect = ProviderError("EMAIL_NOT_FOUND")

            with pytest.raises(UserNotFoundError) as exc_info:
                await self.service.generate_password_reset_link(
                    "nonexistent@example.com"
                )

            assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_other_errors_raise_app_exception(self):
        """Test other errors map to AppException.

        Validates: Requirement 3.4
        """
        with patch.object(
            self.service,
            "_make_admin_identity_toolkit_request",
            new_callable=AsyncMock,
        ) as mock_request:
            mock_request.side_effect = ProviderError("INTERNAL_ERROR")

            with pytest.raises(AppException) as exc_info:
                await self.service.generate_password_reset_link("user@example.com")

            # Should be AppException but NOT UserNotFoundError
            assert not isinstance(exc_info.value, UserNotFoundError)


class TestParseRetryAfter:
    """Unit tests for _parse_retry_after static method."""

    def test_parses_integer_value(self):
        """Test parsing a valid integer string."""
        result = FirebaseAuthService._parse_retry_after("60")
        assert result == 60

    def test_parses_zero(self):
        """Test parsing zero value."""
        result = FirebaseAuthService._parse_retry_after("0")
        assert result == 0

    def test_returns_none_for_none_input(self):
        """Test that None input returns None."""
        result = FirebaseAuthService._parse_retry_after(None)
        assert result is None

    def test_returns_none_for_empty_string(self):
        """Test that empty string returns None."""
        result = FirebaseAuthService._parse_retry_after("")
        assert result is None

    def test_returns_none_for_invalid_format(self):
        """Test that non-integer string returns None."""
        result = FirebaseAuthService._parse_retry_after("not-a-number")
        assert result is None

    def test_returns_none_for_float_string(self):
        """Test that float string returns None (strict int parsing)."""
        result = FirebaseAuthService._parse_retry_after("60.5")
        assert result is None

    @hypothesis_settings(max_examples=50)
    @given(seconds=st.integers(min_value=0, max_value=86400))
    def test_parses_any_valid_integer(self, seconds):
        """Property: any valid integer string is parsed correctly."""
        result = FirebaseAuthService._parse_retry_after(str(seconds))
        assert result == seconds


class TestSanitizeErrorCode:
    """Unit tests for _sanitize_error_code static method."""

    def test_extracts_simple_error_code(self):
        """Test extracting a simple error code."""
        result = FirebaseAuthService._sanitize_error_code("INVALID_PASSWORD")
        assert result == "INVALID_PASSWORD"

    def test_extracts_code_with_additional_text(self):
        """Test extracting error code when message has additional text."""
        result = FirebaseAuthService._sanitize_error_code(
            "WEAK_PASSWORD : Password should be at least 6 characters"
        )
        assert result == "WEAK_PASSWORD"

    def test_extracts_code_with_brackets(self):
        """Test extracting error code when message has bracket content."""
        result = FirebaseAuthService._sanitize_error_code(
            "PASSWORD_DOES_NOT_MEET_REQUIREMENTS [Missing: uppercase]"
        )
        assert result == "PASSWORD_DOES_NOT_MEET_REQUIREMENTS"

    def test_returns_unknown_for_empty_string(self):
        """Test that empty string returns UNKNOWN."""
        result = FirebaseAuthService._sanitize_error_code("")
        assert result == "UNKNOWN"

    def test_returns_unknown_for_lowercase_message(self):
        """Test that lowercase-only message returns UNKNOWN."""
        result = FirebaseAuthService._sanitize_error_code("some error message")
        assert result == "UNKNOWN"

    def test_handles_code_with_numbers(self):
        """Test that codes with numbers are handled."""
        result = FirebaseAuthService._sanitize_error_code("ERROR_CODE_123")
        assert result == "ERROR_CODE_123"


class TestRateLimitErrorRetryAfter:
    """Unit tests for RateLimitError retry_after parameter."""

    def test_default_retry_after_is_none(self):
        """Test that retry_after defaults to None."""
        error = RateLimitError("Too many requests")
        assert error.retry_after is None

    def test_retry_after_can_be_set(self):
        """Test that retry_after can be set via constructor."""
        error = RateLimitError("Too many requests", retry_after=60)
        assert error.retry_after == 60

    def test_message_is_preserved(self):
        """Test that message is preserved with retry_after."""
        error = RateLimitError("Custom message", retry_after=30)
        assert error.message == "Custom message"
        assert error.retry_after == 30


class TestIdentityToolkitRetryBehavior:
    """Tests for retry behavior in _make_identity_toolkit_request."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = FirebaseAuthService(api_key="test-api-key")

    @pytest.mark.asyncio
    async def test_request_error_raises_provider_error(self):
        """Test that httpx.RequestError raises ProviderError."""
        with patch("app.auth.service.get_firebase_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.RequestError("Connection failed")
            mock_get_client.return_value = mock_client

            with pytest.raises(ProviderError, match="unavailable"):
                await self.service._make_identity_toolkit_request(
                    "v1/test", {"key": "value"}
                )

    @pytest.mark.asyncio
    async def test_retry_true_retries_on_request_error(self):
        """Test that retry=True retries on RequestError."""
        call_count = 0

        async def mock_post(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise httpx.RequestError("Transient error")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"success": True}
            return mock_response

        with patch("app.auth.service.get_firebase_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.post = mock_post
            mock_get_client.return_value = mock_client

            with patch("app.core.retry._calculate_delay", return_value=0.001):
                result = await self.service._make_identity_toolkit_request(
                    "v1/test", {"key": "value"}, retry=True
                )

            assert result == {"success": True}
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_429_response_raises_rate_limit_with_retry_after(self):
        """Test that 429 response includes Retry-After header value."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "120"}
        mock_response.json.return_value = {
            "error": {"message": "TOO_MANY_ATTEMPTS_TRY_LATER"}
        }

        with patch("app.auth.service.get_firebase_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            with pytest.raises(RateLimitError) as exc_info:
                await self.service._make_identity_toolkit_request(
                    "v1/test", {"key": "value"}
                )

            assert exc_info.value.retry_after == 120

    @pytest.mark.asyncio
    async def test_429_without_json_still_raises_rate_limit(self):
        """Test that 429 response without valid JSON raises RateLimitError."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "60"}
        mock_response.json.side_effect = ValueError("No JSON")

        with patch("app.auth.service.get_firebase_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            with pytest.raises(RateLimitError) as exc_info:
                await self.service._make_identity_toolkit_request(
                    "v1/test", {"key": "value"}
                )

            assert exc_info.value.retry_after == 60


class TestPasswordErrorPriority:
    """Tests for password error handling priority."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = FirebaseAuthService(api_key="test-api-key")

    @pytest.mark.asyncio
    async def test_password_policy_error_takes_priority_over_weak_password(self):
        """Test that PASSWORD_DOES_NOT_MEET_REQUIREMENTS is checked before WEAK_PASSWORD."""  # noqa: E501
        from app.auth.exceptions import PasswordPolicyError

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {}
        # Message contains both patterns
        mock_response.json.return_value = {
            "error": {
                "message": (
                    "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : "
                    "Missing password requirements: [containsLowercaseLetter]"
                )
            }
        }

        with patch("app.auth.service.get_firebase_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            with pytest.raises(PasswordPolicyError) as exc_info:
                await self.service._make_identity_toolkit_request(
                    "v1/test", {"password": "ALLCAPS123"}
                )

            # Should raise PasswordPolicyError, not WeakPasswordError
            assert len(exc_info.value.requirements) > 0
            assert "containsLowercaseLetter" in exc_info.value.requirements
