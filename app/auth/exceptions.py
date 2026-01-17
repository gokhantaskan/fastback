"""Auth domain exceptions.

Authentication and authorization related exceptions.
"""

from app.core.exceptions import AppException, ValidationError


# Authentication errors (401)
class AuthenticationError(AppException):
    """Base class for authentication failures."""

    status_code = 401
    error_type = "authentication_error"

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class InvalidCredentialsError(AuthenticationError):
    """Raised when email/password combination is invalid."""

    error_type = "invalid_credentials"

    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(message)


class InvalidTokenError(AuthenticationError):
    """Raised when authentication token is invalid or expired."""

    error_type = "invalid_token"

    def __init__(self, message: str = "Invalid authentication token"):
        super().__init__(message)


class SessionCookieError(AuthenticationError):
    """Raised when session cookie operations fail."""

    error_type = "session_cookie_error"

    def __init__(self, message: str = "Session cookie error"):
        super().__init__(message)


class SessionExpiredError(AuthenticationError):
    """Raised when session cookie is invalid or expired."""

    error_type = "session_expired"

    def __init__(self, message: str = "Session has expired"):
        super().__init__(message)


# Authorization errors (403)
class AuthorizationError(AppException):
    """Base class for authorization failures."""

    status_code = 403
    error_type = "authorization_error"

    def __init__(self, message: str = "Access denied"):
        super().__init__(message)


class UserDisabledError(AuthorizationError):
    """Raised when user account is disabled in Firebase."""

    error_type = "user_disabled"

    def __init__(self, message: str = "User account is disabled"):
        super().__init__(message)


class AdminRequiredError(AuthorizationError):
    """Raised when admin privileges are required."""

    error_type = "admin_required"

    def __init__(self, message: str = "Admin privileges required"):
        super().__init__(message)


# Validation errors (400) - auth specific
class WeakPasswordError(ValidationError):
    """Raised when password does not meet strength requirements."""

    error_type = "weak_password"

    def __init__(self, message: str = "Password is too weak"):
        super().__init__(message)


class PasswordPolicyError(ValidationError):
    """Raised when password does not meet policy requirements."""

    error_type = "password_policy_error"

    def __init__(
        self,
        message: str = "Password does not meet requirements",
        requirements: list[str] | None = None,
    ):
        self.requirements = requirements or []
        if requirements:
            message = f"{message}: {', '.join(requirements)}"
        super().__init__(message)


class EmailVerificationError(ValidationError):
    """Raised when email verification operations fail."""

    error_type = "email_verification_error"

    def __init__(self, message: str = "Email verification failed"):
        super().__init__(message)


class EmailChangeError(ValidationError):
    """Raised when email change operations fail."""

    error_type = "email_change_error"

    def __init__(self, message: str = "Email change failed"):
        super().__init__(message)
