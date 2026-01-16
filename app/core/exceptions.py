"""App-wide exception hierarchy.

This module provides a unified exception system with automatic HTTP status code
mapping and consistent error response formatting.
"""


class AppException(Exception):
    """Base exception for all application errors.

    All custom exceptions inherit from this class and define their own
    status_code and error_type for consistent API responses.
    """

    status_code: int = 500
    error_type: str = "internal_error"

    def __init__(self, message: str = "An unexpected error occurred"):
        self.message = message
        super().__init__(message)


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


class UserInactiveError(AuthorizationError):
    """Raised when user is inactive in local database."""

    error_type = "user_inactive"

    def __init__(self, message: str = "User is inactive"):
        super().__init__(message)


# Not found errors (404)
class NotFoundError(AppException):
    """Base class for resource not found errors."""

    status_code = 404
    error_type = "not_found"

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message)


class UserNotFoundError(NotFoundError):
    """Raised when user cannot be found."""

    error_type = "user_not_found"

    def __init__(self, message: str = "User not found"):
        super().__init__(message)


# Conflict errors (409)
class ConflictError(AppException):
    """Base class for resource conflict errors."""

    status_code = 409
    error_type = "conflict"

    def __init__(self, message: str = "Resource conflict"):
        super().__init__(message)


class EmailExistsError(ConflictError):
    """Raised when attempting to register with an existing email."""

    error_type = "email_exists"

    def __init__(self, message: str = "Email already registered"):
        super().__init__(message)


# Validation errors (400)
class ValidationError(AppException):
    """Base class for validation errors."""

    status_code = 400
    error_type = "validation_error"

    def __init__(self, message: str = "Validation failed"):
        super().__init__(message)


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


class BadRequestError(ValidationError):
    """Raised for general bad request errors."""

    error_type = "bad_request"

    def __init__(self, message: str = "Bad request"):
        super().__init__(message)


class EmailVerificationError(ValidationError):
    """Raised when email verification operations fail."""

    error_type = "email_verification_error"

    def __init__(self, message: str = "Email verification failed"):
        super().__init__(message)


# Rate limit errors (429)
class RateLimitError(AppException):
    """Raised when rate limit is exceeded."""

    status_code = 429
    error_type = "rate_limit_exceeded"

    def __init__(self, message: str = "Too many requests, please try again later"):
        super().__init__(message)


# External service errors (502)
class ExternalServiceError(AppException):
    """Base class for external service failures."""

    status_code = 502
    error_type = "external_service_error"

    def __init__(self, message: str = "External service error"):
        super().__init__(message)


class ProviderError(ExternalServiceError):
    """Raised when upstream provider returns an unexpected response."""

    error_type = "provider_error"

    def __init__(
        self, message: str = "Authentication provider returned an invalid response"
    ):
        super().__init__(message)


# Internal errors (500)
class InternalError(AppException):
    """Raised for internal server errors."""

    status_code = 500
    error_type = "internal_error"

    def __init__(self, message: str = "An internal error occurred"):
        super().__init__(message)
