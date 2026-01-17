"""App-wide base exception hierarchy.

This module provides base exception classes with automatic HTTP status code
mapping and consistent error response formatting.

Domain-specific exceptions are in their respective domain modules:
- app.auth.exceptions: Authentication and authorization exceptions
- app.user.exceptions: User-related exceptions
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


# Validation errors (400)
class ValidationError(AppException):
    """Base class for validation errors."""

    status_code = 400
    error_type = "validation_error"

    def __init__(self, message: str = "Validation failed"):
        super().__init__(message)


class BadRequestError(ValidationError):
    """Raised for general bad request errors."""

    error_type = "bad_request"

    def __init__(self, message: str = "Bad request"):
        super().__init__(message)


# Not found errors (404)
class NotFoundError(AppException):
    """Base class for resource not found errors."""

    status_code = 404
    error_type = "not_found"

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message)


# Conflict errors (409)
class ConflictError(AppException):
    """Base class for resource conflict errors."""

    status_code = 409
    error_type = "conflict"

    def __init__(self, message: str = "Resource conflict"):
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
