"""User domain exceptions.

User-related exceptions for not found, inactive, and conflict scenarios.
"""

# Import AuthorizationError from auth domain to avoid circular imports
# We define UserInactiveError here but it inherits from a base class
from app.core.exceptions import AppException, ConflictError, NotFoundError


class UserAuthorizationError(AppException):
    """Base class for user authorization failures."""

    status_code = 403
    error_type = "authorization_error"

    def __init__(self, message: str = "Access denied"):
        super().__init__(message)


class UserNotFoundError(NotFoundError):
    """Raised when user cannot be found."""

    error_type = "user_not_found"

    def __init__(self, message: str = "User not found"):
        super().__init__(message)


class UserInactiveError(UserAuthorizationError):
    """Raised when user is inactive in local database."""

    error_type = "user_inactive"

    def __init__(self, message: str = "User is inactive"):
        super().__init__(message)


class EmailExistsError(ConflictError):
    """Raised when attempting to register with an existing email."""

    error_type = "email_exists"

    def __init__(self, message: str = "Email already registered"):
        super().__init__(message)
