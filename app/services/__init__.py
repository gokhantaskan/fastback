"""Application services layer.

Services encapsulate business logic and external integrations,
keeping route handlers thin and focused on HTTP concerns.
"""

from app.core.exceptions import (
    AppException,
    InvalidCredentialsError,
    ProviderError,
    RateLimitError,
    SessionCookieError,
    UserDisabledError,
)
from app.services.firebase_auth import (
    FirebaseAuthService,
    FirebaseUser,
    TokenClaims,
)

__all__ = [
    "AppException",
    "FirebaseAuthService",
    "FirebaseUser",
    "InvalidCredentialsError",
    "ProviderError",
    "RateLimitError",
    "SessionCookieError",
    "TokenClaims",
    "UserDisabledError",
]
