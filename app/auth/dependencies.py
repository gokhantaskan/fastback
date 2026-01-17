"""Auth domain dependencies.

Authentication dependencies for FastAPI routes including get_current_user
and type aliases for authenticated user injection.
"""

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select

from app.auth.exceptions import (
    AdminRequiredError,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionCookieError,
)
from app.auth.service import FirebaseAuthService, get_firebase_auth_service
from app.core.exceptions import AppException
from app.db.engine import get_session
from app.user.exceptions import UserInactiveError, UserNotFoundError
from app.user.models import User

security = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    firebase_auth: Annotated[FirebaseAuthService, Depends(get_firebase_auth_service)],
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(security)
    ] = None,
) -> User:
    """Verify Firebase authentication and return local User.

    Supports two authentication methods (in priority order):
    1. Session cookie (preferred for web apps)
    2. Bearer ID token (for API clients, mobile apps)

    Args:
        request: FastAPI request (for session cookie)
        session: Database session
        firebase_auth: Firebase auth service
        credentials: Optional bearer token from Authorization header

    Returns:
        User model from local database

    Raises:
        InvalidTokenError: If authentication token is invalid
        InvalidCredentialsError: If not authenticated
        UserNotFoundError: If user not found in database
        UserInactiveError: If user is inactive
    """
    _external_id: str | None = None

    # Priority 1: Session cookie authentication (web apps)
    session_cookie = request.cookies.get("session")

    if session_cookie:
        try:
            claims = firebase_auth.verify_session_cookie(
                session_cookie, check_revoked=True
            )
            _external_id = claims.uid
        except SessionCookieError as e:
            raise InvalidTokenError() from e

    # Priority 2: Bearer token authentication (API clients)
    if _external_id is None and credentials is not None:
        try:
            claims = firebase_auth.verify_id_token(credentials.credentials)
            _external_id = claims.uid
        except AppException as e:
            raise InvalidTokenError() from e

    # No valid authentication provided
    if not _external_id:
        raise InvalidCredentialsError("Not authenticated")

    # Query local user by Firebase UID
    user = session.exec(select(User).where(User.external_id == _external_id)).first()

    if user is None:
        raise UserNotFoundError()

    if not user.is_active:
        raise UserInactiveError()

    return user


# Type aliases for dependency injection
CurrentUserDep = Annotated[User, Depends(get_current_user)]
FirebaseAuthDep = Annotated[FirebaseAuthService, Depends(get_firebase_auth_service)]


def require_auth(_user: CurrentUserDep) -> None:
    """Require authentication without injecting user into path operation.

    Use as a router-level dependency when all routes require auth:
        router = APIRouter(dependencies=[Depends(require_auth)])

    For endpoints that need the user object, still use CurrentUserDep directly.
    FastAPI caches dependencies, so there's no duplicate auth overhead.
    """
    pass  # Authentication already validated by CurrentUserDep


def get_admin_user(user: CurrentUserDep) -> User:
    """Verify the current user has admin privileges.

    Args:
        user: Current authenticated user

    Returns:
        User model if user is admin

    Raises:
        AdminRequiredError: If user is not an admin
    """
    if not user.is_admin:
        raise AdminRequiredError()
    return user


AdminUserDep = Annotated[User, Depends(get_admin_user)]


def require_admin(_user: AdminUserDep) -> None:
    """Require admin privileges without injecting user into path operation.

    Use as a router-level or endpoint-level dependency:
        router = APIRouter(dependencies=[Depends(require_admin)])
        @router.get("/", dependencies=[Depends(require_admin)])

    For endpoints that need the admin user object, use AdminUserDep directly.
    """
    pass  # Admin check already validated by AdminUserDep
