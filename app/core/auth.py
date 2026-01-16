"""Authentication dependencies for FastAPI routes.

This module provides the get_current_user dependency that verifies
Firebase authentication and retrieves the local user.
"""

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select

from app.core.exceptions import (
    AppException,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionCookieError,
    UserInactiveError,
    UserNotFoundError,
)
from app.db.engine import get_session
from app.models.user import User
from app.services.firebase_auth import FirebaseAuthService, get_firebase_auth_service

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
    firebase_uid: str | None = None

    # Priority 1: Session cookie authentication (web apps)
    session_cookie = request.cookies.get("session")

    if session_cookie:
        try:
            claims = firebase_auth.verify_session_cookie(
                session_cookie, check_revoked=True
            )
            firebase_uid = claims.uid
        except SessionCookieError as e:
            raise InvalidTokenError() from e

    # Priority 2: Bearer token authentication (API clients)
    if firebase_uid is None and credentials is not None:
        try:
            claims = firebase_auth.verify_id_token(credentials.credentials)
            firebase_uid = claims.uid
        except AppException as e:
            raise InvalidTokenError() from e

    # No valid authentication provided
    if not firebase_uid:
        raise InvalidCredentialsError("Not authenticated")

    # Query local user by Firebase UID
    user = session.exec(select(User).where(User.firebase_uid == firebase_uid)).first()

    if user is None:
        raise UserNotFoundError()

    if not user.is_active:
        raise UserInactiveError()

    return user
