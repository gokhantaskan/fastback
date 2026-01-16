"""Centralized dependency type aliases for FastAPI routes.

Import all dependencies from this single module:
    from app.core.deps import SessionDep, CurrentUserDep, SettingsDep, FirebaseAuthDep
"""

from typing import Annotated

from fastapi import Depends
from sqlmodel import Session

from app.core.auth import get_current_user
from app.core.settings import Settings, get_settings
from app.db.engine import get_session
from app.models.user import User
from app.services.firebase_auth import FirebaseAuthService, get_firebase_auth_service

# Database session
SessionDep = Annotated[Session, Depends(get_session)]

# Application settings
SettingsDep = Annotated[Settings, Depends(get_settings)]

# Firebase authentication service
FirebaseAuthDep = Annotated[FirebaseAuthService, Depends(get_firebase_auth_service)]

# Current authenticated user (requires valid Firebase token)
CurrentUserDep = Annotated[User, Depends(get_current_user)]


# Dependency for router-level auth requirement (verifies auth, returns nothing)
# Use this when you need auth but don't need the user object in the path operation
def require_auth(_user: CurrentUserDep) -> None:
    """Require authentication without injecting user into path operation.

    Use as a router-level dependency when all routes require auth:
        router = APIRouter(dependencies=[Depends(require_auth)])

    For endpoints that need the user object, still use CurrentUserDep directly.
    FastAPI caches dependencies, so there's no duplicate auth overhead.
    """
    pass  # Authentication already validated by CurrentUserDep
