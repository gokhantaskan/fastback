"""Centralized infrastructure dependency type aliases.

Import infrastructure dependencies from this module:
    from app.core.deps import SessionDep, SettingsDep

For authentication dependencies, import from auth domain:
    from app.auth.dependencies import CurrentUserDep, FirebaseAuthDep, require_auth
"""

from typing import Annotated

from fastapi import Depends
from sqlmodel import Session

from app.core.settings import Settings, get_settings
from app.db.engine import get_session

# Database session
SessionDep = Annotated[Session, Depends(get_session)]

# Application settings
SettingsDep = Annotated[Settings, Depends(get_settings)]
