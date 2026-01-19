"""User domain models.

SQLModel table definition for User.
"""

import uuid
from enum import Enum

from pydantic import EmailStr
from sqlmodel import Field, SQLModel

from app.core.mixins import TimestampMixin


class UserStatus(str, Enum):
    """User account status.

    - pending: Logged in via Firebase but profile not completed
    - active: Profile complete, account active
    - inactive: Deactivated by admin
    """

    pending = "pending"
    active = "active"
    inactive = "inactive"


class User(TimestampMixin, SQLModel, table=True):
    """User database model.

    Note: external_id is internal-only (Firebase UID) and should
    never be exposed in API responses.
    """

    __tablename__: str = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    external_id: str = Field(index=True, unique=True)
    email: EmailStr = Field(index=True, unique=True, max_length=255)
    email_verified: bool = Field(default=False)
    first_name: str = Field(default="", max_length=50)
    last_name: str = Field(default="", max_length=50)
    status: UserStatus = Field(default=UserStatus.pending, max_length=20)
    is_admin: bool = Field(default=False)
