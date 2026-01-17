"""User domain models.

SQLModel table definition for User.
"""

import uuid

from pydantic import EmailStr
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
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
    is_active: bool = Field(default=True)
    is_admin: bool = Field(default=False)
