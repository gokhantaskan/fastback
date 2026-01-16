"""User domain schemas.

Request and response schemas for user operations.

Security notes:
- external_id (Firebase UID) is internal-only, never exposed in responses
- UserBase contains only fields safe for API responses
- UserUpdateMe is restricted to prevent privilege escalation
"""

import uuid

from pydantic import EmailStr
from sqlmodel import SQLModel


class UserBase(SQLModel):
    """Base user properties safe for API responses.

    This class should ONLY contain fields that are safe to expose
    to end users. Never add internal fields like external_id here.
    """

    email: EmailStr
    email_verified: bool
    first_name: str | None
    last_name: str | None
    is_active: bool
    is_admin: bool


class UserCreate(SQLModel):
    """Schema for creating a user (internal use after Firebase auth).

    This is used internally when creating a user record after
    successful Firebase authentication. Not exposed via API.
    """

    external_id: str
    email: EmailStr
    email_verified: bool = False
    first_name: str = ""
    last_name: str = ""


class UserRead(UserBase):
    """Response schema for user data.

    Inherits safe fields from UserBase and adds id.
    external_id is intentionally excluded.
    """

    id: uuid.UUID


class UserUpdateMe(SQLModel):
    """Schema for users updating their own profile.

    Intentionally limited to prevent privilege escalation.
    Users cannot modify: email, is_active, is_admin, external_id.
    """

    first_name: str | None = None
    last_name: str | None = None


class UserUpdate(SQLModel):
    """Schema for admin updating a user.

    Admins can modify more fields than regular users.
    is_admin is intentionally excluded - requires superuser.
    """

    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_active: bool | None = None
