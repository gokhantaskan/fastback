"""User domain schemas.

Request and response schemas for user operations.

Security notes:
- external_id (Firebase UID) is internal-only, never exposed in responses
- UserBase contains only fields safe for API responses
- UserUpdateMe is restricted to prevent privilege escalation
"""

import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_serializer
from sqlmodel import SQLModel

from app.user.models import UserStatus


class UserBase(SQLModel):
    """Base user properties safe for all API responses.

    This class should ONLY contain fields that are safe to expose
    to any user. Never add internal fields like external_id here.
    """

    email: EmailStr
    email_verified: bool
    first_name: str | None
    last_name: str | None


class UserPublicRead(UserBase):
    """Response schema for public/self user data.

    Used for non-admin contexts like /me endpoints.
    Does not expose privilege levels or account status.
    """

    id: uuid.UUID
    status: UserStatus
    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at", "updated_at")
    def serialize_datetime(self, value: datetime) -> str:
        """Format datetime as ISO 8601 with Z suffix."""
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


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
    status: UserStatus = UserStatus.pending


class UserRead(UserPublicRead):
    """Full response schema for admin contexts.

    Extends UserPublicRead with sensitive fields like account status
    and privilege level. Use only for admin-protected endpoints.
    """

    is_admin: bool


class UserUpdateMe(SQLModel):
    """Schema for users updating their own profile.

    Intentionally limited to prevent privilege escalation.
    Users cannot modify: email, status, is_admin, external_id.
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
    status: UserStatus | None = None


class CompleteProfileRequest(SQLModel):
    """Request schema for completing user profile.

    Used when a user logs in via Firebase but doesn't have a local profile,
    or when their profile is in 'pending' status.
    """

    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
