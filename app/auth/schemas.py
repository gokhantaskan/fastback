"""Auth domain schemas.

Request and response schemas for authentication operations.
"""

import uuid

from pydantic import BaseModel, EmailStr, Field


class AuthRegister(BaseModel):
    """Request schema for user registration."""

    email: EmailStr
    password: str = Field(min_length=8)
    first_name: str = Field(min_length=1)
    last_name: str = Field(min_length=1)


class AuthLogin(BaseModel):
    """Response schema for login."""

    id: uuid.UUID
    email: str
    first_name: str | None
    last_name: str | None
    email_verified: bool = False


class EmailPasswordLoginRequest(BaseModel):
    """Request schema for email/password login via Firebase Identity Toolkit."""

    email: EmailStr
    password: str


class AuthLogout(BaseModel):
    """Response schema for logout."""

    message: str


class PasswordResetRequest(BaseModel):
    """Request schema for password reset."""

    email: EmailStr


class PasswordResetResponse(BaseModel):
    """Response schema for password reset."""

    message: str


class ConfirmPasswordResetRequest(BaseModel):
    """Request schema for confirming password reset with oobCode."""

    oob_code: str
    new_password: str


class AuthMessage(BaseModel):
    """Generic auth message response."""

    message: str


class ConfirmEmailVerificationRequest(BaseModel):
    """Request schema for confirming email verification with oobCode."""

    oob_code: str


class EmailVerificationResponse(BaseModel):
    """Response schema for email verification status."""

    email_verified: bool
    message: str


class UpdatePasswordRequest(BaseModel):
    """Request schema for updating password (authenticated user)."""

    current_password: str
    new_password: str


class RequestEmailChangeRequest(BaseModel):
    """Request schema for requesting email change.

    Requires current password for re-authentication (security best practice).
    """

    new_email: EmailStr
    current_password: str


class ConfirmEmailChangeRequest(BaseModel):
    """Request schema for confirming email change with oobCode."""

    oob_code: str
