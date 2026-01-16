import uuid

from pydantic import EmailStr
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    firebase_uid: str = Field(index=True, unique=True)
    email: EmailStr = Field(index=True, unique=True, max_length=255)
    email_verified: bool = Field(default=False)
    first_name: str = Field(max_length=50)
    last_name: str = Field(max_length=50)
    is_active: bool = Field(default=True)


# Table model
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class UserCreate(UserBase):
    pass


class UserRead(SQLModel):
    """Response schema for user data. Excludes firebase_uid for security."""

    id: uuid.UUID
    email: EmailStr
    email_verified: bool
    first_name: str | None
    last_name: str | None
    is_active: bool


class UserUpdate(SQLModel):
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_active: bool | None = None
