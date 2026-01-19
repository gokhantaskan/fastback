"""User domain router.

User management routes for CRUD operations.
"""

import uuid

from fastapi import APIRouter, Depends, status
from sqlmodel import and_, select

from app.auth.dependencies import CurrentUserDep, require_admin, require_auth
from app.core.constants import CommonResponses, Routes
from app.core.deps import SessionDep
from app.user.exceptions import EmailExistsError, UserNotFoundError
from app.user.models import User
from app.user.schemas import UserPublicRead, UserRead, UserUpdate, UserUpdateMe

router = APIRouter(
    prefix=Routes.USER.prefix,
    tags=[Routes.USER.tag],
    dependencies=[Depends(require_auth)],
    responses={
        **CommonResponses.UNAUTHORIZED,
        **CommonResponses.FORBIDDEN,
    },
)


@router.patch("/me", response_model=UserPublicRead)
async def update_me(
    user: CurrentUserDep, user_update: UserUpdateMe, session: SessionDep
):
    """Update current authenticated user's profile.

    Users can only update their own first_name and last_name.
    For security, users cannot modify email, status, or is_admin.
    """
    update_data = user_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(user: CurrentUserDep, session: SessionDep):
    """Delete current authenticated user."""
    session.delete(user)
    session.commit()


@router.get("/", response_model=list[UserRead], dependencies=[Depends(require_admin)])
async def list_users(session: SessionDep):
    """List all users. Admin only."""
    users = session.exec(select(User)).all()
    return users


@router.get(
    "/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require_admin)],
    responses={**CommonResponses.NOT_FOUND},
)
async def get_user(user_id: uuid.UUID, session: SessionDep):
    """Get a user by ID. Admin only."""
    user = session.get(User, user_id)
    if not user:
        raise UserNotFoundError()
    return user


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require_admin)],
    responses={**CommonResponses.NOT_FOUND, **CommonResponses.CONFLICT},
)
async def update_user(user_id: uuid.UUID, user_update: UserUpdate, session: SessionDep):
    """Update a user by ID. Admin only.

    Admins can update email, first_name, last_name, and status.
    is_admin changes require superuser privileges (not implemented here).
    """
    user = session.get(User, user_id)
    if not user:
        raise UserNotFoundError()

    update_data = user_update.model_dump(exclude_unset=True)

    # Check if new email is already taken by another user
    if "email" in update_data and update_data["email"] != user.email:
        email_exists = session.exec(
            select(User).where(
                and_(User.email == update_data["email"], User.id != user_id)
            )
        ).first()
        if email_exists:
            raise EmailExistsError("Email already in use")
    for key, value in update_data.items():
        setattr(user, key, value)

    session.add(user)
    session.commit()
    session.refresh(user)
    return user
