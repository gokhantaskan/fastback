import uuid

from fastapi import APIRouter, Depends, status
from sqlmodel import select

from app.core.constants import CommonResponses, Routes
from app.core.deps import CurrentUserDep, SessionDep, require_auth
from app.core.exceptions import UserNotFoundError
from app.models.user import User, UserRead, UserUpdate

router = APIRouter(
    prefix=Routes.USER.prefix,
    tags=[Routes.USER.tag],
    dependencies=[Depends(require_auth)],
    responses={
        **CommonResponses.UNAUTHORIZED,
        **CommonResponses.FORBIDDEN,
    },
)


@router.patch("/me", response_model=UserRead)
async def update_me(user: CurrentUserDep, user_update: UserUpdate, session: SessionDep):
    """Update current authenticated user."""
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


@router.get("/", response_model=list[UserRead])
async def list_users(session: SessionDep):
    """List all users."""
    users = session.exec(select(User)).all()
    return users


@router.get(
    "/{user_id}",
    response_model=UserRead,
    responses={**CommonResponses.NOT_FOUND},
)
async def get_user(user_id: uuid.UUID, session: SessionDep):
    """Get a user by ID."""
    user = session.get(User, user_id)
    if not user:
        raise UserNotFoundError()
    return user
