"""Authentication routes for user registration, login, logout, and password management.

This module provides thin HTTP handlers that delegate to services
for business logic and Firebase communication.
"""

import contextlib

import httpx
from fastapi import APIRouter, Request, Response, status
from sqlmodel import select

from app.core.constants import CommonResponses, Routes
from app.core.deps import CurrentUserDep, FirebaseAuthDep, SessionDep, SettingsDep
from app.core.email import send_email_verification_email, send_password_reset_email
from app.core.exceptions import (
    AppException,
    BadRequestError,
    EmailExistsError,
    EmailVerificationError,
    InternalError,
    InvalidCredentialsError,
    SessionCookieError,
    UserInactiveError,
    UserNotFoundError,
    WeakPasswordError,
)
from app.models.auth_schemas import (
    AuthLogin,
    AuthLogout,
    AuthMessage,
    AuthRegister,
    ConfirmEmailVerificationRequest,
    ConfirmPasswordResetRequest,
    EmailPasswordLoginRequest,
    EmailVerificationResponse,
    PasswordResetRequest,
    PasswordResetResponse,
)
from app.models.user import User, UserRead

router = APIRouter(
    prefix=Routes.AUTH.prefix,
    tags=[Routes.AUTH.tag],
    responses={**CommonResponses.BAD_REQUEST},
)


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    responses={**CommonResponses.CONFLICT},
)
async def register(
    register_data: AuthRegister,
    session: SessionDep,
    firebase_auth: FirebaseAuthDep,
):
    """Register a new user.

    Creates a Firebase user and a local database user in one step.
    Email format is validated by Pydantic's EmailStr before this code runs.
    """
    # Check if email is already taken in local database
    email_exists = session.exec(
        select(User).where(User.email == register_data.email)
    ).first()

    if email_exists:
        raise EmailExistsError()

    # Create Firebase user via service layer (exceptions propagate automatically)
    firebase_user = firebase_auth.create_user(
        email=register_data.email,
        password=register_data.password,
    )

    # Create local user
    user = User(
        firebase_uid=firebase_user.uid,
        email=register_data.email,
        first_name=register_data.first_name,
        last_name=register_data.last_name,
        is_active=True,
    )
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
    except Exception as e:
        # Rollback: delete Firebase user if local DB operation fails
        firebase_auth.delete_user(firebase_user.uid)
        raise InternalError("Failed to create user") from e

    return user


@router.post(
    "/login",
    response_model=AuthLogin,
    responses={**CommonResponses.UNAUTHORIZED, **CommonResponses.FORBIDDEN},
)
async def login(
    payload: EmailPasswordLoginRequest,
    response: Response,
    session: SessionDep,
    firebase_auth: FirebaseAuthDep,
    settings: SettingsDep,
):
    """Login with email/password and set Firebase session cookie.

    Uses Firebase Identity Toolkit to authenticate, then creates
    a session cookie for subsequent requests.
    """
    # Authenticate with Firebase (exceptions propagate automatically)
    firebase_user = await firebase_auth.sign_in_with_email_password(
        email=payload.email,
        password=payload.password,
    )

    # Create session cookie (exceptions propagate automatically)
    session_cookie = firebase_auth.create_session_cookie(
        firebase_user.id_token,
        expires_in=settings.session_expires_in,
    )

    # Query or create local user
    user = session.exec(
        select(User).where(User.firebase_uid == firebase_user.uid)
    ).first()

    if user is None:
        if not firebase_user.email:
            raise BadRequestError("Email not found in Firebase token")

        user = User(
            firebase_uid=firebase_user.uid,
            email=firebase_user.email,
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    if not user.is_active:
        raise UserInactiveError()

    # Set session cookie
    response.set_cookie(
        key="session",
        value=session_cookie,
        max_age=int(settings.session_expires_in.total_seconds()),
        httponly=True,
        secure=settings.is_secure_cookie,
        samesite="lax",
    )

    return AuthLogin(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        email_verified=user.email_verified,
    )


@router.post(
    "/logout",
    response_model=AuthLogout,
    responses={**CommonResponses.UNAUTHORIZED},
)
async def logout(
    request: Request,
    response: Response,
    firebase_auth: FirebaseAuthDep,
):
    """Clear Firebase session cookie and revoke refresh tokens."""
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        raise InvalidCredentialsError("Not authenticated")

    # Always clear cookie on logout
    response.delete_cookie(key="session")

    # Best-effort: verify and revoke tokens
    try:
        claims = firebase_auth.verify_session_cookie(
            session_cookie, check_revoked=False
        )
        firebase_auth.revoke_refresh_tokens(claims.uid)
    except SessionCookieError:
        # Cookie invalid, but still clear it
        pass

    return AuthLogout(message="Logout successful")


@router.post("/request-password-reset", response_model=PasswordResetResponse)
async def request_reset_password(
    request: PasswordResetRequest,
    firebase_auth: FirebaseAuthDep,
):
    """Request a password reset email.

    Generates a Firebase password reset link and sends it via Resend.
    Always returns success to prevent email enumeration attacks.
    """
    with contextlib.suppress(UserNotFoundError, AppException, Exception):
        reset_link = firebase_auth.generate_password_reset_link(request.email)
        send_password_reset_email(request.email, reset_link)

    return PasswordResetResponse(
        message="If an account with that email exists, a password reset link has been sent"  # noqa: E501
    )


@router.post("/confirm-password-reset", response_model=AuthMessage)
async def confirm_password_reset(
    request: ConfirmPasswordResetRequest,
    settings: SettingsDep,
):
    """Confirm password reset using oobCode from email link.

    Uses Firebase Identity Toolkit API to verify oobCode and set new password.
    """
    if not settings.firebase_api_key:
        raise InternalError("Firebase API key not configured")

    url = f"{settings.identity_toolkit_base_url}/v1/accounts:resetPassword?key={settings.firebase_api_key}"  # noqa: E501
    payload = {
        "oobCode": request.oob_code,
        "newPassword": request.new_password,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload)

    if response.status_code != 200:
        error_data = response.json()
        error_message = error_data.get("error", {}).get("message", "Unknown error")

        if "EXPIRED_OOB_CODE" in error_message:
            raise BadRequestError("Password reset link has expired")
        if "INVALID_OOB_CODE" in error_message:
            raise BadRequestError("Invalid password reset link")
        if "WEAK_PASSWORD" in error_message:
            raise WeakPasswordError()

        raise BadRequestError("Failed to reset password")

    return AuthMessage(message="Password has been reset successfully")


@router.get(
    "/me",
    response_model=UserRead,
    responses={**CommonResponses.UNAUTHORIZED},
)
async def get_me(user: CurrentUserDep):
    """Get current authenticated user."""
    return user


@router.post(
    "/request-verification-email",
    response_model=AuthMessage,
    responses={**CommonResponses.UNAUTHORIZED},
)
async def send_verification_email(
    user: CurrentUserDep,
    firebase_auth: FirebaseAuthDep,
):
    """Send email verification link to current user.

    Generates a Firebase email verification link, extracts the oobCode,
    creates a custom verification URL, and sends it via Resend.
    """
    if user.email_verified:
        return AuthMessage(message="Email is already verified")

    with contextlib.suppress(
        UserNotFoundError, EmailVerificationError, AppException, Exception
    ):
        verification_link = firebase_auth.generate_email_verification_link(user.email)
        send_email_verification_email(user.email, verification_link)

    return AuthMessage(message="Verification email sent")


@router.post("/confirm-verification-email", response_model=EmailVerificationResponse)
async def confirm_email_verification(
    request: ConfirmEmailVerificationRequest,
    session: SessionDep,
    settings: SettingsDep,
):
    """Confirm verification email using oobCode from email link.

    Uses Firebase Identity Toolkit API to verify oobCode and update email verification status.
    Updates local user's email_verified status if verification email succeeds.
    """  # noqa: E501
    if not settings.firebase_api_key:
        raise InternalError("Firebase API key not configured")

    url = f"{settings.identity_toolkit_base_url}/v1/accounts:update?key={settings.firebase_api_key}"  # noqa: E501
    payload = {
        "oobCode": request.oob_code,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload)

    if response.status_code != 200:
        error_data = response.json()
        error_message = error_data.get("error", {}).get("message", "Unknown error")

        if "EXPIRED_OOB_CODE" in error_message:
            raise EmailVerificationError("Email verification link has expired")
        if "INVALID_OOB_CODE" in error_message:
            raise EmailVerificationError("Invalid email verification link")

        raise EmailVerificationError("Failed to verify email")

    # Get user info from response
    data = response.json()
    firebase_uid = data.get("localId")
    email_verified = data.get("emailVerified", False)

    if not firebase_uid:
        raise InternalError("Failed to get user ID from verification response")

    if not email_verified:
        return EmailVerificationResponse(
            email_verified=False,
            message="Email verification failed",
        )

    # Update local user's email_verified status
    user = session.exec(select(User).where(User.firebase_uid == firebase_uid)).first()

    if user:
        user.email_verified = True
        session.add(user)
        session.commit()
        session.refresh(user)

    return EmailVerificationResponse(
        email_verified=True,
        message="Email verified successfully",
    )


@router.post(
    "/revoke-tokens",
    response_model=AuthMessage,
    responses={**CommonResponses.UNAUTHORIZED},
)
async def revoke_tokens(user: CurrentUserDep, firebase_auth: FirebaseAuthDep):
    """Revoke all refresh tokens for the current user.

    This will sign out the user from all devices.
    """
    try:
        firebase_auth.revoke_refresh_tokens(user.firebase_uid)
    except Exception as e:
        raise InternalError("Failed to revoke tokens") from e

    return AuthMessage(message="All tokens have been revoked")
