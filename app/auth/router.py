"""Auth domain router.

Authentication routes for user registration, login, logout, and password management.
This module provides thin HTTP handlers that delegate to services
for business logic and Firebase communication.
"""

import logging

from fastapi import APIRouter, Request, Response, status
from sqlmodel import select

from app.auth.dependencies import CurrentUserDep, FirebaseAuthDep
from app.auth.exceptions import (
    EmailVerificationError,
    InvalidCredentialsError,
    SessionCookieError,
)
from app.auth.schemas import (
    AuthLogout,
    AuthMessage,
    AuthRegister,
    ConfirmEmailChangeRequest,
    ConfirmEmailVerificationRequest,
    ConfirmPasswordResetRequest,
    EmailPasswordLoginRequest,
    EmailVerificationResponse,
    PasswordResetRequest,
    PasswordResetResponse,
    ProfileIncompleteResponse,
    RequestEmailChangeRequest,
    UpdatePasswordRequest,
)
from app.core.constants import CommonResponses, Routes
from app.core.deps import SessionDep, SettingsDep
from app.core.email import (
    send_email_change_verification_email,
    send_email_verification_email,
    send_password_reset_email,
)
from app.core.exceptions import AppException, BadRequestError, InternalError
from app.user.exceptions import EmailExistsError, UserInactiveError, UserNotFoundError
from app.user.models import User, UserStatus
from app.user.schemas import CompleteProfileRequest, UserRead

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix=Routes.AUTH.prefix,
    tags=[Routes.AUTH.tag],
    responses={**CommonResponses.BAD_REQUEST},
)


@router.post(
    "/register",
    response_model=AuthMessage,
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

    # Create local user with active status (profile is complete via registration)
    user = User(
        external_id=firebase_user.uid,
        email=register_data.email,
        first_name=register_data.first_name,
        last_name=register_data.last_name,
        status=UserStatus.active,
    )
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
    except Exception as e:
        # Rollback: delete Firebase user if local DB operation fails
        firebase_auth.delete_user(firebase_user.uid)
        raise InternalError("Failed to create user") from e

    # Send verification email (best-effort: log failures but don't fail registration)
    try:
        verification_link = await firebase_auth.generate_email_verification_link(
            register_data.email
        )
        send_email_verification_email(register_data.email, verification_link)
    except (UserNotFoundError, EmailVerificationError, AppException, Exception) as e:
        # Log for monitoring, but suppress to prevent failing registration
        logger.debug(
            "Verification email failed for newly registered user %s: %s",
            user.id,
            str(e),
        )

    return AuthMessage(message="User registered successfully")


@router.post(
    "/login",
    response_model=UserRead | ProfileIncompleteResponse,
    responses={
        **CommonResponses.UNAUTHORIZED,
        **CommonResponses.FORBIDDEN,
        200: {
            "description": "Login successful or profile completion required",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Full login success",
                            "value": {
                                "id": "uuid",
                                "email": "user@example.com",
                                "status": "active",
                            },
                        },
                        "profile_incomplete": {
                            "summary": "Profile completion required",
                            "value": {
                                "status": "profile_incomplete",
                                "message": "Please complete your profile",
                                "email": "user@example.com",
                            },
                        },
                    }
                }
            },
        },
    },
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

    Returns:
        - UserRead: If user exists and profile is complete (status=active)
        - ProfileIncompleteResponse: If user needs to complete profile (status=pending)

    Raises:
        - UserInactiveError: If user status is 'inactive'
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

    # Query local user
    user = session.exec(
        select(User).where(User.external_id == firebase_user.uid)
    ).first()

    # If user doesn't exist locally, create with pending status
    if user is None:
        if not firebase_user.email:
            raise BadRequestError("Email not found in Firebase token")

        user = User(
            external_id=firebase_user.uid,
            email=firebase_user.email,
            status=UserStatus.pending,
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    # Check user status
    if user.status == UserStatus.inactive:
        raise UserInactiveError()

    # Set session cookie (needed for both complete and incomplete profiles)
    response.set_cookie(
        key="session",
        value=session_cookie,
        max_age=int(settings.session_expires_in.total_seconds()),
        httponly=True,
        secure=settings.is_secure_cookie,
        samesite="lax",
    )

    # If profile is pending, return profile incomplete response
    if user.status == UserStatus.pending:
        return ProfileIncompleteResponse(email=user.email)

    return user


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
    try:
        reset_link = await firebase_auth.generate_password_reset_link(request.email)
        send_password_reset_email(request.email, reset_link)
    except (UserNotFoundError, AppException, Exception) as e:
        # Log for monitoring, but suppress to prevent email enumeration
        logger.debug(
            "Password reset request failed for email %s: %s",
            request.email,
            str(e),
        )

    return PasswordResetResponse(
        message="If an account with that email exists, a password reset link has been sent"  # noqa: E501
    )


@router.post("/confirm-password-reset", response_model=AuthMessage)
async def confirm_password_reset(
    request: ConfirmPasswordResetRequest,
    firebase_auth: FirebaseAuthDep,
):
    """Confirm password reset using oobCode from email link.

    Uses Firebase Identity Toolkit API to verify oobCode and set new password.
    """
    await firebase_auth.confirm_password_reset(
        oob_code=request.oob_code,
        new_password=request.new_password,
    )

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
    "/complete-profile",
    response_model=UserRead,
    responses={**CommonResponses.UNAUTHORIZED, **CommonResponses.BAD_REQUEST},
)
async def complete_profile(
    profile_data: CompleteProfileRequest,
    user: CurrentUserDep,
    session: SessionDep,
):
    """Complete user profile after Firebase login.

    This endpoint is called when a user logs in via Firebase but doesn't have
    a complete local profile (status='pending').

    Updates the user's first_name, last_name and sets status to 'active'.
    """
    if user.status != UserStatus.pending:
        raise BadRequestError("Profile is already complete")

    user.first_name = profile_data.first_name
    user.last_name = profile_data.last_name
    user.status = UserStatus.active

    session.add(user)
    session.commit()
    session.refresh(user)

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

    try:
        verification_link = await firebase_auth.generate_email_verification_link(
            user.email
        )
        send_email_verification_email(user.email, verification_link)
    except (UserNotFoundError, EmailVerificationError, AppException, Exception) as e:
        # Log for monitoring, but suppress to prevent revealing internal errors
        logger.debug(
            "Verification email request failed for user %s: %s",
            user.id,
            str(e),
        )

    return AuthMessage(message="Verification email sent")


@router.post("/confirm-verification-email", response_model=EmailVerificationResponse)
async def confirm_email_verification(
    request: ConfirmEmailVerificationRequest,
    session: SessionDep,
    firebase_auth: FirebaseAuthDep,
):
    """Confirm verification email using oobCode from email link.

    Uses Firebase Identity Toolkit API to verify oobCode and update email verification status.
    Updates local user's email_verified status if verification email succeeds.
    """  # noqa: E501
    external_id, email_verified = await firebase_auth.confirm_email_verification(
        oob_code=request.oob_code
    )

    if not email_verified:
        return EmailVerificationResponse(
            email_verified=False,
            message="Email verification failed",
        )

    # Update local user's email_verified status
    user = session.exec(select(User).where(User.external_id == external_id)).first()

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
        firebase_auth.revoke_refresh_tokens(user.external_id)
    except Exception as e:
        raise InternalError("Failed to revoke tokens") from e

    return AuthMessage(message="All tokens have been revoked")


@router.post(
    "/update-password",
    response_model=AuthMessage,
    responses={**CommonResponses.UNAUTHORIZED, **CommonResponses.BAD_REQUEST},
)
async def update_password(
    request: UpdatePasswordRequest,
    user: CurrentUserDep,
    firebase_auth: FirebaseAuthDep,
):
    """Update the current user's password.

    Requires the user to provide their current password for verification,
    then updates to the new password.
    """
    # Re-authenticate user with current password to get fresh ID token
    try:
        firebase_user = await firebase_auth.sign_in_with_email_password(
            email=user.email,
            password=request.current_password,
        )
    except InvalidCredentialsError:
        raise BadRequestError("Current password is incorrect") from None

    if not firebase_user.id_token:
        raise BadRequestError("Failed to verify current password")

    # Update password using the fresh ID token
    await firebase_auth.update_password(
        id_token=firebase_user.id_token,
        new_password=request.new_password,
    )

    return AuthMessage(message="Password updated successfully")


@router.post(
    "/request-email-change",
    response_model=AuthMessage,
    responses={**CommonResponses.UNAUTHORIZED, **CommonResponses.CONFLICT},
)
async def request_email_change(
    request: RequestEmailChangeRequest,
    user: CurrentUserDep,
    session: SessionDep,
    firebase_auth: FirebaseAuthDep,
):
    """Request an email change for the current user.

    Requires re-authentication with current password for security.
    Sends a verification email to the new email address.
    """
    # Check if new email is already taken in local database
    email_exists = session.exec(
        select(User).where(User.email == request.new_email)
    ).first()

    if email_exists:
        raise EmailExistsError("Email already in use")

    # Re-authenticate to get a fresh ID token (same pattern as update_password)
    try:
        firebase_user = await firebase_auth.sign_in_with_email_password(
            email=user.email,
            password=request.current_password,
        )
    except InvalidCredentialsError:
        raise BadRequestError("Current password is incorrect") from None

    if not firebase_user.id_token:
        raise BadRequestError("Failed to verify current password")

    # Generate email change link
    email_change_link = await firebase_auth.generate_email_change_link(
        id_token=firebase_user.id_token,
        current_email=user.email,
        new_email=request.new_email,
    )

    # Send verification to CURRENT email to validate ownership
    send_email_change_verification_email(
        to_email=user.email,
        new_email=request.new_email,
        firebase_verification_link=email_change_link,
    )

    return AuthMessage(
        message="A verification link has been sent to your current email address"
    )


@router.post("/confirm-email-change", response_model=AuthMessage)
async def confirm_email_change(
    request: ConfirmEmailChangeRequest,
    session: SessionDep,
    firebase_auth: FirebaseAuthDep,
):
    """Confirm email change using oobCode from verification email.

    Uses Firebase Identity Toolkit API to verify oobCode and update email.
    Updates local user's email after successful verification.
    """
    external_id, new_email = await firebase_auth.confirm_email_change(
        oob_code=request.oob_code
    )

    # Update local user's email
    user = session.exec(select(User).where(User.external_id == external_id)).first()

    if user:
        user.email = new_email
        user.email_verified = True  # Email is verified since they confirmed via link
        session.add(user)
        session.commit()

    return AuthMessage(message="Email changed successfully")
