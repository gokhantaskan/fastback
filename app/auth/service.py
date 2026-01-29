"""Firebase Authentication Service.

This module provides a clean abstraction over Firebase Admin SDK and
Identity Toolkit REST API for authentication operations.

Follows Single Responsibility Principle - handles only Firebase auth communication.
"""

import contextlib
import re
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Any, Protocol

import firebase_admin
import httpx
from firebase_admin import auth as firebase_admin_auth
from firebase_admin.exceptions import FirebaseError

from app.auth.exceptions import (
    EmailChangeError,
    EmailVerificationError,
    InvalidCredentialsError,
    PasswordPolicyError,
    SessionCookieError,
    UserDisabledError,
    WeakPasswordError,
)
from app.auth.identity_toolkit import (
    IDENTITY_TOOLKIT_ENDPOINTS,
    SignInWithPasswordResponse,
    UpdateAccountResponse,
)
from app.core.exceptions import (
    AppException,
    ProviderError,
    RateLimitError,
)
from app.core.http import get_firebase_client
from app.core.retry import with_retry
from app.user.exceptions import (
    EmailExistsError,
    UserNotFoundError,
)

_INVALID_CREDENTIALS_MESSAGES = {
    "EMAIL_NOT_FOUND",
    "INVALID_PASSWORD",
    "INVALID_LOGIN_CREDENTIALS",
}


@dataclass(frozen=True)
class FirebaseUser:
    """Represents authenticated Firebase user data."""

    uid: str
    email: str | None = None
    id_token: str | None = None


@dataclass(frozen=True)
class FirebaseUserRecord:
    """Represents full Firebase user record data."""

    uid: str
    email: str | None = None
    email_verified: bool = False


@dataclass(frozen=True)
class TokenClaims:
    """Decoded token claims from Firebase."""

    uid: str
    email: str | None = None


class FirebaseAuthServiceProtocol(Protocol):
    """Protocol for Firebase authentication operations.

    Enables dependency inversion - code depends on this protocol,
    not the concrete implementation.
    """

    async def sign_in_with_email_password(
        self, email: str, password: str
    ) -> FirebaseUser:
        """Authenticate user with email/password via Identity Toolkit."""
        ...

    def create_session_cookie(self, id_token: str, expires_in: timedelta) -> str:
        """Create a session cookie from ID token."""
        ...

    def verify_session_cookie(
        self, session_cookie: str, check_revoked: bool = True
    ) -> TokenClaims:
        """Verify session cookie and return claims."""
        ...

    def verify_id_token(self, id_token: str) -> TokenClaims:
        """Verify ID token and return claims."""
        ...

    def revoke_refresh_tokens(self, uid: str) -> None:
        """Revoke all refresh tokens for a user."""
        ...

    def logout(self, session_cookie: str) -> None:
        """Logout user by revoking their refresh tokens."""
        ...

    def create_user(self, email: str, password: str) -> FirebaseUser:
        """Create a new Firebase user."""
        ...

    def delete_user(self, uid: str) -> None:
        """Delete a Firebase user (best-effort, errors suppressed)."""
        ...

    async def generate_password_reset_link(self, email: str) -> str:
        """Generate a password reset link for a user."""
        ...

    async def generate_email_verification_link(self, email: str) -> str:
        """Generate an email verification link for a user."""
        ...

    def get_user(self, uid: str) -> FirebaseUserRecord:
        """Get Firebase user record by UID."""
        ...

    async def update_password(self, id_token: str, new_password: str) -> None:
        """Update user's password using ID token."""
        ...

    async def generate_email_change_link(
        self, id_token: str, current_email: str, new_email: str
    ) -> str:
        """Generate an email change verification link."""
        ...

    async def confirm_password_reset(self, oob_code: str, new_password: str) -> None:
        """Confirm password reset using oobCode from email."""
        ...

    async def confirm_email_verification(self, oob_code: str) -> tuple[str, bool]:
        """Confirm email verification using oobCode. Returns (external_id, email_verified)."""  # noqa: E501
        ...

    async def confirm_email_change(self, oob_code: str) -> tuple[str, str]:
        """Confirm email change using oobCode. Returns (external_id, new_email)."""
        ...


class FirebaseAuthService:
    """Firebase Authentication Service implementation.

    Handles all Firebase authentication operations including:
    - Email/password sign-in via Identity Toolkit REST API
    - Session cookie creation and verification
    - ID token verification
    - Token revocation
    """

    def __init__(
        self,
        api_key: str | None,
        identity_toolkit_base_url: str = "https://identitytoolkit.googleapis.com",
    ):
        self._api_key = api_key
        self._identity_toolkit_base_url = identity_toolkit_base_url

    def _ensure_api_key(self) -> str:
        """Ensure API key is configured."""
        if not self._api_key:
            raise AppException("Firebase API key not configured")
        return self._api_key

    async def _make_identity_toolkit_request(
        self, endpoint: str, payload: dict[str, Any], *, retry: bool = False
    ) -> dict[str, Any]:
        """Make a request to Identity Toolkit REST API.

        Args:
            endpoint: API endpoint path (e.g., "v1/accounts:signInWithPassword")
            payload: Request payload
            retry: Whether to retry on transient network errors

        Returns:
            Response JSON data

        Raises:
            InvalidCredentialsError: If email/password invalid
            UserDisabledError: If user account is disabled
            RateLimitError: If rate limit exceeded
            ProviderError: If upstream returns unexpected response
        """
        api_key = self._ensure_api_key()
        url = f"{self._identity_toolkit_base_url}/{endpoint}?key={api_key}"
        client = get_firebase_client()

        async def do_request() -> httpx.Response:
            return await client.post(url, json=payload)

        # Always use with_retry for consistent error handling.
        # When retry=False, attempts=1 means no retries but still catches RequestError.
        try:
            response = await with_retry(
                do_request,
                # 2 attempts = 1 initial try + 1 retry on failure
                attempts=2 if retry else 1,
                exceptions=(httpx.RequestError,),
            )
        except httpx.RequestError as e:
            raise ProviderError("Authentication provider unavailable") from e

        if response.status_code != 200:
            self._handle_identity_toolkit_error(response)

        return response.json()

    @staticmethod
    def _get_admin_access_token() -> str:
        """Get access token from Firebase Admin SDK credentials.

        This provides service account authentication which has elevated
        permissions compared to API key authentication.

        Returns:
            Access token string

        Raises:
            AppException: If Firebase Admin SDK is not initialized
        """
        try:
            app = firebase_admin.get_app()
            credential = app.credential
            access_token_info = credential.get_access_token()
            return access_token_info.access_token
        except ValueError as e:
            raise AppException("Firebase Admin SDK not initialized") from e

    async def _make_admin_identity_toolkit_request(
        self, endpoint: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Make a request to Identity Toolkit REST API using Admin SDK credentials.

        Uses service account authentication which has elevated permissions
        for operations like returnOobLink.

        Args:
            endpoint: API endpoint path (e.g., "v1/accounts:sendOobCode")
            payload: Request payload

        Returns:
            Response JSON data

        Raises:
            InvalidCredentialsError: If authentication fails
            ProviderError: If upstream returns unexpected response
        """
        access_token = self._get_admin_access_token()
        url = f"{self._identity_toolkit_base_url}/{endpoint}"
        client = get_firebase_client()

        try:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except httpx.RequestError as e:
            raise ProviderError("Authentication provider unavailable") from e

        if response.status_code != 200:
            self._handle_identity_toolkit_error(response)

        return response.json()

    @staticmethod
    def _parse_retry_after(value: str | None) -> int | None:
        """Parse Retry-After header into seconds."""
        if not value:
            return None
        with contextlib.suppress(ValueError):
            parsed = int(value)
            if parsed >= 0:
                return parsed
        return None

    def _raise_rate_limit_error(
        self, response: httpx.Response, cause: BaseException | None = None
    ) -> None:
        """Raise RateLimitError with Retry-After header parsed from response.

        Args:
            response: HTTP response containing potential Retry-After header
            cause: Optional exception to chain with 'from'

        Raises:
            RateLimitError: Always raises with parsed retry_after value
        """
        retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
        error = RateLimitError(
            "Too many attempts, try again later", retry_after=retry_after
        )
        if cause:
            raise error from cause
        raise error

    @staticmethod
    def _sanitize_error_code(error_message: str) -> str:
        """Extract a safe, non-sensitive error code for logging."""
        match = re.match(r"[A-Z0-9_]+", error_message)
        return match.group(0) if match else "UNKNOWN"

    def _handle_identity_toolkit_error(self, response: httpx.Response) -> None:
        """Handle error response from Identity Toolkit REST API."""
        import logging

        logger = logging.getLogger(__name__)

        try:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", "Unknown error")
        except ValueError as e:
            if response.status_code == 429:
                self._raise_rate_limit_error(response, cause=e)
            raise ProviderError(
                "Authentication provider returned an invalid response"
            ) from e

        # Log sanitized error code for debugging (avoid sensitive data)
        error_code = self._sanitize_error_code(error_message)
        logger.info(
            "Identity Toolkit error: status=%s, code=%s",
            response.status_code,
            error_code,
        )

        # Handle HTTP 429 explicitly
        if response.status_code == 429:
            self._raise_rate_limit_error(response)

        if error_message in _INVALID_CREDENTIALS_MESSAGES:
            raise InvalidCredentialsError("Invalid email or password")

        if error_message == "USER_DISABLED":
            raise UserDisabledError("User account is disabled")

        if error_message == "TOO_MANY_ATTEMPTS_TRY_LATER":
            self._raise_rate_limit_error(response)

        # Check PASSWORD_DOES_NOT_MEET_REQUIREMENTS before WEAK_PASSWORD
        # (more specific first)
        if "PASSWORD_DOES_NOT_MEET_REQUIREMENTS" in error_message:
            requirements = self._extract_password_requirements(error_message)
            raise PasswordPolicyError(
                "Password does not meet requirements",
                requirements=requirements,
            )

        if "WEAK_PASSWORD" in error_message:
            raise WeakPasswordError("Password is too weak")

        if "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" in error_message:
            raise InvalidCredentialsError(
                "Session expired, please login again to continue"
            )

        if "TOKEN_EXPIRED" in error_message or "INVALID_ID_TOKEN" in error_message:
            raise InvalidCredentialsError("Session expired, please login again")

        if "EMAIL_EXISTS" in error_message:
            from app.user.exceptions import EmailExistsError

            raise EmailExistsError("Email already in use")

        # OOB code errors (password reset, email verification, email change)
        if "EXPIRED_OOB_CODE" in error_message:
            raise ProviderError("EXPIRED_OOB_CODE")

        if "INVALID_OOB_CODE" in error_message:
            raise ProviderError("INVALID_OOB_CODE")

        if response.status_code in {400, 401, 403}:
            raise InvalidCredentialsError("Authentication failed")

        raise ProviderError(f"Authentication failed: {error_message}")

    async def sign_in_with_email_password(
        self, email: str, password: str
    ) -> FirebaseUser:
        """Authenticate user with email/password via Identity Toolkit.

        Args:
            email: User's email address
            password: User's password

        Returns:
            FirebaseUser with uid, email, and id_token

        Raises:
            InvalidCredentialsError: If email/password invalid
            UserDisabledError: If user account is disabled
            RateLimitError: If rate limit exceeded
            ProviderError: If upstream returns unexpected response
        """
        # https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword
        data: SignInWithPasswordResponse = await self._make_identity_toolkit_request(
            endpoint=IDENTITY_TOOLKIT_ENDPOINTS["signInWithPassword"],
            payload={
                "email": email,
                "password": password,
                "returnSecureToken": True,
            },
            retry=True,
        )

        id_token = data.get("idToken")
        uid = data.get("localId")
        user_email = data.get("email")

        if not id_token or not uid:
            raise InvalidCredentialsError("Authentication failed")

        return FirebaseUser(uid=uid, email=user_email, id_token=id_token)

    def create_session_cookie(self, id_token: str, expires_in: timedelta) -> str:
        """Create a session cookie from ID token.

        Args:
            id_token: Firebase ID token
            expires_in: Cookie expiration time (1 day to 2 weeks)

        Returns:
            Session cookie string

        Raises:
            SessionCookieError: If cookie creation fails
        """
        try:
            return firebase_admin_auth.create_session_cookie(
                id_token, expires_in=expires_in
            )
        except (ValueError, FirebaseError) as e:
            raise SessionCookieError("Failed to create session cookie") from e

    @staticmethod
    def _extract_token_claims(
        decoded: dict[str, Any], allow_sub: bool = False
    ) -> TokenClaims:
        """Extract uid and email from decoded token claims.

        Args:
            decoded: Decoded token dictionary
            allow_sub: Whether to accept 'sub' as uid fallback

        Returns:
            TokenClaims with uid and email

        Raises:
            AppException: If uid is missing
        """
        uid = decoded.get("uid")
        if allow_sub and not uid:
            uid = decoded.get("sub")

        if not uid:
            raise AppException("Invalid token: missing uid")

        return TokenClaims(uid=uid, email=decoded.get("email"))

    def verify_session_cookie(
        self, session_cookie: str, check_revoked: bool = True
    ) -> TokenClaims:
        """Verify session cookie and return claims.

        Args:
            session_cookie: Session cookie string
            check_revoked: Whether to check if token was revoked

        Returns:
            TokenClaims with uid and email

        Raises:
            SessionCookieError: If verification fails
        """
        try:
            decoded = firebase_admin_auth.verify_session_cookie(
                session_cookie, check_revoked=check_revoked
            )
            return self._extract_token_claims(decoded, allow_sub=True)
        except FirebaseError as e:
            raise SessionCookieError("Invalid session cookie") from e
        except AppException as e:
            raise SessionCookieError(str(e)) from e

    def verify_id_token(self, id_token: str) -> TokenClaims:
        """Verify ID token and return claims.

        Args:
            id_token: Firebase ID token

        Returns:
            TokenClaims with uid and email

        Raises:
            AppException: If verification fails
        """
        try:
            decoded = firebase_admin_auth.verify_id_token(id_token)
            return self._extract_token_claims(decoded, allow_sub=False)
        except (ValueError, FirebaseError) as e:
            raise AppException("Invalid ID token") from e

    def revoke_refresh_tokens(self, uid: str) -> None:
        """Revoke all refresh tokens for a user.

        Args:
            uid: Firebase user UID

        Note:
            Silently ignores errors as this is typically best-effort.
        """
        with contextlib.suppress(FirebaseError):
            firebase_admin_auth.revoke_refresh_tokens(uid)

    def logout(self, session_cookie: str) -> None:
        """Logout user by revoking their refresh tokens.

        Args:
            session_cookie: The session cookie to invalidate

        Note:
            This method verifies the session cookie and revokes all refresh tokens.
            Cookie clearing should be handled at the router level.
            Silently succeeds if cookie is invalid (user already logged out).
        """
        try:
            claims = self.verify_session_cookie(session_cookie, check_revoked=False)
            self.revoke_refresh_tokens(claims.uid)
        except SessionCookieError:
            # Invalid cookie - user is effectively logged out already
            pass

    def delete_user(self, uid: str) -> None:
        """Delete a Firebase user (best-effort, errors suppressed).

        Args:
            uid: Firebase user UID

        Note:
            Silently ignores errors as this is typically used for rollback.
        """
        with contextlib.suppress(FirebaseError):
            firebase_admin_auth.delete_user(uid)

    @staticmethod
    def _extract_password_requirements(error_message: str) -> list[str]:
        """Extract password requirements from Firebase error message.

        Args:
            error_message: The Firebase error message containing requirements

        Returns:
            List of missing password requirements
        """
        match = re.search(r"Missing password requirements: \[([^\]]+)\]", error_message)
        if match:
            requirements_str = match.group(1)
            return [req.strip() for req in requirements_str.split(",")]
        return []

    @staticmethod
    def _handle_firebase_error(
        error: FirebaseError,
        error_mappings: dict[str, type[AppException] | tuple[type[AppException], str]],
        default_error: type[AppException] | None = None,
        default_message: str = "Firebase operation failed",
    ) -> None:
        """Handle Firebase Admin SDK errors and map to custom exceptions.

        Args:
            error: The FirebaseError that was raised
            error_mappings: Dict mapping error codes/messages to exception classes or (class, message) tuples
            default_error: Default exception class if no mapping matches
            default_message: Default error message

        Raises:
            Appropriate AppException subclass based on error mappings
        """  # noqa: E501
        error_message = str(error)
        error_code = getattr(error, "code", None)

        # Check error code first (more specific)
        if error_code and error_code in error_mappings:
            mapping = error_mappings[error_code]
            if isinstance(mapping, tuple):
                exc_class, msg = mapping
                raise exc_class(msg) from error
            else:
                raise mapping(default_message) from error

        # Check if any mapped string appears in error message
        for key, mapping in error_mappings.items():
            if key in error_message:
                if isinstance(mapping, tuple):
                    exc_class, msg = mapping
                    raise exc_class(msg) from error
                else:
                    raise mapping(default_message) from error

        # Default error handling
        if default_error:
            raise default_error(default_message) from error
        raise AppException(default_message) from error

    def create_user(self, email: str, password: str) -> FirebaseUser:
        """Create a new Firebase user.

        Args:
            email: User's email address
            password: User's password

        Returns:
            FirebaseUser with uid and email

        Raises:
            EmailExistsError: If email already registered
            WeakPasswordError: If password doesn't meet requirements
            PasswordPolicyError: If password doesn't meet policy requirements
            AppException: For other Firebase errors
        """
        try:
            firebase_user = firebase_admin_auth.create_user(
                email=email, password=password
            )
            return FirebaseUser(uid=firebase_user.uid, email=email)
        except FirebaseError as e:
            error_message = str(e)

            # Handle password policy errors with requirements extraction
            if "PASSWORD_DOES_NOT_MEET_REQUIREMENTS" in error_message:
                requirements = self._extract_password_requirements(error_message)
                raise PasswordPolicyError(
                    "Password does not meet requirements",
                    requirements=requirements,
                ) from e

            self._handle_firebase_error(
                error=e,
                error_mappings={
                    "EMAIL_EXISTS": (EmailExistsError, "Email already registered"),
                    "EMAIL_ALREADY_EXISTS": (
                        EmailExistsError,
                        "Email already registered",
                    ),
                    "WEAK_PASSWORD": (WeakPasswordError, "Password is too weak"),
                    "INVALID_PASSWORD": (WeakPasswordError, "Password is too weak"),
                },
                default_error=AppException,
                default_message="Failed to create user",
            )

    async def generate_password_reset_link(self, email: str) -> str:
        """Generate a password reset link for a user.

        Uses Identity Toolkit sendOobCode API with Admin SDK credentials.

        Args:
            email: User's email address

        Returns:
            Password reset URL string

        Raises:
            UserNotFoundError: If email not found in Firebase
            AppException: For other Firebase errors
        """
        try:
            data = await self._make_admin_identity_toolkit_request(
                endpoint=IDENTITY_TOOLKIT_ENDPOINTS["sendOobCode"],
                payload={
                    "requestType": "PASSWORD_RESET",
                    "email": email,
                    "returnOobLink": True,
                },
            )
        except ProviderError as e:
            error_str = str(e)
            if "EMAIL_NOT_FOUND" in error_str or "USER_NOT_FOUND" in error_str:
                raise UserNotFoundError("User not found") from e
            raise AppException("Failed to generate password reset link") from e

        oob_link = data.get("oobLink")
        if not oob_link:
            raise AppException("Failed to generate password reset link")

        return oob_link

    async def generate_email_verification_link(self, email: str) -> str:
        """Generate an email verification link for a user.

        Uses Identity Toolkit sendOobCode API with Admin SDK credentials.

        Args:
            email: User's email address

        Returns:
            Email verification URL string

        Raises:
            UserNotFoundError: If email not found in Firebase
            EmailVerificationError: For other verification errors
        """
        try:
            data = await self._make_admin_identity_toolkit_request(
                endpoint=IDENTITY_TOOLKIT_ENDPOINTS["sendOobCode"],
                payload={
                    "requestType": "VERIFY_EMAIL",
                    "email": email,
                    "returnOobLink": True,
                },
            )
        except ProviderError as e:
            error_str = str(e)
            if "EMAIL_NOT_FOUND" in error_str or "USER_NOT_FOUND" in error_str:
                raise UserNotFoundError("User not found") from e
            raise EmailVerificationError(
                "Failed to generate email verification link"
            ) from e

        oob_link = data.get("oobLink")
        if not oob_link:
            raise EmailVerificationError("Failed to generate email verification link")

        return oob_link

    def get_user(self, uid: str) -> FirebaseUserRecord:
        """Get Firebase user record by UID.

        Args:
            uid: Firebase user UID

        Returns:
            FirebaseUserRecord with uid, email, and email_verified status

        Raises:
            UserNotFoundError: If user not found in Firebase
            AppException: For other Firebase errors
        """
        try:
            user = firebase_admin_auth.get_user(uid)
            return FirebaseUserRecord(
                uid=user.uid,
                email=user.email,
                email_verified=user.email_verified,
            )
        except FirebaseError as e:
            self._handle_firebase_error(
                error=e,
                error_mappings={
                    "USER_NOT_FOUND": (UserNotFoundError, "User not found")
                },
                default_error=AppException,
                default_message="Failed to get user",
            )

    async def update_password(self, id_token: str, new_password: str) -> None:
        """Update user's password using Identity Toolkit.

        Args:
            id_token: Firebase ID token for the authenticated user
            new_password: The new password to set

        Raises:
            WeakPasswordError: If password doesn't meet requirements
            PasswordPolicyError: If password doesn't meet policy requirements
            InvalidCredentialsError: If token is invalid
            ProviderError: If upstream returns unexpected response
        """
        data: UpdateAccountResponse = await self._make_identity_toolkit_request(
            endpoint=IDENTITY_TOOLKIT_ENDPOINTS["update"],
            payload={
                "idToken": id_token,
                "password": new_password,
                "returnSecureToken": True,
            },
        )

        if not data.get("localId"):
            raise ProviderError("Failed to update password")

    async def generate_email_change_link(
        self, id_token: str, current_email: str, new_email: str
    ) -> str:
        """Generate an email change verification link.

        Uses sendOobCode with VERIFY_AND_CHANGE_EMAIL request type.
        Uses Admin SDK credentials for elevated permissions required by returnOobLink.

        Args:
            id_token: Firebase ID token for the authenticated user
            current_email: The user's current email address
            new_email: The new email address to change to

        Returns:
            Email change verification URL string

        Raises:
            InvalidCredentialsError: If token is invalid
            ProviderError: If upstream returns unexpected response
        """
        data = await self._make_admin_identity_toolkit_request(
            endpoint=IDENTITY_TOOLKIT_ENDPOINTS["sendOobCode"],
            payload={
                "requestType": "VERIFY_AND_CHANGE_EMAIL",
                "idToken": id_token,
                "email": current_email,
                "newEmail": new_email,
                "returnOobLink": True,
            },
        )

        oob_link = data.get("oobLink")
        if not oob_link:
            raise ProviderError("Failed to generate email change link")

        return oob_link

    async def confirm_password_reset(self, oob_code: str, new_password: str) -> None:
        """Confirm password reset using oobCode from email.

        Args:
            oob_code: Out-of-band code from password reset email
            new_password: The new password to set

        Raises:
            BadRequestError: If oobCode is expired or invalid
            WeakPasswordError: If password doesn't meet requirements
            ProviderError: If upstream returns unexpected response
        """
        from app.core.exceptions import BadRequestError

        try:
            await self._make_identity_toolkit_request(
                endpoint=IDENTITY_TOOLKIT_ENDPOINTS["resetPassword"],
                payload={
                    "oobCode": oob_code,
                    "newPassword": new_password,
                },
            )
        except ProviderError as e:
            error_str = str(e)
            if "EXPIRED_OOB_CODE" in error_str:
                raise BadRequestError("Password reset link has expired") from e
            if "INVALID_OOB_CODE" in error_str:
                raise BadRequestError("Invalid password reset link") from e
            raise

    async def confirm_email_verification(self, oob_code: str) -> tuple[str, bool]:
        """Confirm email verification using oobCode from email.

        Args:
            oob_code: Out-of-band code from verification email

        Returns:
            Tuple of (external_id, email_verified)

        Raises:
            EmailVerificationError: If oobCode is expired, invalid, or fails
            InternalError: If response is missing required fields
        """
        from app.core.exceptions import InternalError

        try:
            data: UpdateAccountResponse = await self._make_identity_toolkit_request(
                endpoint=IDENTITY_TOOLKIT_ENDPOINTS["update"],
                payload={"oobCode": oob_code},
            )
        except ProviderError as e:
            error_str = str(e)
            if "EXPIRED_OOB_CODE" in error_str:
                raise EmailVerificationError(
                    "Email verification link has expired"
                ) from e
            if "INVALID_OOB_CODE" in error_str:
                raise EmailVerificationError("Invalid email verification link") from e
            raise EmailVerificationError("Failed to verify email") from e

        external_id = data.get("localId")
        email_verified = data.get("emailVerified", False)

        if not external_id:
            raise InternalError("Failed to get user ID from verification response")

        return external_id, email_verified

    async def confirm_email_change(self, oob_code: str) -> tuple[str, str]:
        """Confirm email change using oobCode from verification email.

        Args:
            oob_code: Out-of-band code from email change verification email

        Returns:
            Tuple of (external_id, new_email)

        Raises:
            EmailChangeError: If oobCode is expired, invalid, or change fails
            InternalError: If response is missing required fields
        """
        from app.core.exceptions import InternalError

        try:
            data: UpdateAccountResponse = await self._make_identity_toolkit_request(
                endpoint=IDENTITY_TOOLKIT_ENDPOINTS["update"],
                payload={"oobCode": oob_code},
            )
        except ProviderError as e:
            error_str = str(e)
            if "EXPIRED_OOB_CODE" in error_str:
                raise EmailChangeError("Email change link has expired") from e
            if "INVALID_OOB_CODE" in error_str:
                raise EmailChangeError("Invalid email change link") from e
            raise EmailChangeError("Failed to change email") from e

        external_id = data.get("localId")
        new_email = data.get("email")

        if not external_id or not new_email:
            raise InternalError("Failed to get user info from email change response")

        return external_id, new_email


@lru_cache
def get_firebase_auth_service() -> FirebaseAuthService:
    """Get cached Firebase Auth Service instance.

    The service is cached for the application lifetime since
    its configuration doesn't change at runtime.
    """
    from app.core.settings import Settings, get_settings

    settings: Settings = get_settings()
    return FirebaseAuthService(
        api_key=settings.firebase_api_key,
        identity_toolkit_base_url=settings.identity_toolkit_base_url,
    )
