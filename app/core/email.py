from urllib.parse import parse_qs, urlparse

import resend

from app.core.settings import get_settings


def init_resend() -> None:
    """Initialize Resend with API key if available."""
    settings = get_settings()
    if not settings.resend_api_key:
        return
    resend.api_key = settings.resend_api_key


def _extract_oob_code(firebase_link: str) -> str | None:
    """Extract oobCode from Firebase link (password reset or email verification).

    Firebase links look like:
    https://app.firebaseapp.com/__/auth/action?mode=resetPassword&oobCode=ABC123...
    https://app.firebaseapp.com/__/auth/action?mode=verifyEmail&oobCode=ABC123...
    """
    parsed = urlparse(firebase_link)
    params = parse_qs(parsed.query)
    oob_codes = params.get("oobCode", [])
    return oob_codes[0] if oob_codes else None


def send_password_reset_email(to_email: str, firebase_reset_link: str) -> None:
    """Send password reset email via Resend.

    Args:
        to_email: Recipient email address
        firebase_reset_link: Firebase password reset link (oobCode will be extracted)
    """
    settings = get_settings()

    # Email domain
    from_email = f"noreply@{settings.app_domain}"

    # Extract oobCode and build custom reset URL
    oob_code = _extract_oob_code(firebase_reset_link)
    reset_url = f"{settings.client_url}/auth/reset-password?oobCode={oob_code}"

    # DEBUG
    print("================================================")
    print(f"OOB Code: {oob_code}")
    print(f"Reset URL: {reset_url}")
    print("================================================")

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Reset Your Password",
            "html": f"""
                <h2>Password Reset Request</h2>
                <p>You requested to reset your password for your FastBack account. Click the link below to proceed:</p>
                <p><a href="{reset_url}">Reset Password</a></p>
                <p>If you didn't request this, you can safely ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
            """,  # noqa: E501
        }
    )


def send_email_verification_email(
    to_email: str, firebase_verification_link: str
) -> None:
    """Send email verification email via Resend.

    Args:
        to_email: Recipient email address
        firebase_verification_link: Firebase email verification link (oobCode will be extracted)
    """  # noqa: E501
    settings = get_settings()

    # Email domain
    from_email = f"noreply@{settings.app_domain}"

    # Extract oobCode and build custom verification URL
    oob_code = _extract_oob_code(firebase_verification_link)
    verification_url = f"{settings.client_url}/auth/verify-email?oobCode={oob_code}"

    # DEBUG
    print("================================================")
    print(f"OOB Code: {oob_code}")
    print(f"Verification URL: {verification_url}")
    print("================================================")

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Verify Your Email",
            "html": f"""
                <h2>Verify Your Email Address</h2>
                <p>Thank you for signing up for FastBack! Please verify your email address by clicking the link below:</p>
                <p><a href="{verification_url}">Verify Email</a></p>
                <p>If you didn't create an account, you can safely ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
            """,  # noqa: E501
        }
    )


def send_email_change_verification_email(
    *, to_email: str, new_email: str, firebase_verification_link: str
) -> None:
    """Send email change verification email via Resend.

    Args:
        to_email: Current email address on file (recipient for security verification)
        new_email: Requested new email address
        firebase_verification_link: Firebase email change link (oobCode is extracted)
    """
    settings = get_settings()

    # Email domain
    from_email = f"noreply@{settings.app_domain}"

    # Extract oobCode and build custom verification URL
    oob_code = _extract_oob_code(firebase_verification_link)
    verification_url = (
        f"{settings.client_url}/auth/confirm-email-change?oobCode={oob_code}"  # noqa: E501
    )

    # DEBUG
    print("================================================")
    print(f"OOB Code: {oob_code}")
    print(f"Email Change URL: {verification_url}")
    print("================================================")

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Confirm Email Change",
            "html": f"""
                <h2>Confirm Email Address Change</h2>
                <p>You requested to change your email address to {new_email} for your FastBack account. Click the link below to confirm:</p>
                <p><a href="{verification_url}">Confirm Email Change</a></p>
                <p>If you didn't request this change, please secure your account immediately.</p>
                <p>This link will expire in 1 hour.</p>
            """,  # noqa: E501
        }
    )
