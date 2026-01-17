from urllib.parse import parse_qs, urlparse

import resend

from app.core.constants import JinjaCompiledEmailTemplatesEnv
from app.core.settings import get_settings


def _render_template(template_name: str, **context: str) -> str:
    """Render a pre-compiled email template.

    Templates are pre-compiled with CSS inlined and HTML minified.
    Run `make compile-emails` after modifying source templates.

    Args:
        template_name: Name of the template file
        **context: Template variables

    Returns:
        Rendered HTML
    """
    template = JinjaCompiledEmailTemplatesEnv.get_template(template_name)
    return template.render(**context)


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

    html_content = _render_template("password-reset.html", reset_url=reset_url)

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Reset Your Password",
            "html": html_content,
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

    html_content = _render_template(
        "email-verification.html", verification_url=verification_url
    )

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Verify Your Email",
            "html": html_content,
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

    html_content = _render_template(
        "email-change-verification.html",
        new_email=new_email,
        verification_url=verification_url,
    )

    resend.Emails.send(
        {
            "from": from_email,
            "to": to_email,
            "subject": "FastBack - Confirm Email Change",
            "html": html_content,
        }
    )
