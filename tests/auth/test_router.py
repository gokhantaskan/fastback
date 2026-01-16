"""Tests for auth domain router."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.auth.exceptions import (
    InvalidCredentialsError,
    SessionCookieError,
    UserDisabledError,
)
from app.auth.service import (
    FirebaseAuthService,
    FirebaseUser,
    TokenClaims,
    get_firebase_auth_service,
)
from app.core.exceptions import ProviderError, RateLimitError
from app.core.settings import Settings, get_settings
from app.db.engine import get_session
from app.main import app
from app.user.models import User

# --- Helper fixtures ---


def create_mock_firebase_service(
    sign_in_result: FirebaseUser | Exception | None = None,
    session_cookie: str = "mock-session-cookie",
    verify_session_result: TokenClaims | Exception | None = None,
):
    """Create a mock FirebaseAuthService with customizable behavior."""
    mock_service = MagicMock(spec=FirebaseAuthService)

    if sign_in_result is not None:
        if isinstance(sign_in_result, Exception):
            mock_service.sign_in_with_email_password.side_effect = sign_in_result
        else:
            mock_service.sign_in_with_email_password.return_value = sign_in_result

    mock_service.create_session_cookie.return_value = session_cookie

    if verify_session_result is not None:
        if isinstance(verify_session_result, Exception):
            mock_service.verify_session_cookie.side_effect = verify_session_result
        else:
            mock_service.verify_session_cookie.return_value = verify_session_result

    return mock_service


def create_mock_settings(
    firebase_api_key: str | None = "test-api-key",
    session_expires_days: int = 5,
):
    """Create mock settings."""
    return Settings(
        env_name="test",
        database_url="sqlite://",
        session_secret_key="test-secret-key",
        admin_username="admin",
        admin_password="admin",
        session_expires_days=session_expires_days,
        firebase_api_key=firebase_api_key,
        google_id_toolkit_url="https://identitytoolkit.googleapis.com",
    )


# --- POST /auth/register ---


def test_register_new_user(session: Session):
    """Test POST /auth/register creates a new user."""
    from app.auth.service import FirebaseAuthService, FirebaseUser

    external_id = "new-firebase-uid-123"
    email = "newuser@example.com"
    password = "securepassword123"

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.create_user.return_value = FirebaseUser(uid=external_id, email=email)

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "first_name": "New",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 201
    data = response.json()
    assert "message" in data
    assert data["message"] == "User registered successfully"
    mock_service.create_user.assert_called_once_with(email=email, password=password)


def test_register_duplicate_email_local(session: Session, test_user: User):
    """Test POST /auth/register with existing email in local DB returns 409."""
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": test_user.email,
            "password": "somepassword123",
            "first_name": "Test",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 409
    assert "Email already registered" in response.json()["message"]


def test_register_duplicate_email_firebase(session: Session):
    """Test POST /auth/register with existing email in Firebase returns 409."""
    from app.auth.service import FirebaseAuthService
    from app.user.exceptions import EmailExistsError

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.create_user.side_effect = EmailExistsError("Email already registered")

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": "existing@example.com",
            "password": "somepassword123",
            "first_name": "Existing",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 409
    assert "Email already registered" in response.json()["message"]


def test_register_weak_password(session: Session):
    """Test POST /auth/register with weak password returns 400."""
    from app.auth.exceptions import WeakPasswordError
    from app.auth.service import FirebaseAuthService

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.create_user.side_effect = WeakPasswordError("Password is too weak")

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": "new@example.com",
            "password": "123",
            "first_name": "New",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "weak" in response.json()["message"].lower()


def test_register_firebase_error(session: Session):
    """Test POST /auth/register handles generic Firebase errors with 500."""
    from app.auth.service import FirebaseAuthService
    from app.core.exceptions import AppException

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.create_user.side_effect = AppException("Unknown error")

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": "new@example.com",
            "password": "securepassword123",
            "first_name": "New",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 500
    assert "Unknown error" in response.json()["message"]


def test_register_missing_password(session: Session):
    """Test POST /auth/register without password returns 422."""
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={"email": "test@example.com"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 422


def test_register_invalid_email(session: Session):
    """Test POST /auth/register with invalid email returns 422 (Pydantic validation)."""
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={"email": "not-valid-email", "password": "securepassword123"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 422


def test_register_empty_first_name(session: Session):
    """Test POST /auth/register with empty first_name returns 422."""
    from app.auth.service import FirebaseAuthService

    mock_service = MagicMock(spec=FirebaseAuthService)

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "password": "securepassword123",
            "first_name": "",
            "last_name": "User",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 422
    mock_service.create_user.assert_not_called()


def test_register_empty_last_name(session: Session):
    """Test POST /auth/register with empty last_name returns 422."""
    from app.auth.service import FirebaseAuthService

    mock_service = MagicMock(spec=FirebaseAuthService)

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "password": "securepassword123",
            "first_name": "Test",
            "last_name": "",
        },
    )

    app.dependency_overrides.clear()

    assert response.status_code == 422
    mock_service.create_user.assert_not_called()


# --- POST /auth/login ---


def test_login_existing_user(session: Session, test_user: User):
    """Test POST /auth/login with existing user returns user info."""
    mock_service = create_mock_firebase_service(
        sign_in_result=FirebaseUser(
            uid=test_user.external_id,
            email=test_user.email,
            id_token="mock-id-token",
        )
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": test_user.email, "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_user.id)
    assert data["email"] == test_user.email
    assert "session" in response.cookies


def test_login_auto_register_new_user(session: Session):
    """Test POST /auth/login auto-registers new users."""
    external_id = "auto-register-uid"
    email = "autoregister@example.com"

    mock_service = create_mock_firebase_service(
        sign_in_result=FirebaseUser(
            uid=external_id,
            email=email,
            id_token="mock-id-token",
        )
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": email, "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email


def test_login_inactive_user(session: Session, inactive_user: User):
    """Test POST /auth/login with inactive user returns 403."""
    mock_service = create_mock_firebase_service(
        sign_in_result=FirebaseUser(
            uid=inactive_user.external_id,
            email=inactive_user.email,
            id_token="mock-id-token",
        )
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": inactive_user.email, "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 403
    assert "inactive" in response.json()["message"]


def test_login_no_email_in_token_new_user(session: Session):
    """Test POST /auth/login without email in token for new user returns 400."""
    mock_service = create_mock_firebase_service(
        sign_in_result=FirebaseUser(
            uid="no-email-uid",
            email=None,  # No email
            id_token="mock-id-token",
        )
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "Email not found" in response.json()["message"]


def test_login_invalid_credentials(session: Session):
    """Test POST /auth/login with invalid credentials returns 401."""
    mock_service = create_mock_firebase_service(
        sign_in_result=InvalidCredentialsError("Invalid email or password")
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "bad"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 401


def test_login_user_disabled(session: Session):
    """Test POST /auth/login with disabled user returns 403."""
    mock_service = create_mock_firebase_service(
        sign_in_result=UserDisabledError("User is disabled")
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 403


def test_login_rate_limited(session: Session):
    """Test POST /auth/login when rate limited returns 429."""
    mock_service = create_mock_firebase_service(
        sign_in_result=RateLimitError("Too many attempts")
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 429


def test_login_provider_error(session: Session):
    """Test POST /auth/login handles provider errors with 502."""
    mock_service = create_mock_firebase_service(
        sign_in_result=ProviderError("Provider returned invalid response")
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 502


def test_login_session_cookie_error(session: Session, test_user: User):
    """Test POST /auth/login handles session cookie creation failure."""
    mock_service = create_mock_firebase_service(
        sign_in_result=FirebaseUser(
            uid=test_user.external_id,
            email=test_user.email,
            id_token="mock-id-token",
        )
    )
    mock_service.create_session_cookie.side_effect = SessionCookieError(
        "Failed to create session"
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    app.dependency_overrides[get_settings] = lambda: create_mock_settings()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        json={"email": test_user.email, "password": "pw"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 401
    assert "Failed to create session" in response.json()["message"]


# --- POST /auth/logout ---


def test_logout(
    client: TestClient,
    mock_firebase_auth: MagicMock,
):
    """Test POST /auth/logout returns success message."""
    mock_firebase_auth.verify_session_cookie.return_value = TokenClaims(uid="uid")

    client.cookies.set("session", "mock-session-cookie")
    response = client.post("/auth/logout")

    assert response.status_code == 200
    assert response.json()["message"] == "Logout successful"


def test_logout_unauthenticated(unauthenticated_client: TestClient):
    """Test POST /auth/logout without cookie returns 401."""
    response = unauthenticated_client.post("/auth/logout")

    assert response.status_code == 401


# --- POST /auth/request-password-reset ---


def test_reset_password(session: Session):
    """Test POST /auth/request-password-reset returns success message."""
    from app.auth.service import FirebaseAuthService

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.generate_password_reset_link.return_value = "https://example.com/reset"

    with patch("app.auth.router.send_password_reset_email") as mock_send:
        mock_send.return_value = None

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
        client = TestClient(app)

        response = client.post(
            "/auth/request-password-reset",
            json={"email": "test@example.com"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "password reset link has been sent" in response.json()["message"]
    mock_send.assert_called_once_with("test@example.com", "https://example.com/reset")


def test_reset_password_nonexistent_email(session: Session):
    """Test POST /auth/request-password-reset with nonexistent email still returns success."""  # noqa: E501
    from app.auth.service import FirebaseAuthService
    from app.user.exceptions import UserNotFoundError

    mock_service = MagicMock(spec=FirebaseAuthService)
    mock_service.generate_password_reset_link.side_effect = UserNotFoundError(
        "User not found"
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_firebase_auth_service] = lambda: mock_service
    client = TestClient(app)

    response = client.post(
        "/auth/request-password-reset",
        json={"email": "nonexistent@example.com"},
    )

    app.dependency_overrides.clear()

    # Should still return 200 to prevent email enumeration
    assert response.status_code == 200


def test_reset_password_invalid_email(session: Session):
    """Test POST /auth/request-password-reset with invalid email format returns 422."""
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)

    response = client.post(
        "/auth/request-password-reset",
        json={"email": "not-an-email"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 422


# --- POST /auth/confirm-password-reset ---


def test_confirm_password_reset(session: Session):
    """Test POST /auth/confirm-password-reset with valid oobCode succeeds."""
    from unittest.mock import AsyncMock

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"email": "test@example.com"}

    with patch("app.auth.router.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: create_mock_settings()
        client = TestClient(app)

        response = client.post(
            "/auth/confirm-password-reset",
            json={"oob_code": "valid-oob-code", "new_password": "newpassword123"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["message"] == "Password has been reset successfully"


def test_confirm_password_reset_expired_code(session: Session):
    """Test POST /auth/confirm-password-reset with expired oobCode returns 400."""
    from unittest.mock import AsyncMock

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": {"message": "EXPIRED_OOB_CODE"}}

    with patch("app.auth.router.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: create_mock_settings()
        client = TestClient(app)

        response = client.post(
            "/auth/confirm-password-reset",
            json={"oob_code": "expired-code", "new_password": "newpassword123"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "expired" in response.json()["message"]


def test_confirm_password_reset_invalid_code(session: Session):
    """Test POST /auth/confirm-password-reset with invalid oobCode returns 400."""
    from unittest.mock import AsyncMock

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": {"message": "INVALID_OOB_CODE"}}

    with patch("app.auth.router.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: create_mock_settings()
        client = TestClient(app)

        response = client.post(
            "/auth/confirm-password-reset",
            json={"oob_code": "invalid-code", "new_password": "newpassword123"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "Invalid" in response.json()["message"]


def test_confirm_password_reset_weak_password(session: Session):
    """Test POST /auth/confirm-password-reset with weak password returns 400."""
    from unittest.mock import AsyncMock

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": {"message": "WEAK_PASSWORD"}}

    with patch("app.auth.router.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: create_mock_settings()
        client = TestClient(app)

        response = client.post(
            "/auth/confirm-password-reset",
            json={"oob_code": "valid-code", "new_password": "123"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "weak" in response.json()["message"]


def test_confirm_password_reset_no_api_key(session: Session):
    """Test POST /auth/confirm-password-reset without API key returns 500."""
    # Use a MagicMock to fully control the settings without env var interference
    mock_settings = MagicMock()
    mock_settings.firebase_api_key = None

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_settings] = lambda: mock_settings
    client = TestClient(app)

    response = client.post(
        "/auth/confirm-password-reset",
        json={"oob_code": "valid-code", "new_password": "newpassword123"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 500
    assert "API key not configured" in response.json()["message"]


def test_confirm_password_reset_generic_error(session: Session):
    """Test POST /auth/confirm-password-reset with generic error returns 400."""
    from unittest.mock import AsyncMock

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": {"message": "SOME_OTHER_ERROR"}}

    with patch("app.auth.router.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )

        app.dependency_overrides[get_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: create_mock_settings()
        client = TestClient(app)

        response = client.post(
            "/auth/confirm-password-reset",
            json={"oob_code": "some-code", "new_password": "newpassword123"},
        )

        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "Failed to reset password" in response.json()["message"]


# --- GET /auth/me ---


def test_auth_me(client: TestClient, test_user: User):
    """Test GET /auth/me returns current user."""
    response = client.get("/auth/me")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_user.id)
    assert data["email"] == test_user.email


def test_auth_me_unauthenticated(unauthenticated_client: TestClient):
    """Test GET /auth/me without auth returns 401."""
    response = unauthenticated_client.get("/auth/me")

    assert response.status_code == 401


# --- POST /auth/revoke-tokens ---


def test_revoke_tokens(
    client: TestClient, test_user: User, mock_firebase_auth: MagicMock
):
    """Test POST /auth/revoke-tokens revokes all tokens."""
    response = client.post("/auth/revoke-tokens")

    assert response.status_code == 200
    assert response.json()["message"] == "All tokens have been revoked"
    mock_firebase_auth.revoke_refresh_tokens.assert_called_once_with(
        test_user.external_id
    )


def test_revoke_tokens_error(client: TestClient, mock_firebase_auth: MagicMock):
    """Test POST /auth/revoke-tokens handles errors."""
    mock_firebase_auth.revoke_refresh_tokens.side_effect = Exception("Error")

    response = client.post("/auth/revoke-tokens")

    assert response.status_code == 500
    assert "Failed to revoke tokens" in response.json()["message"]


def test_revoke_tokens_unauthenticated(unauthenticated_client: TestClient):
    """Test POST /auth/revoke-tokens without auth returns 401."""
    response = unauthenticated_client.post("/auth/revoke-tokens")

    assert response.status_code == 401
