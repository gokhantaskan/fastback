import inspect
from unittest.mock import MagicMock

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.core.auth import get_current_user
from app.core.settings import Settings, get_settings
from app.db.engine import get_session
from app.main import app
from app.models.user import User
from app.services.firebase_auth import (
    FirebaseAuthService,
    TokenClaims,
    get_firebase_auth_service,
)


def pytest_configure(config: pytest.Config) -> None:
    # Tests use @pytest.mark.asyncio, but we intentionally rely on anyio.
    config.addinivalue_line(
        "markers",
        "asyncio: run async tests using anyio (project-local hook)",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Run @pytest.mark.asyncio tests with anyio.

    This avoids adding an external pytest-asyncio dependency.
    """
    if pyfuncitem.get_closest_marker("asyncio") is None:
        return None

    test_func = pyfuncitem.obj
    if not inspect.iscoroutinefunction(test_func):
        return None

    funcargs = {
        name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames
    }

    async def _run_async_test() -> None:
        await test_func(**funcargs)

    anyio.run(_run_async_test)
    return True


@pytest.fixture(name="session")
def session_fixture():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    """Create a test user in the database."""
    user = User(
        firebase_uid="test-firebase-uid-123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="inactive_user")
def inactive_user_fixture(session: Session):
    """Create an inactive test user."""
    user = User(
        firebase_uid="inactive-uid-456",
        email="inactive@example.com",
        first_name="Inactive",
        last_name="User",
        is_active=False,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="mock_firebase_auth")
def mock_firebase_auth_fixture():
    """Create a mock FirebaseAuthService."""
    mock_service = MagicMock(spec=FirebaseAuthService)
    # Default mock behaviors
    mock_service.verify_session_cookie.return_value = TokenClaims(uid="test-uid")
    mock_service.verify_id_token.return_value = TokenClaims(uid="test-uid")
    return mock_service


@pytest.fixture(name="mock_settings")
def mock_settings_fixture():
    """Create mock settings."""
    return Settings(
        env_name="test",
        database_url="sqlite://",
        session_secret_key="test-secret-key",
        admin_username="admin",
        admin_password="admin",
        session_expires_days=5,
        firebase_api_key="test-api-key",
        google_id_toolkit_url="https://identitytoolkit.googleapis.com",
    )


@pytest.fixture(name="client")
def client_fixture(
    session: Session,
    test_user: User,
    mock_firebase_auth: MagicMock,
    mock_settings: Settings,
):
    """Create a test client with overridden dependencies."""

    def get_session_override():
        return session

    def get_current_user_override():
        return test_user

    def get_firebase_auth_override():
        return mock_firebase_auth

    def get_settings_override():
        return mock_settings

    app.dependency_overrides[get_session] = get_session_override
    app.dependency_overrides[get_current_user] = get_current_user_override
    app.dependency_overrides[get_firebase_auth_service] = get_firebase_auth_override
    app.dependency_overrides[get_settings] = get_settings_override

    client = TestClient(app)
    yield client

    app.dependency_overrides.clear()


@pytest.fixture(name="unauthenticated_client")
def unauthenticated_client_fixture(
    session: Session,
    mock_firebase_auth: MagicMock,
    mock_settings: Settings,
):
    """Create a test client without auth override (for testing auth failures)."""

    def get_session_override():
        return session

    def get_firebase_auth_override():
        return mock_firebase_auth

    def get_settings_override():
        return mock_settings

    app.dependency_overrides[get_session] = get_session_override
    app.dependency_overrides[get_firebase_auth_service] = get_firebase_auth_override
    app.dependency_overrides[get_settings] = get_settings_override

    client = TestClient(app)
    yield client

    app.dependency_overrides.clear()
