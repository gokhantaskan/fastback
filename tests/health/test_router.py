"""Tests for health domain router."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.db.engine import get_session
from app.main import app


def test_health_endpoint_database_healthy(session: Session):
    """Test GET /health returns ok status when database is healthy."""

    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/health")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_health_endpoint_database_unhealthy():
    """Test GET /health returns 503 when database is unreachable."""
    mock_session = MagicMock(spec=Session)
    mock_session.exec.side_effect = Exception("Connection refused")

    def get_session_override():
        return mock_session

    app.dependency_overrides[get_session] = get_session_override

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/health")

    app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"status": "unhealthy", "database": "error"}
