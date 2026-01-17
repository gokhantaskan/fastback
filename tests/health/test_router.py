"""Tests for health domain router."""

from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint():
    """Test GET /health returns status ok."""
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
