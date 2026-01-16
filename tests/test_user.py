from fastapi.testclient import TestClient
from sqlmodel import Session

from app.models.user import User

# --- PATCH /user/me ---


def test_update_me_email(client: TestClient, test_user: User, session: Session):
    """Test PATCH /user/me updates email."""
    response = client.patch("/user/me", json={"email": "updated@example.com"})

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "updated@example.com"
    assert data["id"] == str(test_user.id)

    # Verify in database
    session.refresh(test_user)
    assert test_user.email == "updated@example.com"


def test_update_me_is_active(client: TestClient, test_user: User, session: Session):
    """Test PATCH /user/me updates is_active."""
    response = client.patch("/user/me", json={"is_active": False})

    assert response.status_code == 200
    data = response.json()
    assert data["is_active"] is False

    session.refresh(test_user)
    assert test_user.is_active is False


def test_update_me_partial(client: TestClient, test_user: User):
    """Test PATCH /user/me with empty body doesn't change anything."""
    original_email = test_user.email
    response = client.patch("/user/me", json={})

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == original_email


def test_update_me_unauthenticated(unauthenticated_client: TestClient):
    """Test PATCH /user/me without auth returns 401."""
    response = unauthenticated_client.patch(
        "/user/me", json={"email": "hacker@example.com"}
    )

    assert response.status_code == 401


# --- DELETE /user/me ---


def test_delete_me(client: TestClient, test_user: User, session: Session):
    """Test DELETE /user/me removes the user."""
    user_id = test_user.id
    response = client.delete("/user/me")

    assert response.status_code == 204

    # Verify user is deleted
    deleted_user = session.get(User, user_id)
    assert deleted_user is None


def test_delete_me_unauthenticated(unauthenticated_client: TestClient):
    """Test DELETE /user/me without auth returns 401."""
    response = unauthenticated_client.delete("/user/me")

    assert response.status_code == 401


# --- GET /user/ ---


def test_list_users(client: TestClient, test_user: User):
    """Test GET /user/ returns list of users."""
    response = client.get("/user/")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(u["id"] == str(test_user.id) for u in data)


def test_list_users_unauthenticated(unauthenticated_client: TestClient):
    """Test GET /user/ without auth returns 401."""
    response = unauthenticated_client.get("/user/")

    assert response.status_code == 401


# --- GET /user/{user_id} ---


def test_get_user_by_id(client: TestClient, test_user: User):
    """Test GET /user/{user_id} returns the user."""
    response = client.get(f"/user/{test_user.id}")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_user.id)
    assert data["email"] == test_user.email


def test_get_user_not_found(client: TestClient):
    """Test GET /user/{user_id} with non-existent ID returns 404."""
    non_existent_uuid = "00000000-0000-0000-0000-000000000000"
    response = client.get(f"/user/{non_existent_uuid}")

    assert response.status_code == 404
    assert response.json()["message"] == "User not found"


def test_get_user_unauthenticated(unauthenticated_client: TestClient):
    """Test GET /user/{user_id} without auth returns 401."""
    response = unauthenticated_client.get("/user/00000000-0000-0000-0000-000000000001")

    assert response.status_code == 401
