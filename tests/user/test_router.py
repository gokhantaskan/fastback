"""Tests for user domain router."""

import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.user.models import User

# --- PATCH /users/me (Self-update, limited fields) ---


def test_update_me_first_name(client: TestClient, test_user: User, session: Session):
    """Test PATCH /users/me updates first_name."""
    response = client.patch("/users/me", json={"first_name": "Updated"})

    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == "Updated"
    assert data["id"] == str(test_user.id)

    session.refresh(test_user)
    assert test_user.first_name == "Updated"


def test_update_me_last_name(client: TestClient, test_user: User, session: Session):
    """Test PATCH /users/me updates last_name."""
    response = client.patch("/users/me", json={"last_name": "NewLastName"})

    assert response.status_code == 200
    data = response.json()
    assert data["last_name"] == "NewLastName"

    session.refresh(test_user)
    assert test_user.last_name == "NewLastName"


def test_update_me_partial(client: TestClient, test_user: User):
    """Test PATCH /users/me with empty body doesn't change anything."""
    original_first_name = test_user.first_name
    response = client.patch("/users/me", json={})

    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == original_first_name


def test_update_me_ignores_restricted_fields(
    client: TestClient, test_user: User, session: Session
):
    """Test PATCH /users/me ignores email, is_active, is_admin for security."""
    original_email = test_user.email
    original_is_active = test_user.is_active
    original_is_admin = test_user.is_admin

    # Attempt to change restricted fields (should be ignored by schema)
    response = client.patch(
        "/users/me",
        json={
            "email": "hacker@example.com",
            "is_active": False,
            "is_admin": True,
            "first_name": "Legit",
        },
    )

    assert response.status_code == 200
    data = response.json()

    # Only first_name should change
    assert data["first_name"] == "Legit"
    assert data["email"] == original_email
    assert data["is_active"] == original_is_active
    assert data["is_admin"] == original_is_admin

    session.refresh(test_user)
    assert test_user.email == original_email
    assert test_user.is_active == original_is_active
    assert test_user.is_admin == original_is_admin


def test_update_me_unauthenticated(unauthenticated_client: TestClient):
    """Test PATCH /users/me without auth returns 401."""
    response = unauthenticated_client.patch(
        "/users/me", json={"first_name": "Hacker"}
    )

    assert response.status_code == 401


# --- DELETE /users/me ---


def test_delete_me(client: TestClient, test_user: User, session: Session):
    """Test DELETE /users/me removes the user."""
    user_id = test_user.id
    response = client.delete("/users/me")

    assert response.status_code == 204

    # Verify user is deleted
    deleted_user = session.get(User, user_id)
    assert deleted_user is None


def test_delete_me_unauthenticated(unauthenticated_client: TestClient):
    """Test DELETE /users/me without auth returns 401."""
    response = unauthenticated_client.delete("/users/me")

    assert response.status_code == 401


# --- GET /users/ (Admin only) ---


def test_list_users(admin_client: TestClient, admin_user: User):
    """Test GET /users/ returns list of users for admin."""
    response = admin_client.get("/users/")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(u["id"] == str(admin_user.id) for u in data)


def test_list_users_non_admin(client: TestClient):
    """Test GET /users/ returns 403 for non-admin users."""
    response = client.get("/users/")

    assert response.status_code == 403
    assert response.json()["type"] == "admin_required"


def test_list_users_unauthenticated(unauthenticated_client: TestClient):
    """Test GET /users/ without auth returns 401."""
    response = unauthenticated_client.get("/users/")

    assert response.status_code == 401


# --- GET /users/{user_id} (Admin only) ---


def test_get_user_by_id(admin_client: TestClient, admin_user: User):
    """Test GET /users/{user_id} returns the user for admin."""
    response = admin_client.get(f"/users/{admin_user.id}")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(admin_user.id)
    assert data["email"] == admin_user.email


def test_get_user_by_id_non_admin(client: TestClient, test_user: User):
    """Test GET /users/{user_id} returns 403 for non-admin users."""
    response = client.get(f"/users/{test_user.id}")

    assert response.status_code == 403
    assert response.json()["type"] == "admin_required"


def test_get_user_not_found(admin_client: TestClient):
    """Test GET /users/{user_id} with non-existent ID returns 404 for admin."""
    non_existent_uuid = "00000000-0000-0000-0000-000000000000"
    response = admin_client.get(f"/users/{non_existent_uuid}")

    assert response.status_code == 404
    assert response.json()["message"] == "User not found"


def test_get_user_unauthenticated(unauthenticated_client: TestClient):
    """Test GET /users/{user_id} without auth returns 401."""
    response = unauthenticated_client.get("/users/00000000-0000-0000-0000-000000000001")

    assert response.status_code == 401


# --- PATCH /users/{user_id} (Admin only) ---


def test_update_user_by_admin(
    admin_client: TestClient, session: Session
):
    """Test PATCH /users/{user_id} allows admin to update user."""
    # Create a target user to update
    target_user = User(
        external_id="target-external-id",
        email="target@example.com",
        first_name="Target",
        last_name="User",
    )
    session.add(target_user)
    session.commit()
    session.refresh(target_user)

    response = admin_client.patch(
        f"/users/{target_user.id}",
        json={
            "email": "updated-target@example.com",
            "first_name": "UpdatedTarget",
            "is_active": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "updated-target@example.com"
    assert data["first_name"] == "UpdatedTarget"
    assert data["is_active"] is False

    session.refresh(target_user)
    assert target_user.email == "updated-target@example.com"
    assert target_user.first_name == "UpdatedTarget"
    assert target_user.is_active is False


def test_update_user_non_admin(client: TestClient, test_user: User):
    """Test PATCH /users/{user_id} returns 403 for non-admin users."""
    response = client.patch(
        f"/users/{test_user.id}",
        json={"first_name": "Hacker"},
    )

    assert response.status_code == 403
    assert response.json()["type"] == "admin_required"


def test_update_user_not_found(admin_client: TestClient):
    """Test PATCH /users/{user_id} with non-existent ID returns 404."""
    non_existent_uuid = "00000000-0000-0000-0000-000000000000"
    response = admin_client.patch(
        f"/users/{non_existent_uuid}",
        json={"first_name": "Ghost"},
    )

    assert response.status_code == 404
    assert response.json()["message"] == "User not found"


def test_update_user_unauthenticated(unauthenticated_client: TestClient):
    """Test PATCH /users/{user_id} without auth returns 401."""
    some_uuid = str(uuid.uuid4())
    response = unauthenticated_client.patch(
        f"/users/{some_uuid}",
        json={"first_name": "Anon"},
    )

    assert response.status_code == 401
