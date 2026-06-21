import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Point to a separate test database BEFORE importing the app
TEST_DB_URL = "sqlite:///./test_auth_service.db"

from app.main import app
from app.database import Base, get_db

# ---------- Test database setup ----------

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function", autouse=True)
def setup_and_teardown_db():
    """Creates fresh tables before each test, drops them after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


# ---------- Helper ----------

def register_and_verify_user(client, email="user@example.com", password="Password123"):
    """Helper: registers a user and verifies them, returns the verification token."""
    response = client.post("/auth/register", json={"email": email, "password": password})
    token = response.json()["message"].split(": ")[-1]
    client.post("/auth/verify-email", json={"token": token})
    return token


# ---------- Tests ----------

def test_register_new_user(client):
    response = client.post(
        "/auth/register", json={"email": "newuser@example.com", "password": "Password123"}
    )
    assert response.status_code == 201
    assert "Verification token" in response.json()["message"]


def test_register_duplicate_email_rejected(client):
    client.post("/auth/register", json={"email": "dupe@example.com", "password": "Password123"})
    response = client.post(
        "/auth/register", json={"email": "dupe@example.com", "password": "Password123"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"


def test_register_invalid_email_rejected(client):
    response = client.post(
        "/auth/register", json={"email": "not-an-email", "password": "Password123"}
    )
    assert response.status_code == 422  # Pydantic/EmailStr validation


def test_register_short_password_rejected(client):
    response = client.post(
        "/auth/register", json={"email": "shortpw@example.com", "password": "123"}
    )
    assert response.status_code == 422  # min_length=8 validation

def test_register_weak_password_rejected(client):
    response = client.post(
        "/auth/register", json={"email": "weakpw@example.com", "password": "alllowercase1"}
    )
    assert response.status_code == 422  # missing uppercase letter    


def test_login_blocked_before_verification(client):
    client.post("/auth/register", json={"email": "unverified@example.com", "password": "Password123"})
    response = client.post(
        "/auth/login", json={"email": "unverified@example.com", "password": "Password123"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Email not verified"


def test_login_wrong_password_rejected(client):
    register_and_verify_user(client, email="wrongpw@example.com")
    response = client.post(
        "/auth/login", json={"email": "wrongpw@example.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401


def test_login_nonexistent_user_rejected(client):
    response = client.post(
        "/auth/login", json={"email": "ghost@example.com", "password": "Password123"}
    )
    assert response.status_code == 401


def test_verify_email_invalid_token_rejected(client):
    response = client.post("/auth/verify-email", json={"token": "not-a-real-token"})
    assert response.status_code == 400


def test_full_login_after_verification(client):
    register_and_verify_user(client, email="verified@example.com")
    response = client.post(
        "/auth/login", json={"email": "verified@example.com", "password": "Password123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_refresh_with_valid_token_rotates_tokens(client):
    register_and_verify_user(client, email="refresher@example.com")
    login_response = client.post(
        "/auth/login", json={"email": "refresher@example.com", "password": "Password123"}
    )
    old_refresh_token = login_response.json()["refresh_token"]

    refresh_response = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert new_tokens["refresh_token"] != old_refresh_token  # rotation happened


def test_refresh_with_invalid_token_rejected(client):
    response = client.post("/auth/refresh", json={"refresh_token": "garbage.invalid.token"})
    assert response.status_code == 401


def test_refresh_with_access_token_rejected(client):
    """An access token should NOT work as a refresh token (type check)."""
    register_and_verify_user(client, email="typecheck@example.com")
    login_response = client.post(
        "/auth/login", json={"email": "typecheck@example.com", "password": "Password123"}
    )
    access_token = login_response.json()["access_token"]

    response = client.post("/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_logout_invalidates_refresh_token(client):
    register_and_verify_user(client, email="logouttest@example.com")
    login_response = client.post(
        "/auth/login", json={"email": "logouttest@example.com", "password": "Password123"}
    )
    refresh_token = login_response.json()["refresh_token"]

    logout_response = client.post("/auth/logout", json={"refresh_token": refresh_token})
    assert logout_response.status_code == 200

    # Reusing the same refresh token after logout should now fail
    reuse_response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert reuse_response.status_code == 401


def test_logout_with_invalid_token_rejected(client):
    response = client.post("/auth/logout", json={"refresh_token": "garbage.invalid.token"})
    assert response.status_code == 401

    