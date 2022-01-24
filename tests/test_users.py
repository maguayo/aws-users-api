from venv import create
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.helpers import send_email, get_secrets, decode_token
from tests.constants import USER1
from unittest.mock import MagicMock
from freezegun import freeze_time

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "stage": None,
        "success": True,
        "region": None,
    }


def test_signup(create_user1):
    response = create_user1
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert "user" in response.json()

    assert response.json()["user"]["email"] == USER1["email"]
    assert response.json()["user"]["first_name"] == USER1["first_name"]
    assert response.json()["user"]["last_name"] == USER1["last_name"]

    access_token = decode_token(response.json()["access_token"])
    refresh_token = decode_token(response.json()["refresh_token"])

    assert access_token["email"] == USER1["email"]
    assert access_token["account_type"] == USER1["account_type"]
    assert access_token["first_name"] == USER1["first_name"]
    assert access_token["last_name"] == USER1["last_name"]

    assert refresh_token["email"] == USER1["email"]
    assert refresh_token["refresh_token"] == True


def test_login(create_user1):
    response = client.post(
        "/users/login",
        json={
            "email": USER1["email"],
            "password": USER1["password"],
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert "user" in response.json()

    assert response.json()["user"]["email"] == USER1["email"]
    assert response.json()["user"]["first_name"] == USER1["first_name"]
    assert response.json()["user"]["last_name"] == USER1["last_name"]

    access_token = decode_token(response.json()["access_token"])
    refresh_token = decode_token(response.json()["refresh_token"])

    assert access_token["email"] == USER1["email"]
    assert access_token["account_type"] == USER1["account_type"]
    assert access_token["first_name"] == USER1["first_name"]
    assert access_token["last_name"] == USER1["last_name"]

    assert refresh_token["email"] == USER1["email"]
    assert refresh_token["refresh_token"] == True


def test_verify_token():
    responseCreate = client.post(
        "/users/signup",
        json=USER1,
    )
    assert responseCreate.status_code == 200

    loginResponse = client.post(
        "/users/login",
        json={
            "email": USER1["email"],
            "password": USER1["password"],
        },
    )
    assert loginResponse.status_code == 200

    response = client.post(
        "/token/verify",
        json={
            "token": loginResponse.json()["access_token"],
        },
    )
    assert response.json() is not False
    assert response.status_code == 200
    assert USER1["email"] == response.json()["email"]

    future_date = datetime.now(tz=timezone.utc) + timedelta(days=2)
    with freeze_time(future_date):
        response = client.post(
            "/token/verify",
            json={
                "token": loginResponse.json()["access_token"],
            },
        )
        assert response.json() is False


@pytest.mark.skip(reason="WIP: Invalid signature caused by freeze_time")
def test_refresh_token(create_user1):
    loginResponse = client.post(
        "/users/login",
        json={
            "email": USER1["email"],
            "password": USER1["password"],
        },
    )
    assert loginResponse.status_code == 200

    response = client.post(
        "/token/verify",
        json={
            "token": loginResponse.json()["access_token"],
        },
    )
    assert response.json() is not False
    assert response.status_code == 200
    assert USER1["email"] == response.json()["email"]

    future_date = datetime.now(tz=timezone.utc) + timedelta(days=2)
    with freeze_time(future_date):
        response = client.post(
            "/token/verify",
            json={
                "token": loginResponse.json()["access_token"],
            },
        )
        assert response.status_code == 200
        assert response.json() is False

        response = client.post(
            "/token/refresh",
            json={
                "token": loginResponse.json()["refresh_token"],
            },
        )
        assert response.status_code == 200
        assert response.json() is False
