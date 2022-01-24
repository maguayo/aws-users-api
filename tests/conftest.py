# conftest.py
import pytest
import os
import shutil
from src.models import Users
import pytest
from fastapi.testclient import TestClient
from src.main import app
from tests.constants import USER1, USER2

client = TestClient(app)


@pytest.fixture
def create_user1():
    return client.post(
        "/users/signup",
        json=USER1,
    )


@pytest.fixture
def create_user2():
    return client.post(
        "/users/signup",
        json=USER2,
    )


@pytest.fixture(autouse=True)
def run_before_and_after_tests():
    print("Init tests")
    clean_users()

    yield  # this is where the testing happens

    print("Clean tests")
    clean_users()


def clean_users():
    for item in Users.scan():
        item.delete()
