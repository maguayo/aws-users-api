import json
import os
import requests
from datetime import datetime, timezone, timedelta
import boto3
import jwt
import base64
from src.constants import DEFAULT_JWT_SECRET
from botocore.exceptions import ClientError


def get_env(key):
    return os.environ.get(key)


def create_access_token(data: dict):
    data["exp"] = datetime.now(tz=timezone.utc) + timedelta(minutes=1)
    return create_jwt(data)


def create_refresh_token(data: dict):
    tokenData = {}
    tokenData["id"] = data["id"]
    tokenData["email"] = data["email"]
    tokenData["exp"] = datetime.now(tz=timezone.utc) + timedelta(days=30)
    tokenData["refresh_token"] = True
    return create_jwt(tokenData)


def create_verification_token(email: str):
    data = {
        "email": email,
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
    }
    return create_jwt(data)


def create_jwt(data: dict):
    secret = get_env("JWT_SECRET")
    return jwt.encode(data, secret, algorithm="HS256")


def send_email(to, subject, template, data):
    if os.environ.get("SEND_EMAILS", True) != True:
        return {"SEND_EMAILS": False}

    api_key = get_env("MAILGUN_API_KEY")
    base_url = get_env("MAILGUN_BASE_URL")

    return requests.post(
        base_url + "/messages",
        auth=("api", api_key),
        data={
            "from": "Example <hello@example.com>",
            "to": [to],
            "subject": subject,
            "template": template,
            "h:X-Mailgun-Variables": json.dumps(data),
        },
    )


def decode_token(token):
    try:
        secret = get_env("JWT_SECRET")
        token = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    else:
        return token
