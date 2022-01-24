import datetime
import uuid
import jwt
from src.models import Users
from pynamodb.exceptions import DoesNotExist
from fastapi import HTTPException
from src.auth import make_password, check_password
from src.helpers import (
    create_jwt,
    send_email,
    decode_token,
    create_access_token,
    create_refresh_token,
    create_verification_token,
)


def create_user(data: dict):
    try:
        Users.get(hash_key=data["email"])
        raise HTTPException(status_code=409, detail="User already exists")
    except DoesNotExist:
        pass

    try:
        user = Users(
            id=str(uuid.uuid4()),
            account_type=data["account_type"],
            email=data["email"],
            first_name=data["first_name"],
            last_name=data["last_name"],
            password=make_password(data["password"]),
            phone=data.get("phone", ""),
            cif=data.get("cif", ""),
            city=data.get("city", ""),
            address=data.get("address", ""),
            created_at=datetime.datetime.now().timestamp(),
            modified=datetime.datetime.now().timestamp(),
            utms=data.get("utms", {}),
        )
        user.save()
    except KeyError:
        raise HTTPException(status_code=400, detail="Missing required fields")
    else:
        user = user.to_dict()
        user.pop("password")
        response = send_email(
            to=user["email"],
            subject="Welcome to Example",
            template="welcome",
            data=user,
        )
        return {
            "user": user,
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
        }


def login_user(data: dict):
    try:
        email = data["email"]
        password = data["password"]
        user = Users.get(hash_key=email)
    except KeyError:
        raise HTTPException(status_code=400, detail="Missing required fields")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User does not exist")
    else:
        user = user.to_dict()
        if check_password(password, user["password"]):
            user.pop("password")
            return {
                "user": user,
                "access_token": create_access_token(user),
                "refresh_token": create_refresh_token(user),
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid password")


def reset_password_email(data: dict):
    token = create_verification_token(email=data["email"])
    send_email(
        to=data["email"],
        subject="Reset your password",
        template="reset-password",
        data={"token": token},
    )


def reset_password(data: dict):
    token = decode_token(data["token"])
    if not token:
        raise HTTPException(status_code=401, detail="Invalid token")

    if token["email"] != data["email"]:
        raise HTTPException(status_code=400, detail="Invalid token")

    try:
        user = Users.get(hash_key=token["email"])
    except KeyError:
        raise HTTPException(status_code=400, detail="Missing required fields")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User does not exist")
    else:
        user.password = make_password(data["password"])
        user.save()
        user = user.to_dict()
        user.pop("password")
        return {
            "user": user,
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
        }


def verify_token(token: str):
    return decode_token(token)


def refresh_token(token: str):
    token = decode_token(token)
    if not token or "refresh_token" not in token or not token["refresh_token"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        user = Users.get(hash_key=token["email"])
    except KeyError:
        raise HTTPException(status_code=400, detail="Missing required fields")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User does not exist")
    else:
        user = user.to_dict()
        user.pop("password")
        return {
            "user": user,
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
        }
