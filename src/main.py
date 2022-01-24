import logging
import uuid
import os
import jwt
import datetime
import sentry_sdk
from fastapi import FastAPI, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from src.auth import make_password, check_password
from src.models import Users
from pynamodb.exceptions import DoesNotExist
from src.api import users
from dotenv import load_dotenv


load_dotenv()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

stage = os.environ.get("STAGE", None)
openapi_prefix = f"/{stage}" if stage else None

app = FastAPI(title="Users API", openapi_prefix=openapi_prefix)

app.add_middleware(
    CORSMiddleware,
    allow_origins={"*"},
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def traces_sampler(sampling_context):
    return 1


sentry_sdk.init(
    os.environ.get("SENTRY"),
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0,
    traces_sampler=traces_sampler,
)


@app.get("/health")
def health():
    return {
        "success": True,
        "stage": stage,
        "region": os.environ.get("REGION", None),
        "MAILGUN_BASE_URL": os.environ.get("MAILGUN_BASE_URL", None),
        "SENTRY": os.environ.get("SENTRY", None),
    }


@app.post("/users/signup")
def create_user(data: dict):
    return users.create_user(data)


@app.post("/users/login")
def login_user(data: dict):
    return users.login_user(data)


@app.post("/users/reset")
def token_reset_send(data: dict):
    return users.reset_password_email(data)


@app.patch("/users/reset")
def token_reset(data: dict):
    return users.reset_password(data)


@app.post("/token/verify")
def token_verify(data: dict):
    return users.verify_token(token=data["token"])


@app.post("/token/refresh")
def token_verify(data: dict):
    return users.refresh_token(token=data["token"])


handler = Mangum(app)
