
import os
import secrets
import hmac
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import encrypt_token, create_access_token
from app.models import User
from app.schemas.user import UserResponse

load_dotenv()

router = APIRouter(prefix="/auth", tags=["Authentication"])

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_CALLBACK_URL = os.getenv("GITHUB_CALLBACK_URL")

GITHUB_API_URL = "https://api.github.com"
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"


@router.get("/github/login")
def github_login():
    if not GITHUB_CLIENT_ID or not GITHUB_CALLBACK_URL:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is missing"
        )

    state = secrets.token_urlsafe(32)

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_CALLBACK_URL,
        "scope": "read:user user:email",
        "state": state
    }

    response = RedirectResponse(
        url=f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    )

    response.set_cookie(
        key="github_oauth_state",
        value=state,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=600,
        path="/api/v1/auth"
    )

    return response


@router.get("/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db)
):
    if error or not code or not state:
        response = JSONResponse(
            status_code=400,
            content={"detail": "GitHub authorization was cancelled or invalid"}
        )
        response.delete_cookie(
            key="github_oauth_state",
            path="/api/v1/auth"
        )
        return response

    saved_state = request.cookies.get("github_oauth_state")

    if not saved_state or not hmac.compare_digest(saved_state, state):
        response = JSONResponse(
            status_code=400,
            content={"detail": "Invalid OAuth state"}
        )
        response.delete_cookie(
            key="github_oauth_state",
            path="/api/v1/auth"
        )
        return response

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is missing"
        )

    try:
        token_response = httpx.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_CALLBACK_URL
            },
            headers={"Accept": "application/json"},
            timeout=20
        )

        token_response.raise_for_status()
        token_data = token_response.json()

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Unable to communicate with GitHub"
        )

    access_token = token_data.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=400,
            detail="Unable to obtain GitHub access token"
        )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    try:
        profile_response = httpx.get(
            f"{GITHUB_API_URL}/user",
            headers=headers,
            timeout=20
        )

        profile_response.raise_for_status()
        github_user = profile_response.json()

        email_response = httpx.get(
            f"{GITHUB_API_URL}/user/emails",
            headers=headers,
            timeout=20
        )

        email_response.raise_for_status()
        emails = email_response.json()

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve GitHub account information"
        )

    github_id = str(github_user["id"])
    username = github_user["login"]

    primary_email = next(
    (
        item["email"]
        for item in emails
        if item.get("primary") and item.get("verified")
    ),
    None
)

    encrypted_token = encrypt_token(access_token)

    user = db.scalar(
        select(User).where(User.github_id == github_id)
    )

    if user:
        user.username = username
        user.email = primary_email
        user.github_access_token_encrypted = encrypted_token

    else:
        user = User(
            github_id=github_id,
            username=username,
            email=primary_email,
            github_access_token_encrypted=encrypted_token
        )
        db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This email is already associated with another account"
        )

    jwt_token = create_access_token(
        {"sub": str(user.id)}
    )

    response = JSONResponse(
        content=jsonable_encoder({
            "access_token": jwt_token,
            "token_type": "bearer",
            "user": UserResponse.model_validate(user)
        })
    )

    response.delete_cookie(
        key="github_oauth_state",
        path="/api/v1/auth"
    )

    return response


@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: User = Depends(get_current_user)
):
    return current_user
