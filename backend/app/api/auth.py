
import os
import secrets
import hmac
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import encrypt_token, create_access_token
from app.models import User
from app.schemas.user import UserResponse

from app.core.dependencies import get_current_user

load_dotenv()

router = APIRouter(prefix="/auth", tags=["Authentication"])

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"


@router.get("/github/login")
def github_login():
    client_id = os.getenv("GITHUB_CLIENT_ID")
    callback_url = os.getenv("GITHUB_CALLBACK_URL")

    if not client_id or not callback_url:
        raise HTTPException(status_code=500, detail="GitHub OAuth configuration missing")

    state = secrets.token_urlsafe(32)

    params = {
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": "read:user user:email",
        "state": state
    }

    response = RedirectResponse(
        f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
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
    code: str,
    state: str,
    db: Session = Depends(get_db)
):
    saved_state = request.cookies.get("github_oauth_state")

    if not saved_state or not hmac.compare_digest(saved_state, state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    client_id = os.getenv("GITHUB_CLIENT_ID")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    callback_url = os.getenv("GITHUB_CALLBACK_URL")

    if not all([client_id, client_secret, callback_url]):
        raise HTTPException(status_code=500, detail="GitHub OAuth configuration missing")

    try:
        with httpx.Client(timeout=15) as client:
            token_response = client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": callback_url
                },
                headers={"Accept": "application/json"}
            )

            token_response.raise_for_status()
            token_data = token_response.json()

            access_token = token_data.get("access_token")

            if not access_token:
                raise HTTPException(
                    status_code=400,
                    detail="GitHub token exchange failed"
                )

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }

            profile_response = client.get(
                f"{GITHUB_API_URL}/user",
                headers=headers
            )
            profile_response.raise_for_status()
            profile = profile_response.json()

            email = profile.get("email")

            if not email:
                email_response = client.get(
                    f"{GITHUB_API_URL}/user/emails",
                    headers=headers
                )
                email_response.raise_for_status()

                emails = email_response.json()

                email = next(
                    (
                        item["email"]
                        for item in emails
                        if item.get("primary") and item.get("verified")
                    ),
                    None
                )

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Unable to communicate with GitHub"
        )

    github_id = str(profile["id"])

    existing_user = db.scalar(
        select(User).where(User.github_id == github_id)
    )

    if existing_user:
        existing_user.username = profile["login"]
        existing_user.github_access_token_encrypted = encrypt_token(access_token)

        if email:
            email_owner = db.scalar(
                select(User).where(User.email == email)
            )

            if email_owner and email_owner.id != existing_user.id:
                raise HTTPException(
                    status_code=409,
                    detail="Email already associated with another user"
                )

            existing_user.email = email

        db.commit()
        db.refresh(existing_user)
        user = existing_user

    else:
        if email:
            email_owner = db.scalar(
                select(User).where(User.email == email)
            )

            if email_owner:
                raise HTTPException(
                    status_code=409,
                    detail="Email already associated with another user"
                )

        user = User(
            github_id=github_id,
            username=profile["login"],
            email=email,
            github_access_token_encrypted=encrypt_token(access_token)
        )

        db.add(user)

        try:
            db.commit()
            db.refresh(user)
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="Unable to create user"
            )

    jwt_token = create_access_token({
        "sub": str(user.id)
    })

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user)
    }


@router.get("/me", response_model=UserResponse)
def get_logged_in_user(
    current_user: User = Depends(get_current_user)
):
    return current_user