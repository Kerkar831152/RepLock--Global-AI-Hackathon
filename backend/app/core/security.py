
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from cryptography.fernet import Fernet
from jose import jwt, JWTError

load_dotenv()

FERNET_KEY = os.getenv("FERNET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
try:
    ACCESS_TOKEN_EXPIRE_MINUTES = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )
except ValueError as exc:
    raise RuntimeError(
        "ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer"
    ) from exc

if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY is missing from environment")

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from environment")

if len(JWT_SECRET_KEY.encode("utf-8")) < 32:
    raise RuntimeError("JWT_SECRET_KEY must contain at least 32 bytes")

if JWT_ALGORITHM not in {"HS256", "HS384", "HS512"}:
    raise RuntimeError("JWT_ALGORITHM must be HS256, HS384, or HS512")

if ACCESS_TOKEN_EXPIRE_MINUTES < 1:
    raise RuntimeError(
        "ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer"
    )

fernet = Fernet(FERNET_KEY.encode())

def encrypt_token(token: str) -> str:
    return fernet.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    return fernet.decrypt(encrypted_token.encode()).decode()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
