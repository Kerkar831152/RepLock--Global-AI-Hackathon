import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import User
from app.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.scalar(
        select(User).where(User.github_id == user_data.github_id)
    )

    if existing_user:
        raise HTTPException(status_code=409, detail="GitHub user already exists")

    if user_data.email:
        existing_email = db.scalar(
            select(User).where(User.email == user_data.email)
        )
        if existing_email:
            raise HTTPException(status_code=409, detail="Email already exists")

    new_user = User(**user_data.model_dump())
    db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="User already exists")

    return new_user


@router.get("/", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.created_at.desc())).all()


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: uuid.UUID, db: Session = Depends(get_db)):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user