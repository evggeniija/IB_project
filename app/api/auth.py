"""Auth routes, plus the reusable session -> authenticated-user dependency
that later messaging routes should depend on instead of trusting any
client-supplied identity.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.schemas.auth import LoginRequest, RegisterRequest, UserPublic
from app.services.auth_service import (
    EmailAlreadyRegisteredError,
    authenticate_user,
    get_authenticated_user,
    register_user,
)
from app.storage.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_db(request: Request) -> Generator[DBSession, None, None]:
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    """Resolve the authenticated user from the signed session only.

    Never trust a client-supplied identity field for this purpose.
    """
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    user = get_authenticated_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    return user


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: DBSession = Depends(get_db)) -> User:
    master_secret = request.app.state.master_secret
    try:
        return register_user(db, master_secret, payload.email, payload.password)
    except (EmailAlreadyRegisteredError, IntegrityError):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="email already registered"
        ) from None


@router.post("/login", response_model=UserPublic)
def login(payload: LoginRequest, request: Request, db: DBSession = Depends(get_db)) -> User:
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid email or password"
        )
    request.session.clear()
    request.session["user_id"] = user.id
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request) -> Response:
    request.session.clear()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserPublic)
def me(user: User = Depends(get_current_user)) -> User:
    return user
