"""Server-rendered page routes: login, register, dashboard.

These reuse the existing JSON auth API's own session lookup
(``get_current_user``) purely to decide whether to render a page or
redirect; they never re-implement registration/login/session logic. All
actual authentication happens through POST /api/auth/{register,login,logout}
via client-side fetch (see static/js/auth.js).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from app.api.auth import get_current_user, get_db
from app.storage.models import User

router = APIRouter()

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _current_user_or_none(request: Request, db: DBSession) -> User | None:
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None


@router.get("/")
def root_page() -> RedirectResponse:
    # /dashboard already redirects unauthenticated visitors to /login, so
    # this never needs its own authentication check.
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login")
def login_page(request: Request, db: DBSession = Depends(get_db)):
    if _current_user_or_none(request, db) is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html", {})


@router.get("/register")
def register_page(request: Request, db: DBSession = Depends(get_db)):
    if _current_user_or_none(request, db) is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "register.html", {})


@router.get("/dashboard")
def dashboard_page(request: Request, db: DBSession = Depends(get_db)):
    user = _current_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {"user_email": user.email})
