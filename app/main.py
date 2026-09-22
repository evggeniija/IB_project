"""FastAPI application factory and startup wiring.

Constructing an app with ``create_app`` (including the module-level default
``app`` below) performs no filesystem or database I/O. That only happens
inside the ``lifespan`` context manager, which the ASGI server (or a test
client used as a context manager) runs when the application actually
starts.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api.auth import router as auth_router
from app.api.messages import router as messages_router
from app.api.pages import router as pages_router
from app.crypto.pkg import (
    DEFAULT_MASTER_KEY_PATH,
    derive_master_public_key,
    load_or_create_master_secret,
)
from app.storage import models  # noqa: F401  (registers tables on Base.metadata)
from app.storage.database import (
    DEFAULT_DATABASE_URL,
    create_engine_for_url,
    create_session_factory,
    init_db,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _resolve_session_secret(session_secret: str | None) -> str:
    if session_secret:
        return session_secret
    env_secret = os.environ.get("SESSION_SECRET")
    if env_secret:
        return env_secret
    # Local-development fallback only: a fresh random secret generated once
    # per process. Restarting the process invalidates every existing
    # session cookie. Production deployments must set SESSION_SECRET.
    return secrets.token_urlsafe(32)


def _resolve_secure_cookies(secure_cookies: bool | None) -> bool:
    if secure_cookies is not None:
        return secure_cookies
    # Lets `uvicorn app.main:app` (the module-level default instance) pick
    # up an HTTPS deployment's cookie requirement without editing source;
    # local HTTP development is unaffected since this defaults to False.
    return os.environ.get("SECURE_COOKIES", "").strip().lower() in ("1", "true", "yes")


def create_app(
    database_url: str = DEFAULT_DATABASE_URL,
    master_key_path: Path | str = DEFAULT_MASTER_KEY_PATH,
    session_secret: str | None = None,
    secure_cookies: bool | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine_for_url(database_url)
        init_db(engine)
        app.state.session_factory = create_session_factory(engine)

        master_secret = load_or_create_master_secret(master_key_path)
        app.state.master_secret = master_secret
        app.state.master_public_key = derive_master_public_key(master_secret)
        try:
            yield
        finally:
            engine.dispose()

    app = FastAPI(lifespan=lifespan)

    app.add_middleware(
        SessionMiddleware,
        secret_key=_resolve_session_secret(session_secret),
        same_site="lax",
        https_only=_resolve_secure_cookies(secure_cookies),
    )

    app.include_router(auth_router)
    app.include_router(messages_router)
    app.include_router(pages_router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
