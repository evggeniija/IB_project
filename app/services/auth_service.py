"""Registration and authentication logic.

Sender/identity trust rule: only this module decides what counts as a
user's identity (the normalized email) and only the PKG master secret,
held by the server, may derive a user's IBE private key. Callers never
supply a private key or master secret from client input.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session as DBSession

from app.crypto.pkg import MasterSecret, extract_private_key
from app.crypto.serialization import serialize_g2
from app.storage.models import User

_password_hasher = PasswordHasher()

# Hashed once at import time and verified against on every login for an
# email that doesn't exist, so a failed lookup takes about as long as a
# failed password check and can't be used to enumerate registered emails.
_DUMMY_PASSWORD_HASH = _password_hasher.hash("dummy-password-for-timing-parity")


class EmailAlreadyRegisteredError(Exception):
    """Raised when the normalized email is already registered."""


def normalize_email(email: str) -> str:
    return email.strip().lower()


def register_user(
    db: DBSession, master_secret: MasterSecret, email: str, password: str
) -> User:
    normalized_email = normalize_email(email)

    if db.query(User).filter_by(email=normalized_email).one_or_none() is not None:
        raise EmailAlreadyRegisteredError(normalized_email)

    password_hash = _password_hasher.hash(password)
    private_key = extract_private_key(master_secret, normalized_email)

    user = User(
        email=normalized_email,
        password_hash=password_hash,
        ibe_private_key=serialize_g2(private_key),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: DBSession, email: str, password: str) -> User | None:
    normalized_email = normalize_email(email)
    user = db.query(User).filter_by(email=normalized_email).one_or_none()

    if user is None:
        try:
            _password_hasher.verify(_DUMMY_PASSWORD_HASH, password)
        except VerifyMismatchError:
            pass
        return None

    try:
        _password_hasher.verify(user.password_hash, password)
    except VerifyMismatchError:
        return None
    return user


def get_authenticated_user(db: DBSession, user_id: object) -> User | None:
    if not isinstance(user_id, int):
        return None
    return db.get(User, user_id)
