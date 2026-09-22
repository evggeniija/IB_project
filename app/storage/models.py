"""ORM models for user accounts and stored ciphertext messages.

Neither model derives or computes cryptographic material; they only store
the byte strings produced by ``app.crypto``. Never store plaintext, the
derived AES key, or the PKG master secret here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.storage.database import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    # Serialized G2 IBE private key (app.crypto.serialization.G2_POINT_SIZE = 96 bytes).
    ibe_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class Message(Base):
    __tablename__ = "messages"

    message_id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Serialized G1 ephemeral point (48 bytes), HKDF salt (32 bytes),
    # AES-GCM nonce (12 bytes); ciphertext length varies with plaintext.
    ibe_u: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
