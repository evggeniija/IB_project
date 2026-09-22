"""Message send/inbox/decrypt business logic.

The caller (an API route) must resolve ``sender``/``user`` from the
authenticated session; this module never accepts a sender or recipient
identity as authoritative client input, and it never touches the PKG
master secret -- only the master *public* key, for encryption.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session as DBSession

from app.crypto.ibe import IBECiphertext, IBEError
from app.crypto.ibe import decrypt as ibe_decrypt
from app.crypto.ibe import encrypt as ibe_encrypt
from app.crypto.serialization import CryptoPayloadError, deserialize_g2
from app.services.auth_service import normalize_email
from app.storage.models import Message, User

AAD_VERSION = 1


class RecipientNotFoundError(Exception):
    """The normalized recipient identity has no registered user."""


class MessageAccessError(Exception):
    """The message doesn't exist, is malformed, or the caller isn't its recipient."""


class MessageDecryptionError(Exception):
    """Decryption failed. Never carries internal crypto failure detail."""


class MessageAlreadyProcessedError(Exception):
    """The message was already (or concurrently) claimed as decrypted."""


def _canonical_timestamp(timestamp: datetime) -> str:
    # SQLite drops tzinfo on round-trip, so a naive value read back from the
    # DB is treated as UTC (everything we store is already UTC) rather than
    # the local timezone, keeping this identical before and after a commit.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    else:
        timestamp = timestamp.astimezone(UTC)
    return timestamp.isoformat(timespec="microseconds")


def build_aad(
    message_id: str, sender_identity: str, recipient_identity: str, timestamp: datetime
) -> bytes:
    """Deterministic authenticated metadata bound to the ciphertext.

    This proves the stored metadata hasn't been altered relative to the
    ciphertext; it does not by itself prove who sent the message -- that
    comes from the authenticated session at send time.
    """
    metadata = {
        "version": AAD_VERSION,
        "message_id": message_id,
        "sender": sender_identity,
        "recipient": recipient_identity,
        "timestamp": _canonical_timestamp(timestamp),
    }
    return json.dumps(
        metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def send_message(
    db: DBSession,
    master_public_key: Any,
    sender: User,
    recipient: str,
    plaintext: str,
) -> Message:
    recipient_identity = normalize_email(recipient)
    recipient_user = db.query(User).filter_by(email=recipient_identity).one_or_none()
    if recipient_user is None:
        raise RecipientNotFoundError(recipient_identity)

    message_id = str(uuid.uuid4())
    timestamp = datetime.now(UTC)
    aad = build_aad(message_id, sender.email, recipient_identity, timestamp)

    payload = ibe_encrypt(recipient_identity, master_public_key, plaintext.encode("utf-8"), aad)

    message = Message(
        message_id=message_id,
        sender_id=sender.id,
        recipient_id=recipient_user.id,
        timestamp=timestamp,
        ibe_u=payload.u,
        salt=payload.salt,
        nonce=payload.nonce,
        ciphertext=payload.ciphertext,
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


def get_inbox(db: DBSession, user: User) -> list[tuple[Message, str]]:
    """Return (message, sender_email) pairs addressed to ``user``, metadata only."""
    return (
        db.query(Message, User.email)
        .join(User, User.id == Message.sender_id)
        .filter(Message.recipient_id == user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )


def _get_owned_message(db: DBSession, user: User, message_id: str) -> Message:
    # Reject anything that can't possibly be one of our server-generated
    # UUID4 ids before ever touching the DB, so a malformed id fails the
    # same clean way a nonexistent one does.
    try:
        uuid.UUID(message_id)
    except (ValueError, AttributeError, TypeError):
        raise MessageAccessError(message_id) from None

    message = db.get(Message, message_id)
    if message is None or message.recipient_id != user.id:
        raise MessageAccessError(message_id)
    return message


def _claim_message_processed(db: DBSession, user: User, message_id: str) -> bool:
    """Atomically flip ``processed`` False -> True; True iff we won the claim.

    Equivalent to ``UPDATE messages SET processed=1 WHERE message_id=? AND
    recipient_id=? AND processed=0``: if two requests decrypt the same
    message concurrently, only one row-affecting UPDATE can succeed.
    """
    result = db.execute(
        update(Message)
        .where(
            Message.message_id == message_id,
            Message.recipient_id == user.id,
            Message.processed.is_(False),
        )
        .values(processed=True)
    )
    db.commit()
    return result.rowcount == 1


def decrypt_message(db: DBSession, user: User, message_id: str) -> str:
    # Authorization happens before any cryptographic work.
    message = _get_owned_message(db, user, message_id)

    # A cheap pre-check so an already-processed message never pays for a
    # pairing/AES decrypt; the atomic claim below is what actually makes
    # this safe under concurrent requests, not this check by itself.
    if message.processed:
        raise MessageAlreadyProcessedError(message_id)

    sender = db.get(User, message.sender_id)
    if sender is None:
        raise MessageDecryptionError(message_id)

    aad = build_aad(message.message_id, sender.email, user.email, message.timestamp)
    payload = IBECiphertext(
        u=message.ibe_u, salt=message.salt, nonce=message.nonce, ciphertext=message.ciphertext
    )

    try:
        private_key = deserialize_g2(user.ibe_private_key)
        plaintext_bytes = ibe_decrypt(user.email, private_key, payload, aad)
    except (CryptoPayloadError, IBEError) as exc:
        # Never claim `processed` for a decryption that didn't actually
        # succeed -- a failed/tampered attempt must not burn the replay slot.
        raise MessageDecryptionError(message_id) from exc

    if not _claim_message_processed(db, user, message_id):
        # Another request decrypted this message first; discard our
        # correctly-decrypted plaintext rather than returning it twice.
        raise MessageAlreadyProcessedError(message_id)

    return plaintext_bytes.decode("utf-8")
