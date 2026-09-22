"""Messaging routes: send, inbox listing, and decrypt.

Sender identity always comes from the authenticated session
(``get_current_user``), never from a client-supplied field.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.api.auth import get_current_user, get_db
from app.schemas.messages import (
    DecryptResponse,
    InboxMessage,
    SendMessageRequest,
    SendMessageResponse,
)
from app.services.auth_service import normalize_email
from app.services.message_service import (
    MessageAccessError,
    MessageAlreadyProcessedError,
    MessageDecryptionError,
    RecipientNotFoundError,
    decrypt_message,
    get_inbox,
    send_message,
)
from app.storage.models import User

router = APIRouter(prefix="/api/messages", tags=["messages"])


@router.post("", response_model=SendMessageResponse, status_code=status.HTTP_201_CREATED)
def send(
    payload: SendMessageRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
) -> SendMessageResponse:
    master_public_key = request.app.state.master_public_key
    try:
        message = send_message(db, master_public_key, user, payload.recipient, payload.message)
    except RecipientNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="recipient not found"
        ) from None

    return SendMessageResponse(
        message_id=message.message_id,
        recipient=normalize_email(payload.recipient),
        timestamp=message.timestamp,
    )


@router.get("/inbox", response_model=list[InboxMessage])
def inbox(
    user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
) -> list[InboxMessage]:
    rows = get_inbox(db, user)
    return [
        InboxMessage(
            message_id=message.message_id,
            sender=sender_email,
            timestamp=message.timestamp,
            processed=message.processed,
        )
        for message, sender_email in rows
    ]


@router.post("/{message_id}/decrypt", response_model=DecryptResponse)
def decrypt(
    message_id: str,
    user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
) -> DecryptResponse:
    try:
        plaintext = decrypt_message(db, user, message_id)
    except MessageAccessError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="message not found"
        ) from None
    except MessageAlreadyProcessedError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="message already processed"
        ) from None
    except MessageDecryptionError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="unable to decrypt message"
        ) from None

    return DecryptResponse(message_id=message_id, plaintext=plaintext)
