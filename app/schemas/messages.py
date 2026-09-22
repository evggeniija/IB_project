"""Request/response schemas for the messaging API.

None of these expose ciphertext components, the recipient's private key,
or any PKG material.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class SendMessageRequest(BaseModel):
    recipient: EmailStr
    message: str = Field(min_length=1)


class SendMessageResponse(BaseModel):
    message_id: str
    recipient: str
    timestamp: datetime


class InboxMessage(BaseModel):
    message_id: str
    sender: str
    timestamp: datetime
    processed: bool


class DecryptResponse(BaseModel):
    message_id: str
    plaintext: str
