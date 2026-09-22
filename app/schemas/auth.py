"""Request/response schemas for the auth API.

``UserPublic`` intentionally omits ``password_hash`` and ``ibe_private_key``
so they can never be serialized back to a client.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
