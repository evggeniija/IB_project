"""HKDF-SHA256 key derivation and AES-256-GCM authenticated encryption."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"IB_PROJECT_BLS12381_AES256GCM_V1"
HKDF_SALT_SIZE = 32
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12


class SymmetricDecryptionError(ValueError):
    """Authenticated decryption failed (wrong key, tampered data, or bad AAD)."""


def _derive_key(shared_secret: bytes, salt: bytes, identity: str, u_bytes: bytes) -> bytes:
    # u_bytes is always exactly G1_POINT_SIZE bytes, so appending it after the
    # variable-length identity keeps this concatenation unambiguous.
    info = HKDF_INFO + identity.encode("utf-8") + u_bytes
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def aes_encrypt(
    shared_secret: bytes,
    identity: str,
    u_bytes: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes, bytes]:
    salt = secrets.token_bytes(HKDF_SALT_SIZE)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    key = _derive_key(shared_secret, salt, identity, u_bytes)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return salt, nonce, ciphertext


def aes_decrypt(
    shared_secret: bytes,
    identity: str,
    u_bytes: bytes,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    key = _derive_key(shared_secret, salt, identity, u_bytes)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise SymmetricDecryptionError("authenticated decryption failed") from exc
