"""Pairing-based Identity-Based Encryption core (BLS12-381).

Only the ``optimized_bls12_381`` point family is used, matching the
recipient private key / master public key produced by :mod:`app.crypto.pkg`.
Mixing points from the plain (non-optimized) ``py_ecc.bls12_381`` module in
here would silently break pairing computations.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import G1, curve_order, multiply, pairing

from app.crypto.serialization import deserialize_g1, serialize_g1, serialize_gt
from app.crypto.symmetric import SymmetricDecryptionError, aes_decrypt, aes_encrypt

# Domain-separation tag for hashing identities to G2. Changing this value
# changes every identity's derived point (and therefore every private key
# extracted by the PKG), so it must stay fixed for the lifetime of a PKG.
IDENTITY_DST = b"IB_PROJECT_BLS12381G2_XMD:SHA-256_SSWU_RO_IDENTITY_V1"


class IBEError(ValueError):
    """An IBE ciphertext payload is malformed or could not be decrypted."""


@dataclass(frozen=True)
class IBECiphertext:
    """Everything decryption needs. Never carries key material or secrets."""

    u: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def hash_identity(identity: str) -> Any:
    """Map a normalized identity string to a point in G2 (``Q_ID``)."""
    if not identity:
        raise ValueError("identity must not be empty")
    return hash_to_G2(identity.encode("utf-8"), IDENTITY_DST, hashlib.sha256)


def _random_scalar() -> int:
    return secrets.randbelow(curve_order - 1) + 1


def encrypt(
    recipient_identity: str,
    master_public_key: Any,
    plaintext: bytes,
    aad: bytes,
) -> IBECiphertext:
    """Encrypt for ``recipient_identity`` using only public system parameters."""
    q_id = hash_identity(recipient_identity)
    r = _random_scalar()
    u_point = multiply(G1, r)
    shared_secret = pairing(q_id, master_public_key) ** r

    u_bytes = serialize_g1(u_point)
    salt, nonce, ciphertext = aes_encrypt(
        serialize_gt(shared_secret), recipient_identity, u_bytes, plaintext, aad
    )
    return IBECiphertext(u=u_bytes, salt=salt, nonce=nonce, ciphertext=ciphertext)


def decrypt(
    recipient_identity: str,
    recipient_private_key: Any,
    payload: IBECiphertext,
    aad: bytes,
) -> bytes:
    """Decrypt ``payload`` using the recipient's own extracted IBE private key."""
    try:
        u_point = deserialize_g1(payload.u)
    except ValueError as exc:
        raise IBEError("invalid ciphertext payload") from exc

    shared_secret = pairing(recipient_private_key, u_point)

    try:
        return aes_decrypt(
            serialize_gt(shared_secret),
            recipient_identity,
            payload.u,
            payload.salt,
            payload.nonce,
            payload.ciphertext,
            aad,
        )
    except SymmetricDecryptionError as exc:
        raise IBEError("decryption failed") from exc
