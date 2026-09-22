"""PKG (Private Key Generator) master-key setup, extraction, and persistence.

The master secret must never be used for encryption, and encryption must
never require it (see ``app.crypto.ibe.encrypt``, which only takes the
master *public* key).

Importing this module has no filesystem side effects: the master key is
only read or created when ``load_or_create_master_secret`` is called.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from py_ecc.optimized_bls12_381 import G1, curve_order, multiply

from app.crypto.ibe import hash_identity

MasterSecret = int

DEFAULT_MASTER_KEY_PATH = Path("data/keys/master.key")
MASTER_KEY_LENGTH = 32  # bytes


class MasterKeyError(ValueError):
    """The on-disk PKG master key is missing, corrupted, or invalid.

    Never includes the secret scalar's value in its message.
    """


def generate_master_secret() -> MasterSecret:
    """Generate a fresh PKG master scalar ``s`` in ``[1, curve_order - 1]``."""
    return secrets.randbelow(curve_order - 1) + 1


def _validate_master_secret(master_secret: MasterSecret) -> None:
    if not (1 <= master_secret < curve_order):
        raise ValueError("master secret out of valid scalar range")


def derive_master_public_key(master_secret: MasterSecret) -> Any:
    """Compute the public system parameter ``Ppub = s * G1``."""
    _validate_master_secret(master_secret)
    return multiply(G1, master_secret)


def extract_private_key(master_secret: MasterSecret, identity: str) -> Any:
    """Derive an identity's IBE private key ``d_ID = s * Q_ID``.

    Only the PKG, which holds ``master_secret``, may call this.
    """
    _validate_master_secret(master_secret)
    q_id = hash_identity(identity)
    return multiply(q_id, master_secret)


# --- Persistence ---------------------------------------------------------


def _serialize_master_secret(master_secret: MasterSecret) -> bytes:
    return master_secret.to_bytes(MASTER_KEY_LENGTH, "big")


def _deserialize_master_secret(data: bytes) -> MasterSecret:
    if len(data) != MASTER_KEY_LENGTH:
        raise MasterKeyError("master key file has an invalid length")
    master_secret = int.from_bytes(data, "big")
    try:
        _validate_master_secret(master_secret)
    except ValueError as exc:
        raise MasterKeyError("master key file contains an invalid scalar") from exc
    return master_secret


def _ensure_key_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(directory, 0o700)


def _load_master_secret(path: Path) -> MasterSecret:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MasterKeyError("master key file could not be read") from exc
    return _deserialize_master_secret(data)


def _create_master_secret_file(path: Path, master_secret: MasterSecret) -> None:
    """Write a freshly generated key, failing if the file already exists.

    Raises ``FileExistsError`` if another process won the creation race;
    the caller must then load the file it created instead of overwriting it.
    """
    data = _serialize_master_secret(master_secret)
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def load_or_create_master_secret(
    path: Path | str = DEFAULT_MASTER_KEY_PATH,
) -> MasterSecret:
    """Load the persisted PKG master scalar, generating it on first run.

    An existing key is loaded and validated but never overwritten, even if
    it is malformed -- a malformed key must fail loudly rather than being
    silently regenerated, since that would strand existing recipients'
    private keys and ciphertexts.
    """
    path = Path(path)
    _ensure_key_directory(path.parent)

    if path.exists():
        return _load_master_secret(path)

    master_secret = generate_master_secret()
    try:
        _create_master_secret_file(path, master_secret)
    except FileExistsError:
        # Lost the creation race to another process; use what it wrote.
        return _load_master_secret(path)
    return master_secret
