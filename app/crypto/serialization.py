"""Deterministic byte encodings for BLS12-381 group elements.

Only the ``optimized_bls12_381`` point representation (Jacobian coordinates)
is used anywhere in this project; it must never be mixed with the plain
``py_ecc.bls12_381`` (affine) module.
"""

from __future__ import annotations

from typing import Any

from py_ecc.bls.g2_primitives import subgroup_check
from py_ecc.bls.hash import i2osp, os2ip
from py_ecc.bls.point_compression import (
    compress_G1,
    compress_G2,
    decompress_G1,
    decompress_G2,
)
from py_ecc.optimized_bls12_381 import field_modulus

G1_POINT_SIZE = 48
G2_POINT_SIZE = 96
GT_COEFF_SIZE = 48
GT_COEFF_COUNT = 12
GT_SIZE = GT_COEFF_SIZE * GT_COEFF_COUNT


class CryptoPayloadError(ValueError):
    """A serialized crypto payload is malformed, invalid, or unsafe to use."""


def serialize_g1(point: Any) -> bytes:
    return i2osp(compress_G1(point), G1_POINT_SIZE)


def deserialize_g1(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)) or len(data) != G1_POINT_SIZE:
        raise CryptoPayloadError("G1 point must be exactly 48 bytes")
    try:
        # Broad on purpose: this parses untrusted input, and any failure
        # inside py_ecc's decompression (documented as ValueError, but not
        # guaranteed for every malformed input) must still fail closed as
        # a CryptoPayloadError rather than leak an internal exception type.
        point = decompress_G1(os2ip(bytes(data)))
    except Exception as exc:
        raise CryptoPayloadError("malformed G1 point encoding") from exc
    if not subgroup_check(point):
        raise CryptoPayloadError("G1 point is not in the correct subgroup")
    return point


def serialize_g2(point: Any) -> bytes:
    z1, z2 = compress_G2(point)
    half = G2_POINT_SIZE // 2
    return i2osp(z1, half) + i2osp(z2, half)


def deserialize_g2(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)) or len(data) != G2_POINT_SIZE:
        raise CryptoPayloadError("G2 point must be exactly 96 bytes")
    raw = bytes(data)
    half = G2_POINT_SIZE // 2
    z1, z2 = os2ip(raw[:half]), os2ip(raw[half:])
    try:
        # Broad on purpose; see the matching comment in deserialize_g1.
        point = decompress_G2((z1, z2))
    except Exception as exc:
        raise CryptoPayloadError("malformed G2 point encoding") from exc
    if not subgroup_check(point):
        raise CryptoPayloadError("G2 point is not in the correct subgroup")
    return point


def serialize_gt(value: Any) -> bytes:
    # Each FQ12 coefficient is already a plain int reduced mod field_modulus
    # (see py_ecc.fields.optimized_field_elements.FQP.__init__); no repr/str/
    # pickle is involved, only a fixed-width big-endian encoding per limb.
    return b"".join(i2osp(int(c) % field_modulus, GT_COEFF_SIZE) for c in value.coeffs)
