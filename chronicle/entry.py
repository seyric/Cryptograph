"""Entry hashing and canonical payload encoding.

This module is the single source of truth for how a ledger entry is turned into
its identity. Both the writer (`chronicle.ledger`) and the offline verifier
(`hound.verify`) call `compute_entry_hash`, because a divergence between the two
is precisely the kind of defect that would silently invalidate evidence.

Entry identity is:

    SHA3-256( 0x00 || entry_type || canonical_payload || signature )

The leading 0x00 keeps an entry hash in a different domain from a Merkle leaf
hash, which is prefixed 0x01 in `seal.merkle`.
"""

from __future__ import annotations

import hashlib
from typing import Union

from seal.pqc_adapter import canonical_json

# Domain separation byte prefixed to every entry hash.
ENTRY_DOMAIN = b"\x00"


def encode_payload(payload: Union[dict, str]) -> str:
    """Return the canonical string form of a payload for hashing.

    Dicts go through RFC 8785 style canonicalisation so that key order cannot
    change an entry's identity. Strings are taken as already canonical.
    """
    if isinstance(payload, dict):
        return canonical_json(payload).decode("utf-8")
    return str(payload)


def compute_entry_hash(
    entry_type: str,
    payload: Union[dict, str, bytes],
    signature: bytes,
) -> bytes:
    """Compute the 32-byte identity of a ledger entry.

    Args:
        entry_type: Entry discriminator such as ``ENROLL``, ``MANIFEST`` or
            ``DECRYPT_REQUEST``.
        payload: Dict (canonicalised here) or already-canonical string.
        signature: The ML-DSA-65 signature over the payload.

    Returns:
        The raw 32-byte SHA3-256 digest.
    """
    payload_str = encode_payload(payload)
    digest = hashlib.sha3_256()
    digest.update(ENTRY_DOMAIN)
    digest.update(entry_type.encode("utf-8"))
    digest.update(payload_str.encode("utf-8"))
    digest.update(signature)
    return digest.digest()


def compute_entry_hash_hex(
    entry_type: str,
    payload: Union[dict, str, bytes],
    signature: bytes,
) -> str:
    """Lowercase hex form of :func:`compute_entry_hash`, for logs and JSON."""
    return compute_entry_hash(entry_type, payload, signature).hex()


__all__: list[str] = [
    "ENTRY_DOMAIN",
    "compute_entry_hash",
    "compute_entry_hash_hex",
    "encode_payload",
]
