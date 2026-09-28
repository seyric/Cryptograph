"""The quorum certificate: one definition of what validators sign.

Before this module there were three incompatible notions of "the message a
validator signs":

- the proposer signed a candidate header whose ``merkle_root`` was 64 zeroes,
  because the real root was not known until commit;
- the offline verifier checked signatures against the raw block-hash bytes;
- the verifier accepted any signature whose public key was absent from the
  bundle.

All three are replaced by one definition here. A validator signs
:func:`signing_bytes`, which commits to the height, the previous block hash, the
real Merkle root, the timestamp and the proposer. Because the Merkle root is
part of the signed bytes, a signature cannot be transplanted onto different
entries, and :func:`verify_certificate` refuses any validator whose public key is
missing rather than counting it as agreement.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

from seal.pqc_adapter import MLDSA65, b64_encode, canonical_json

#: Minimum number of distinct validator signatures for a block to be valid.
#: With 4 nodes tolerating f=1, the standard threshold is 2f+1 = 3.
QUORUM_THRESHOLD = 3

#: Bumped when the signing format changes, so old evidence can be identified.
CERTIFICATE_VERSION = "canarytrap-blockcert-v1"


def signing_bytes(
    height: int,
    prev_hash: str,
    merkle_root: str,
    timestamp: int,
    proposer_id: str,
) -> bytes:
    """Return the exact byte string a validator signs for a block.

    ``merkle_root`` must be the real root over the block's entries, not a
    placeholder, so a signature cannot be reused for different contents.
    """
    return canonical_json(
        {
            "height": height,
            "prev_hash": prev_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "proposer_id": proposer_id,
        }
    )


def block_hash_for(
    height: int,
    prev_hash: str,
    merkle_root: str,
    timestamp: int,
    proposer_id: str,
) -> bytes:
    """Recompute a block hash from its header fields."""
    return hashlib.sha3_256(
        signing_bytes(height, prev_hash, merkle_root, timestamp, proposer_id)
    ).digest()


@dataclass(frozen=True)
class QuorumCertificate:
    """A block header plus the signatures that agreed to it."""

    version: str
    height: int
    prev_hash: str
    merkle_root: str
    timestamp: int
    proposer_id: str
    block_hash: str
    signatures: Dict[str, bytes] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready form, with signatures base64-encoded."""
        return {
            "version": self.version,
            "height": self.height,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id,
            "block_hash": self.block_hash,
            "signatures": {vid: b64_encode(sig) for vid, sig in self.signatures.items()},
        }

    @property
    def signed_bytes(self) -> bytes:
        """The bytes each signature in this certificate covers."""
        return signing_bytes(
            self.height,
            self.prev_hash,
            self.merkle_root,
            self.timestamp,
            self.proposer_id,
        )


def verify_certificate(
    certificate: QuorumCertificate,
    validator_keys: Mapping[str, bytes],
    threshold: int = QUORUM_THRESHOLD,
) -> Tuple[bool, List[str], List[str]]:
    """Check that a certificate carries a genuine quorum.

    A validator whose public key is not in ``validator_keys`` is **rejected**,
    not silently counted: otherwise an administrator could pad a certificate
    with unverifiable signatures and still pass.

    Returns:
        ``(is_valid, valid_validator_ids, problems)``.
    """
    problems: List[str] = []

    if certificate.version != CERTIFICATE_VERSION:
        return False, [], [f"Unknown certificate version: {certificate.version}"]

    expected_hash = block_hash_for(
        certificate.height,
        certificate.prev_hash,
        certificate.merkle_root,
        certificate.timestamp,
        certificate.proposer_id,
    ).hex()
    if expected_hash != certificate.block_hash:
        problems.append(
            f"Block hash does not match its header: {expected_hash} != {certificate.block_hash}"
        )

    signed = certificate.signed_bytes
    valid: List[str] = []
    for validator_id, signature in sorted(certificate.signatures.items()):
        public_key = validator_keys.get(validator_id)
        if public_key is None:
            problems.append(
                f"Validator {validator_id}: no public key supplied, signature cannot be checked"
            )
            continue
        try:
            if MLDSA65.verify(public_key, signed, signature):
                valid.append(validator_id)
            else:
                problems.append(f"Validator {validator_id}: signature does not match the header")
        except Exception as exc:  # malformed key material must not be fatal
            problems.append(f"Validator {validator_id}: verification error ({exc})")

    if len(valid) < threshold:
        problems.append(
            f"Quorum not reached: {len(valid)} valid signature(s), {threshold} required"
        )

    return (not problems), valid, problems


__all__ = [
    "CERTIFICATE_VERSION",
    "QUORUM_THRESHOLD",
    "QuorumCertificate",
    "block_hash_for",
    "signing_bytes",
    "verify_certificate",
]

