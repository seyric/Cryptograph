"""CANARY TRAP Cryptographic Subsystem.

Provides:
- Hand-rolled Shamir Secret Sharing over prime field F_p (p = 2^256 + 297, smallest prime > 2^256)
- Hand-rolled Binary Merkle Tree with domain separation (RFC 6962 / SHA3-256)
- NIST FIPS 203 ML-KEM-768 Key Encapsulation Mechanism
- NIST FIPS 204 ML-DSA-65 Digital Signature Standard
"""

from .shamir import ShamirSecretSharing
from .merkle import MerkleTree, verify_merkle_proof
from .pqc import MLKEM768, MLDSA65, canonical_json

__all__ = [
    "ShamirSecretSharing",
    "MerkleTree",
    "verify_merkle_proof",
    "MLKEM768",
    "MLDSA65",
    "canonical_json",
]
