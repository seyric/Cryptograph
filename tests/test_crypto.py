"""Comprehensive Unit Tests for the CANARY TRAP Cryptographic Subsystem.

Tests:
1. NIST FIPS 203 ML-KEM-768 key encapsulation, decapsulation, and tampering resistance.
2. NIST FIPS 204 ML-DSA-65 key generation, signing, verification, and tamper detection.
3. Hand-rolled Shamir Secret Sharing over prime field F_p (all 3-of-4 combinations, threshold enforcement).
4. Hand-rolled Binary Merkle Tree with domain separation (0x00/0x01) and audit proof verification.
5. RFC 8785 Canonical JSON determinism.
"""

import os
import itertools

from seal.sharing import ShamirSecretSharing
from seal.merkle import MerkleTree, verify_merkle_proof, hash_leaf, hash_children
from seal.pqc_adapter import MLKEM768, MLDSA65, canonical_json, b64_encode


# ============================================================================
# 1. NIST FIPS 203 ML-KEM-768 Tests
# ============================================================================

def test_ml_kem_768_standard_sizes():
    """Verify exact standard byte lengths per NIST FIPS 203."""
    ek, dk = MLKEM768.keygen()
    assert len(ek) == MLKEM768.PUBLIC_KEY_SIZE == 1184
    assert len(dk) == MLKEM768.SECRET_KEY_SIZE == 2400

    ss, ct = MLKEM768.encaps(ek)
    assert len(ss) == MLKEM768.SHARED_SECRET_SIZE == 32
    assert len(ct) == MLKEM768.CIPHERTEXT_SIZE == 1088


def test_ml_kem_768_encaps_decaps_roundtrip():
    """Verify that decapsulation successfully recovers the encapsulated shared secret."""
    ek, dk = MLKEM768.keygen()
    ss_sender, ct = MLKEM768.encaps(ek)
    ss_receiver = MLKEM768.decaps(dk, ct)

    assert ss_sender == ss_receiver
    assert len(ss_receiver) == 32


def test_ml_kem_768_tamper_ciphertext():
    """Verify that decapsulation of a corrupted ciphertext does not yield the original secret."""
    ek, dk = MLKEM768.keygen()
    ss, ct = MLKEM768.encaps(ek)

    # Flip one byte in the ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[50] ^= 0xFF
    recovered = MLKEM768.decaps(dk, bytes(tampered_ct))

    # In ML-KEM (implicit rejection), decapsulating an invalid ciphertext returns a pseudorandom key
    assert recovered != ss


# ============================================================================
# 2. NIST FIPS 204 ML-DSA-65 Tests
# ============================================================================

def test_ml_dsa_65_standard_sizes():
    """Verify exact standard byte lengths per NIST FIPS 204."""
    vk, sk = MLDSA65.keygen()
    assert len(vk) == MLDSA65.PUBLIC_KEY_SIZE == 1952
    assert len(sk) == MLDSA65.SECRET_KEY_SIZE == 4032

    msg = b"CANARY TRAP TRANSACTION VERIFICATION"
    sig = MLDSA65.sign(sk, msg)
    assert len(sig) == MLDSA65.SIGNATURE_SIZE == 3309


def test_ml_dsa_65_sign_verify_bytes():
    """Verify signature generation and verification on raw bytes."""
    vk, sk = MLDSA65.keygen()
    msg = os.urandom(64)
    sig = MLDSA65.sign(sk, msg)

    assert MLDSA65.verify(vk, msg, sig) is True


def test_ml_dsa_65_sign_verify_dict():
    """Verify signing and verifying canonical JSON dictionary payloads."""
    vk, sk = MLDSA65.keygen()
    payload = {
        "doc_id": "DOC_2026_01",
        "recipient_id": "ALICE",
        "timestamp": 1773880000,
        "nonce": "abcdef0123456789"
    }
    sig = MLDSA65.sign(sk, payload)

    assert MLDSA65.verify(vk, payload, sig) is True


def test_ml_dsa_65_tamper_detection():
    """Verify that any modification to message, signature, or key rejects verification."""
    vk, sk = MLDSA65.keygen()
    msg = b"INTEGRITY PROTECTED AUDIT RECORD"
    sig = MLDSA65.sign(sk, msg)

    # 1. Tampered message
    assert MLDSA65.verify(vk, b"INTEGRITY ALTERED RECORD", sig) is False

    # 2. Tampered signature byte
    tampered_sig = bytearray(sig)
    tampered_sig[100] ^= 0xAA
    assert MLDSA65.verify(vk, msg, bytes(tampered_sig)) is False

    # 3. Wrong public key
    vk2, _ = MLDSA65.keygen()
    assert MLDSA65.verify(vk2, msg, sig) is False


# ============================================================================
# 3. Hand-Rolled Shamir Secret Sharing Tests
# ============================================================================

def test_shamir_3_of_4_all_combinations():
    """Verify that ANY 3 of 4 shares reconstruct the exact 32-byte secret."""
    for _ in range(3):
        secret = os.urandom(32)
        shares = ShamirSecretSharing.split(secret, t=3, n=4)
        assert len(shares) == 4

        # Test all C(4, 3) = 4 combinations
        for subset in itertools.combinations(shares, 3):
            reconstructed = ShamirSecretSharing.reconstruct(list(subset))
            assert reconstructed == secret, f"Failed for subset {[s[0] for s in subset]}"

        # Test all 4 shares together
        reconstructed_all = ShamirSecretSharing.reconstruct(shares)
        assert reconstructed_all == secret


def test_shamir_threshold_enforcement():
    """Verify that fewer than t shares cannot reconstruct the secret."""
    secret = os.urandom(32)
    shares = ShamirSecretSharing.split(secret, t=3, n=4)

    # Any 2 shares must NOT equal the secret
    for subset in itertools.combinations(shares, 2):
        reconstructed_2 = ShamirSecretSharing.reconstruct(list(subset))
        assert reconstructed_2 != secret


def test_shamir_arbitrary_thresholds():
    """Verify Shamir SSS with alternative parameters: (t=2, n=3) and (t=4, n=5)."""
    secret = os.urandom(32)

    # t=2, n=3
    shares_2_3 = ShamirSecretSharing.split(secret, t=2, n=3)
    for subset in itertools.combinations(shares_2_3, 2):
        assert ShamirSecretSharing.reconstruct(list(subset)) == secret

    # t=4, n=5
    shares_4_5 = ShamirSecretSharing.split(secret, t=4, n=5)
    for subset in itertools.combinations(shares_4_5, 4):
        assert ShamirSecretSharing.reconstruct(list(subset)) == secret


# ============================================================================
# 4. Hand-Rolled Binary Merkle Tree Tests
# ============================================================================

def test_merkle_domain_separation():
    """Verify that domain separation prefixes (0x00, 0x01) prevent second-preimage collision."""
    data = b"sample leaf payload"
    leaf_h = hash_leaf(data)
    node_h = hash_children(b"A" * 32, b"B" * 32)

    assert leaf_h != node_h
    # Leaf hash must start with SHA3 of 0x00 prefix
    import hashlib
    assert leaf_h == hashlib.sha3_256(b"\x00" + data).digest()


def test_merkle_proofs_even_and_odd_leaves():
    """Verify Merkle tree construction and inclusion proofs for both even and odd leaf counts."""
    for leaf_count in [1, 2, 3, 4, 5, 7, 8, 15, 16]:
        leaves = [f"ENTRY_PAYLOAD_{i}".encode("utf-8") for i in range(leaf_count)]
        tree = MerkleTree(leaves)
        root = tree.root
        assert len(root) == 32

        # Verify inclusion proof for every single leaf
        for idx in range(leaf_count):
            proof = tree.get_proof(idx)
            is_valid = verify_merkle_proof(leaves[idx], proof, root)
            assert is_valid is True, f"Inclusion proof failed for leaf {idx} in tree of {leaf_count}"

            # Tampered leaf must fail verification
            tampered_leaf = leaves[idx] + b"_TAMPERED"
            assert verify_merkle_proof(tampered_leaf, proof, root) is False


def test_merkle_proof_tampered_sibling():
    """Verify that modifying a hash in the Merkle proof path rejects verification."""
    leaves = [f"ENTRY_{i}".encode("utf-8") for i in range(8)]
    tree = MerkleTree(leaves)
    proof = tree.get_proof(3)

    # Tamper with the first sibling in the proof path
    tampered_proof = [
        {"position": p["position"], "hash": bytearray(p["hash"])}
        for p in proof
    ]
    tampered_proof[0]["hash"][0] ^= 0xFF
    tampered_proof[0]["hash"] = bytes(tampered_proof[0]["hash"])

    assert verify_merkle_proof(leaves[3], tampered_proof, tree.root) is False


# ============================================================================
# 5. Canonical JSON Serialization Tests
# ============================================================================

def test_canonical_json_determinism():
    """Verify RFC 8785 compliance: key insertion order does not affect canonical bytes."""
    dict1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    dict2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}

    bytes1 = canonical_json(dict1)
    bytes2 = canonical_json(dict2)

    assert bytes1 == bytes2
    assert bytes1 == b'{"a":2,"m":{"a":4,"b":3},"z":1}'
