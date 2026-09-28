"""NIST Post-Quantum Cryptography Wrappers for CANARY TRAP.

Implements standard interfaces for:
- ML-KEM-768 (NIST FIPS 203): Key Encapsulation Mechanism
- ML-DSA-65 (NIST FIPS 204): Module-Lattice Digital Signature Standard

Includes RFC 8785 JSON Canonicalization Scheme (JCS) helper for deterministic signing.
"""

import base64
import json
from typing import Tuple, Dict, Any, Union

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65


def b64_encode(data: bytes) -> str:
    """Encode bytes to ASCII Base64 string."""
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    """Decode ASCII Base64 string to bytes."""
    return base64.b64decode(data.encode("ascii"))


def canonical_json(data: Dict[str, Any]) -> bytes:
    """Canonicalize a dictionary to deterministic UTF-8 bytes following RFC 8785 (JCS).
    
    Sorts dictionary keys recursively, removes whitespace, and ensures stable representation.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class MLKEM768:
    """NIST FIPS 203 ML-KEM-768 Key Encapsulation Mechanism."""

    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    @classmethod
    def keygen(cls) -> Tuple[bytes, bytes]:
        """Generate an ML-KEM-768 keypair.
        
        Returns:
            (encapsulation_key, decapsulation_key) as raw bytes.
        """
        ek, dk = ML_KEM_768.keygen()
        return bytes(ek), bytes(dk)

    @classmethod
    def encaps(cls, ek: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a fresh shared secret to the encapsulation key ek.
        
        Args:
            ek: 1184-byte ML-KEM-768 public encapsulation key.
            
        Returns:
            (shared_secret, ciphertext) tuple.
            shared_secret is 32 bytes; ciphertext is 1088 bytes.
        """
        if len(ek) != cls.PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 public key size: expected {cls.PUBLIC_KEY_SIZE}, got {len(ek)}")
        key, ct = ML_KEM_768.encaps(ek)
        return bytes(key), bytes(ct)

    @classmethod
    def decaps(cls, dk: bytes, ct: bytes) -> bytes:
        """Decapsulate the shared secret using decapsulation key dk and ciphertext ct.
        
        Args:
            dk: 2400-byte ML-KEM-768 private decapsulation key.
            ct: 1088-byte ML-KEM-768 ciphertext.
            
        Returns:
            32-byte recovered shared secret.
        """
        if len(dk) != cls.SECRET_KEY_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 secret key size: expected {cls.SECRET_KEY_SIZE}, got {len(dk)}")
        if len(ct) != cls.CIPHERTEXT_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 ciphertext size: expected {cls.CIPHERTEXT_SIZE}, got {len(ct)}")
        recovered_key = ML_KEM_768.decaps(dk, ct)
        return bytes(recovered_key)


class MLDSA65:
    """NIST FIPS 204 ML-DSA-65 Digital Signature Algorithm."""

    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4032
    SIGNATURE_SIZE = 3309

    @classmethod
    def keygen(cls) -> Tuple[bytes, bytes]:
        """Generate an ML-DSA-65 keypair.
        
        Returns:
            (verification_key, signing_key) as raw bytes.
        """
        vk, sk = ML_DSA_65.keygen()
        return bytes(vk), bytes(sk)

    @classmethod
    def sign(cls, sk: bytes, message: Union[bytes, str, Dict[str, Any]]) -> bytes:
        """Sign a message using private signing key sk.
        
        Args:
            sk: 4032-byte ML-DSA-65 private signing key.
            message: Raw bytes, string, or canonicalizable dict.
            
        Returns:
            3309-byte ML-DSA-65 signature.
        """
        if isinstance(message, dict):
            msg_bytes = canonical_json(message)
        elif isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be bytes, str, or dict")

        sig = ML_DSA_65.sign(sk, msg_bytes)
        return bytes(sig)

    @classmethod
    def verify(cls, vk: bytes, message: Union[bytes, str, Dict[str, Any]], signature: bytes) -> bool:
        """Verify an ML-DSA-65 digital signature against public verification key vk.
        
        Args:
            vk: 1952-byte ML-DSA-65 public verification key.
            message: Raw bytes, string, or canonicalizable dict.
            signature: 3309-byte signature.
            
        Returns:
            True if valid, False otherwise.
        """
        if len(vk) != cls.PUBLIC_KEY_SIZE:
            return False
        if len(signature) != cls.SIGNATURE_SIZE:
            return False

        if isinstance(message, dict):
            msg_bytes = canonical_json(message)
        elif isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be bytes, str, or dict")

        try:
            return bool(ML_DSA_65.verify(vk, msg_bytes, signature))
        except Exception:
            return False
