"""Hand-rolled Shamir Secret Sharing over prime field F_p.

Prime chosen: p = 2^256 + 297 (smallest prime strictly greater than 2^256).
This guarantees that any 256-bit symmetric key (AES-256, HMAC seed) is strictly
less than p, ensuring 100% bijective mapping into field elements without rejection.

Threshold parameters:
- t: Minimum threshold of shares required to reconstruct (default: 3)
- n: Total number of shares generated (default: 4)
"""

import os
from typing import List, Tuple

# Prime field modulus: smallest prime > 2^256
FIELD_PRIME = 2**256 + 297
SECRET_BYTE_LENGTH = 32
SHARE_VALUE_BYTE_LENGTH = 33  # ceil(257 / 8) = 33 bytes to hold values up to FIELD_PRIME - 1


class ShamirSecretSharing:
    """Information-theoretically secure Shamir Secret Sharing."""

    PRIME = FIELD_PRIME

    @classmethod
    def split(cls, secret: bytes, t: int = 3, n: int = 4) -> List[Tuple[int, bytes]]:
        """Split a 32-byte secret into n shares with threshold t.
        
        Args:
            secret: 32 bytes of raw secret data (e.g. AES-256 key).
            t: Threshold of shares needed to reconstruct (default 3).
            n: Total number of shares to generate (default 4).
            
        Returns:
            List of tuples (x, y_bytes) for x in 1..n.
        """
        if len(secret) != SECRET_BYTE_LENGTH:
            raise ValueError(f"Secret must be exactly {SECRET_BYTE_LENGTH} bytes, got {len(secret)}")
        if not (1 < t <= n):
            raise ValueError(f"Invalid threshold parameters: must satisfy 1 < t <= n (got t={t}, n={n})")

        # Convert secret to integer a_0
        a0 = int.from_bytes(secret, byteorder="big")
        if a0 >= cls.PRIME:
            raise ValueError("Secret integer exceeds field modulus")

        # Sample random coefficients a_1, ..., a_{t-1} uniformly from [1, PRIME - 1]
        coefficients = [a0]
        for _ in range(t - 1):
            coeff = int.from_bytes(os.urandom(33), byteorder="big") % cls.PRIME
            while coeff == 0:
                coeff = int.from_bytes(os.urandom(33), byteorder="big") % cls.PRIME
            coefficients.append(coeff)

        # Evaluate polynomial f(x) = sum(a_k * x^k) mod PRIME for x in 1..n
        shares = []
        for x in range(1, n + 1):
            y = 0
            x_pow = 1
            for coeff in coefficients:
                y = (y + coeff * x_pow) % cls.PRIME
                x_pow = (x_pow * x) % cls.PRIME
            shares.append((x, y.to_bytes(SHARE_VALUE_BYTE_LENGTH, byteorder="big")))

        return shares

    @classmethod
    def reconstruct(cls, shares: List[Tuple[int, bytes]]) -> bytes:
        """Reconstruct the original 32-byte secret from at least t shares using Lagrange interpolation.
        
        Args:
            shares: List of (x, y_bytes) tuples. Must contain at least t distinct shares.
            
        Returns:
            Original 32-byte secret.
        """
        if not shares:
            raise ValueError("No shares provided for reconstruction")

        # Deduplicate and validate shares
        unique_shares = {}
        for x, y_bytes in shares:
            if x <= 0:
                raise ValueError(f"Share index x must be positive, got {x}")
            if len(y_bytes) != SHARE_VALUE_BYTE_LENGTH:
                raise ValueError(f"Invalid share byte length: expected {SHARE_VALUE_BYTE_LENGTH}, got {len(y_bytes)}")
            y = int.from_bytes(y_bytes, byteorder="big")
            if y >= cls.PRIME:
                raise ValueError("Share value y exceeds field modulus")
            unique_shares[x] = y

        x_coords = list(unique_shares.keys())
        k = len(x_coords)
        if k < 2:
            raise ValueError("At least 2 shares required to attempt reconstruction")

        # Lagrange interpolation at x = 0:
        # f(0) = sum_{i=0}^{k-1} y_i * prod_{j != i} (-x_j) / (x_i - x_j) mod PRIME
        secret_int = 0
        for i, xi in enumerate(x_coords):
            yi = unique_shares[xi]
            num = 1
            den = 1
            for j, xj in enumerate(x_coords):
                if i == j:
                    continue
                num = (num * (-xj)) % cls.PRIME
                den = (den * (xi - xj)) % cls.PRIME

            # den^(-1) mod PRIME via Fermat's Little Theorem: den^(p - 2) mod p
            den_inv = pow(den, cls.PRIME - 2, cls.PRIME)
            lagrange_coeff = (num * den_inv) % cls.PRIME
            secret_int = (secret_int + yi * lagrange_coeff) % cls.PRIME

        return secret_int.to_bytes(SECRET_BYTE_LENGTH, byteorder="big")
