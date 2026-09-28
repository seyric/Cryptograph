"""seal - encryption, key wrapping and key management.

Holds the post-quantum primitives, the threshold-sharing scheme, the Merkle
tree and the container builder. `seal.pqc_adapter` is the single seam over
the post-quantum library, so the provider can be swapped without touching
any other package.
"""
