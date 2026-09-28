"""CANARY TRAP vault subsystem.

Hash-chained, tamper-evident ledger of provenance entries with RFC 9162 style
Merkle inclusion proofs.
"""

from vault.ledger import Ledger

__all__ = ["Ledger"]
