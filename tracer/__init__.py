"""CANARY TRAP Forensic Investigation Lab.

Provides:
- Watermark extraction and session correlation scoring
- Leak attribution with false-accusation probability bounds
- Cryptographic evidence bundle generation
"""

from .accuse import ForensicAccuser, AccusationResult
from .evidence_bundle import EvidenceBundleBuilder

__all__ = [
    "ForensicAccuser",
    "AccusationResult",
    "EvidenceBundleBuilder",
]
