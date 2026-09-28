"""CANARY TRAP Watermark Engine.

Provides:
- PDF Layout Segmentation into Batched Blocks
- Dual-Variant Generation using PDF Tw (word spacing) operators
- PRF-based Codeword Generation
- Forensic Watermark Extraction from PDF Content Streams
"""

from .segmenter import PDFSegmenter, TextBlock
from .variant_gen import VariantGenerator
from .extractor import WatermarkExtractor
from .codeword import generate_codeword_bits

__all__ = [
    "PDFSegmenter",
    "TextBlock",
    "VariantGenerator",
    "WatermarkExtractor",
    "generate_codeword_bits",
]
