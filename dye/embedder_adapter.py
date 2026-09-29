"""The watermark channel seam.

Everything that embeds or recovers a codeword goes through `TextLayerAdapter`.
Callers (`seal.container`, `bridge.session`, `hound.attribution`) depend on this
interface, not on the PDF library, so a second channel - a pixel layer for
photographed screens, for example - can be added later without any of them
changing.

Today the only implementation is the typographic channel: it shifts PDF word
spacing by a fixed delta to encode one bit per block.

    embed:  blocks, page metadata and a codeword  ->  watermarked PDF bytes
    extract: PDF bytes                              ->  recovered bits + confidence
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from .assembler import VariantGenerator
from .extractor import WatermarkExtractor
from .text_layer import PDFSegmenter, TextBlock


class TextLayerAdapter:
    """Embed and extract the typographic codeword channel."""

    #: Word-spacing delta, in PostScript points, between the two variants.
    #: The decoder decides at half of this value.
    DELTA_PT = 0.750

    def __init__(self, lines_per_block: int = 3) -> None:
        self.lines_per_block = lines_per_block

    def segment(
        self, pdf_path: str, lines_per_block: int | None = None
    ) -> Tuple[List[TextBlock], Dict[str, Any]]:
        """Split a document into variation blocks, one bit each."""
        return PDFSegmenter.segment_pdf(
            pdf_path,
            lines_per_block=self.lines_per_block if lines_per_block is None else lines_per_block,
        )

    def embed(
        self,
        blocks: Sequence[TextBlock],
        doc_meta: Dict[str, Any],
        codeword: Sequence[int],
    ) -> bytes:
        """Render the codeword into a watermarked PDF.

        Bit 0 selects the unshifted variant, bit 1 the shifted one, so the
        rendered text is identical either way.
        """
        return VariantGenerator.assemble_pdf(list(blocks), doc_meta, list(codeword))

    def extract(
        self,
        pdf_input: str | bytes,
        total_blocks: int,
        lines_per_block: int | None = None,
    ) -> Tuple[List[int], List[float]]:
        """Recover a codeword from a document, with per-block confidence.

        Two strategies are tried in order: reading the content-stream operators
        directly, then measuring rendered word gaps geometrically. The second is
        the one that survives re-rendering — see the module docstring in
        `dye.extractor`. Use :meth:`extract_with_report` when you need to know
        which one ran.
        """
        bits, confidences, _strategy = self.extract_with_report(
            pdf_input, total_blocks, lines_per_block
        )
        return bits, confidences

    def extract_with_report(
        self,
        pdf_input: str | bytes,
        total_blocks: int,
        lines_per_block: int | None = None,
    ) -> Tuple[List[int], List[float], str]:
        """As :meth:`extract`, but also names the strategy that produced it."""
        return WatermarkExtractor.extract_with_report(
            pdf_input,
            total_expected_blocks=total_blocks,
            lines_per_block=self.lines_per_block if lines_per_block is None else lines_per_block,
        )

    def block_count(self, pdf_path: str, lines_per_block: int | None = None) -> int:
        """Number of variation bits a document yields."""
        _blocks, doc_meta = self.segment(pdf_path, lines_per_block)
        return int(doc_meta["total_blocks"])


__all__ = ["TextLayerAdapter"]
