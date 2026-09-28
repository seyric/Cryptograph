"""Forensic Watermark Extractor for CANARY TRAP.

Inspects leaked PDF documents, analyzes word-spacing deltas across text blocks,
and reconstructs the recovered session codeword y in {0, 1}^M along with confidence scores.
"""

import re
from typing import List, Tuple, Union
import fitz  # PyMuPDF


# Decision boundary for standard 11pt font
DEFAULT_GAP_DECISION_THRESHOLD = 3.433


class WatermarkExtractor:
    """Extracts forensic word-spacing watermarks from PDF files or byte streams."""

    @classmethod
    def extract_from_pdf(
        cls,
        pdf_input: Union[str, bytes],
        total_expected_blocks: int,
        lines_per_block: int = 3
    ) -> Tuple[List[int], List[float]]:
        """Extract recovered codeword bits from a leaked PDF.
        
        Args:
            pdf_input: File path (str) or raw bytes of the leaked PDF.
            total_expected_blocks: Expected length of codeword M.
            lines_per_block: Number of lines grouped per block.
            
        Returns:
            (recovered_codeword, confidence_list)
        """
        if isinstance(pdf_input, (bytes, bytearray)):
            doc = fitz.open(stream=pdf_input, filetype="pdf")
        else:
            doc = fitz.open(pdf_input)

        # --------------------------------------------------------------------
        # Strategy 1: Direct Content Stream Operator Inspection (Ground Truth)
        # --------------------------------------------------------------------
        stream_line_bits: List[int] = []
        try:
            for page in doc:
                contents = page.get_contents()
                if not contents:
                    continue
                # Normalize contents into a list of xref integers
                xrefs = contents if isinstance(contents, list) else [contents]
                for xref in xrefs:
                    stream_bytes = doc.xref_stream(xref)
                    matches = re.findall(rb"([0-9.]+)\s+Tw", stream_bytes)
                    for m in matches:
                        tw_val = float(m)
                        stream_line_bits.append(1 if tw_val >= 0.375 else 0)
        except Exception:
            stream_line_bits = []

        if len(stream_line_bits) >= total_expected_blocks * lines_per_block:
            doc.close()
            recovered_bits = []
            for b_idx in range(total_expected_blocks):
                chunk = stream_line_bits[b_idx * lines_per_block : (b_idx + 1) * lines_per_block]
                bit = 1 if sum(chunk) > len(chunk) / 2.0 else 0
                recovered_bits.append(bit)
            return recovered_bits, [1.0] * total_expected_blocks

        # --------------------------------------------------------------------
        # Strategy 2: Font-Adaptive Geometric Word Gap Measurement (Fallback)
        # --------------------------------------------------------------------
        extracted_line_deltas: List[float] = []

        for page in doc:
            p_dict = page.get_text("dict")
            for b in p_dict.get("blocks", []):
                for l in b.get("lines", []):
                    spans = l.get("spans", [])
                    if not spans:
                        continue
                    font_size = spans[0].get("size", 11.0)
                    line_text = " ".join(sp.get("text", "").strip() for sp in spans)
                    words = line_text.split()
                    if len(words) < 2:
                        continue

                    # Expected natural space width for Helvetica is ~0.278 * font_size
                    base_space = 0.278 * font_size
                    threshold = base_space + 0.375

                    # Measure actual rendered width vs natural glyph width
                    rendered_width = l["bbox"][2] - l["bbox"][0]
                    total_spaces = max(1, len(words) - 1)
                    # Natural glyph width without space adjustments
                    glyph_width = fitz.get_text_length("".join(words), fontsize=font_size)
                    avg_space_width = (rendered_width - glyph_width) / float(total_spaces)

                    # Deviation from baseline threshold
                    delta = avg_space_width - threshold
                    extracted_line_deltas.append(delta)

        doc.close()

        recovered_bits = []
        confidences = []

        for b_idx in range(total_expected_blocks):
            start = b_idx * lines_per_block
            end = start + lines_per_block
            chunk = extracted_line_deltas[start:end]

            if not chunk:
                recovered_bits.append(0)
                confidences.append(0.0)
                continue

            avg_delta = sum(chunk) / len(chunk)
            bit = 1 if avg_delta >= 0.0 else 0
            conf = min(1.0, abs(avg_delta) / 0.35)

            recovered_bits.append(bit)
            confidences.append(float(conf))

        return recovered_bits, confidences
