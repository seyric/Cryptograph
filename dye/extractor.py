"""Forensic watermark extractor.

Two strategies, and the difference matters for how much the result is worth:

- **content_stream** — reads the `Tw` operators straight out of the PDF content
  stream. This is the *encoding*, not a measurement: it works only while the
  leaked file still carries those operators, and it says nothing about a file
  that has been re-rendered, printed or photographed. It is a diagnostic
  shortcut, not evidence, so it is labelled as such and never reported at
  full confidence.
- **geometric** — measures rendered word gaps from the extracted layout. This is
  the evidence-grade path: it survives re-rendering, because it observes the
  output rather than the writer's intent. It is weaker — it can be perturbed by
  font substitution or re-typesetting — and its confidence reflects the measured
  margin, not a flat maximum.

Attribution must record which strategy produced a codeword, because a verdict
resting on `content_stream` is a different claim from one resting on `geometric`.
"""

import re
from typing import List, Tuple, Union

import fitz  # PyMuPDF

# Decision boundary for standard 11pt font
DEFAULT_GAP_DECISION_THRESHOLD = 3.433

STRATEGY_CONTENT_STREAM = "content_stream"
STRATEGY_GEOMETRIC = "geometric"

#: Confidence assigned to content-stream extraction. It reads the writer's own
#: encoding, so it is internally exact but carries no evidence that the mark
#: survived anything — reporting 1.0 overstates what was actually shown.
CONTENT_STREAM_CONFIDENCE = 0.5


class WatermarkExtractor:
    """Extracts forensic word-spacing watermarks from PDF files or byte streams."""

    @classmethod
    def extract_with_report(
        cls,
        pdf_input: Union[str, bytes],
        total_expected_blocks: int,
        lines_per_block: int = 3,
    ) -> Tuple[List[int], List[float], str]:
        """Extract a codeword and say how it was obtained.

        Returns:
            ``(recovered_bits, confidences, strategy)`` where ``strategy`` is
            :data:`STRATEGY_CONTENT_STREAM` or :data:`STRATEGY_GEOMETRIC`.
        """
        return cls._extract(pdf_input, total_expected_blocks, lines_per_block)

    @classmethod
    def extract_from_pdf(
        cls,
        pdf_input: Union[str, bytes],
        total_expected_blocks: int,
        lines_per_block: int = 3
    ) -> Tuple[List[int], List[float]]:
        """Extract recovered codeword bits from a leaked PDF.

        Back-compatible form of :meth:`extract_with_report` that discards the
        strategy. Callers producing evidence should keep the strategy.
        """
        bits, confidences, _strategy = cls._extract(
            pdf_input, total_expected_blocks, lines_per_block
        )
        return bits, confidences

    @classmethod
    def _extract(
        cls,
        pdf_input: Union[str, bytes],
        total_expected_blocks: int,
        lines_per_block: int,
    ) -> Tuple[List[int], List[float], str]:
        if isinstance(pdf_input, (bytes, bytearray)):
            doc = fitz.open(stream=pdf_input, filetype="pdf")
        else:
            doc = fitz.open(pdf_input)

        # --------------------------------------------------------------------
        # Strategy 1: read the Tw operators out of the content stream.
        # Diagnostic shortcut: it observes what the writer encoded, not what the
        # document renders as, so it only holds while those operators survive.
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
            # Read the writer's own encoding: internally exact, but unproven as
            # evidence that the mark survived anything. Never claim full confidence.
            return (
                recovered_bits,
                [CONTENT_STREAM_CONFIDENCE] * total_expected_blocks,
                STRATEGY_CONTENT_STREAM,
            )

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

        # Geometric measurement: the evidence-grade path, because it observes
        # what the document renders rather than what the writer encoded.
        return recovered_bits, confidences, STRATEGY_GEOMETRIC
