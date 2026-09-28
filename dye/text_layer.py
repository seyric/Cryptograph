"""PDF Layout Segmentation and Text Block Grouping for CANARY TRAP.

Parses input PDF documents, partitions text into sequential blocks, and generates
A/B variant content streams utilizing calibrated word-spacing (Tw) operators.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple
import fitz  # PyMuPDF


TW_BASELINE = 0.000  # Variant 0 (baseline word spacing)
TW_OFFSET = 0.750    # Variant 1 (micro-adjusted word spacing, 0.75 pt)


@dataclass
class TextLine:
    """Represents a single positioned line of text."""
    text: str
    x: float
    y_from_bottom: float
    font_name: str = "helv"
    font_size: float = 11.0


@dataclass
class TextBlock:
    """A variation block consisting of one or more text lines."""
    block_idx: int
    page_idx: int
    lines: List[TextLine] = field(default_factory=list)
    variant_0_stream: bytes = b""
    variant_1_stream: bytes = b""


class PDFSegmenter:
    """Segments a PDF document into variation blocks with dual-variant content streams."""

    @classmethod
    def segment_pdf(cls, pdf_path: str, lines_per_block: int = 3) -> Tuple[List[TextBlock], Dict[str, Any]]:
        """Extract text from a PDF and partition into TextBlocks with Variant 0 and Variant 1 streams.
        
        Args:
            pdf_path: Path to the input PDF.
            lines_per_block: Number of lines to group into each variation block (default 3).
            
        Returns:
            (blocks_list, document_metadata_dict)
        """
        doc = fitz.open(pdf_path)
        blocks: List[TextBlock] = []
        page_info: List[Dict[str, Any]] = []

        global_block_idx = 0

        for page_idx in range(len(doc)):
            page = doc[page_idx]
            rect = page.rect
            page_height = rect.height
            page_width = rect.width

            page_info.append({
                "page_idx": page_idx,
                "width": page_width,
                "height": page_height
            })

            # Extract structured text using PyMuPDF dict extraction for exact font metrics
            p_dict = page.get_text("dict")
            extracted_lines: List[TextLine] = []

            for b in p_dict.get("blocks", []):
                if "lines" not in b:
                    continue
                for l in b["lines"]:
                    for sp in l.get("spans", []):
                        txt = sp.get("text", "").strip()
                        if not txt:
                            continue
                        origin = sp.get("origin", (sp["bbox"][0], sp["bbox"][3]))
                        start_x = origin[0]
                        # Exact baseline coordinate in PDF coordinates
                        y_from_bottom = page_height - origin[1]
                        font_size = sp.get("size", 11.0)

                        extracted_lines.append(TextLine(
                            text=txt,
                            x=start_x,
                            y_from_bottom=y_from_bottom,
                            font_name="helv",
                            font_size=font_size
                        ))

            if not extracted_lines:
                continue

            # Batch lines into blocks
            for i in range(0, len(extracted_lines), lines_per_block):
                chunk = extracted_lines[i : i + lines_per_block]
                tb = TextBlock(
                    block_idx=global_block_idx,
                    page_idx=page_idx,
                    lines=chunk
                )
                tb.variant_0_stream = cls._render_block_stream(chunk, tw=TW_BASELINE)
                tb.variant_1_stream = cls._render_block_stream(chunk, tw=TW_OFFSET)
                blocks.append(tb)
                global_block_idx += 1

        doc.close()
        meta = {
            "total_pages": len(page_info),
            "pages": page_info,
            "total_blocks": len(blocks)
        }
        return blocks, meta

    @staticmethod
    def _render_block_stream(lines: List[TextLine], tw: float) -> bytes:
        """Render a list of TextLines into a PDF content stream with specified Tw word spacing."""
        parts = []
        for line in lines:
            # Escape PDF text delimiters
            escaped_text = line.text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream_snippet = (
                f"q\n"
                f"BT\n"
                f"1 0 0 1 {line.x:.2f} {line.y_from_bottom:.2f} Tm\n"
                f"/{line.font_name} {line.font_size:.1f} Tf\n"
                f"{tw:.3f} Tw\n"
                f"({escaped_text}) Tj\n"
                f"ET\n"
                f"Q\n"
            )
            parts.append(stream_snippet.encode("utf-8"))
        return b"".join(parts)
