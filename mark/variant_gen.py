"""PDF Document Assembly and Variant Stitching for CANARY TRAP.

Assembles a complete, forensically watermarked PDF document in memory by combining
codeword-selected variant content streams across all pages.
"""

from typing import List, Dict, Any
import fitz
from .segmenter import TextBlock


class VariantGenerator:
    """Combines variant streams according to a codeword into a compliant PDF."""

    @classmethod
    def assemble_pdf(
        cls,
        blocks: List[TextBlock],
        doc_meta: Dict[str, Any],
        codeword: List[int]
    ) -> bytes:
        """Assemble a complete PDF in memory given a list of TextBlocks and a codeword.
        
        Args:
            blocks: List of TextBlock objects.
            doc_meta: Document metadata dictionary containing page dimensions.
            codeword: List of bits in {0, 1} matching len(blocks).
            
        Returns:
            Raw PDF bytes of the watermarked document.
        """
        if len(blocks) != len(codeword):
            raise ValueError(f"Block count ({len(blocks)}) does not match codeword length ({len(codeword)})")

        doc = fitz.open()

        # Group blocks by page_idx
        page_blocks: Dict[int, List[TextBlock]] = {}
        for b in blocks:
            page_blocks.setdefault(b.page_idx, []).append(b)

        # Create pages
        for page_meta in doc_meta.get("pages", []):
            page_idx = page_meta["page_idx"]
            w = page_meta.get("width", 595.0)
            h = page_meta.get("height", 842.0)
            page = doc.new_page(page_idx, width=w, height=h)

            # Insert font resource
            page.insert_font(fontname="helv", fontbuffer=fitz.Font("helv").buffer)

            # Add placeholder text to establish contents xref
            page.insert_text((0, 0), "")
            contents_xrefs = page.get_contents()
            if not contents_xrefs:
                page.insert_text((72, 72), " ")
                contents_xrefs = page.get_contents()
            xref = contents_xrefs[0]

            # Concatenate selected variant streams for this page
            page_stream_parts = []
            for b in page_blocks.get(page_idx, []):
                variant_choice = codeword[b.block_idx]
                if variant_choice == 1:
                    page_stream_parts.append(b.variant_1_stream)
                else:
                    page_stream_parts.append(b.variant_0_stream)

            full_page_stream = b"".join(page_stream_parts)
            doc.update_stream(xref, full_page_stream)

        pdf_bytes = doc.tobytes(deflate=True, clean=True)
        doc.close()
        return pdf_bytes
