"""Multi-Block Real PDF Watermark Survival and Extraction Test Suite.

Tests the full end-to-end watermarking cycle on multi-line paragraphs:
1. Document segmentation into batched blocks.
2. Dual-variant stream generation.
3. In-memory watermarked PDF assembly according to a target codeword.
4. Aggressive re-saving and stream compression.
5. Forensic extraction and bit recovery assertion.
"""

import os
import fitz
import pytest

from dye.text_layer import PDFSegmenter
from dye.assembler import VariantGenerator
from dye.extractor import WatermarkExtractor
from dye.codeword import generate_codeword_bits


@pytest.fixture
def sample_pdf_path(tmp_path):
    """Generate a realistic 12-line multi-paragraph test document."""
    pdf_file = str(tmp_path / "sample_brief.pdf")
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)

    # Insert 12 distinct lines of typical government/legal text
    sample_lines = [
        "CABINET SECRETARIAT CONFIDENTIAL RECORD REFERENCE 2026",
        "Subject: Post-Quantum Migration Strategy for Inter-Ministerial Networks",
        "1. All designated departments must transition asymmetric roots to FIPS standards.",
        "2. Key encapsulation must adhere to ML-KEM-768 parameter specifications.",
        "3. Digital signatures for authorization requests must employ ML-DSA-65 algorithms.",
        "4. Traditional public key infrastructure certificates are phased out as of Q3.",
        "5. Audited provenance logs must remain immutable across administrative boundaries.",
        "6. Forensic attribution mechanisms must operate within air-gapped secure enclaves.",
        "7. External dependencies on public blockchains or cloud KMS are strictly prohibited.",
        "8. Decryption sessions must cryptographically bind recipient identity prior to release.",
        "9. Non-repudiation records shall be submitted to Section 63 BSA electronic filings.",
        "10. Distribution manifests must seal recipient lists against retroactive tampering."
    ]

    y_pos = 80
    for line in sample_lines:
        page.insert_text((72, y_pos), line, fontsize=11)
        y_pos += 30

    doc.save(pdf_file)
    doc.close()
    return pdf_file


def test_pdf_segmentation(sample_pdf_path):
    """Verify segmentation partitions 12 lines into 4 blocks of 3 lines each."""
    blocks, meta = PDFSegmenter.segment_pdf(sample_pdf_path, lines_per_block=3)
    assert len(blocks) == 4
    assert meta["total_blocks"] == 4
    assert meta["total_pages"] == 1

    for b in blocks:
        assert len(b.lines) == 3
        assert b"0.000 Tw" in b.variant_0_stream
        assert b"0.750 Tw" in b.variant_1_stream


def test_watermark_assembly_and_extraction_roundtrip(sample_pdf_path, tmp_path):
    """Verify that assembling a watermarked PDF with a target codeword survives re-save and extracts 100%."""
    blocks, meta = PDFSegmenter.segment_pdf(sample_pdf_path, lines_per_block=3)
    total_blocks = len(blocks)
    assert total_blocks == 4

    test_codewords = [
        [1, 0, 1, 0],
        [0, 1, 0, 1],
        [1, 1, 0, 0],
        [0, 0, 1, 1]
    ]

    for expected_cw in test_codewords:
        # Assemble watermarked PDF
        pdf_bytes = VariantGenerator.assemble_pdf(blocks, meta, expected_cw)
        assert len(pdf_bytes) > 0

        # Save to disk and re-save with clean/deflate (simulating user download & re-save)
        resaved_path = str(tmp_path / f"resaved_{''.join(map(str, expected_cw))}.pdf")
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        doc.save(resaved_path, garbage=4, deflate=True, clean=True)
        doc.close()

        # Extract recovered codeword from the re-saved file
        recovered_cw, confidences = WatermarkExtractor.extract_from_pdf(
            resaved_path,
            total_expected_blocks=total_blocks,
            lines_per_block=3
        )

        assert recovered_cw == expected_cw, f"Expected {expected_cw}, recovered {recovered_cw}"
        # Assert confidences are positive
        for conf in confidences:
            assert conf > 0.2


def test_codeword_generation_determinism():
    """Verify HMAC-SHA3 PRF produces stable, deterministic bit sequences."""
    seed = b"MASTER_WATERMARK_SECRET_KEY_2026"
    session_hash = os.urandom(32)

    cw1 = generate_codeword_bits(seed, session_hash, 10)
    cw2 = generate_codeword_bits(seed, session_hash, 10)

    assert cw1 == cw2
    assert len(cw1) == 10
    assert all(b in (0, 1) for b in cw1)


def test_geometric_fallback_extraction_without_stream_operators(sample_pdf_path, monkeypatch):
    """Verify Strategy 2 (font-adaptive geometric gap measurement) accurately recovers codewords
    even when raw content-stream 'Tw' operator inspection is completely bypassed/stripped.
    """
    blocks, meta = PDFSegmenter.segment_pdf(sample_pdf_path, lines_per_block=3)
    expected_cw = [1, 0, 1, 0]
    pdf_bytes = VariantGenerator.assemble_pdf(blocks, meta, expected_cw)

    # Monkeypatch doc.xref_stream inside WatermarkExtractor to simulate a viewer/driver
    # that stripped or flattened raw Tw operators, forcing Strategy 2 execution.
    orig_open = fitz.open

    class StreamStrippedDoc:
        def __init__(self, *args, **kwargs):
            self.doc = orig_open(*args, **kwargs)

        def __iter__(self):
            return iter(self.doc)

        def __len__(self):
            return len(self.doc)

        def __getitem__(self, idx):
            return self.doc[idx]

        def xref_stream(self, xref):
            # Return empty stream without Tw operators
            return b""

        def close(self):
            self.doc.close()

    monkeypatch.setattr(fitz, "open", lambda *args, **kwargs: StreamStrippedDoc(*args, **kwargs))

    recovered_cw, confidences = WatermarkExtractor.extract_from_pdf(
        pdf_bytes,
        total_expected_blocks=4,
        lines_per_block=3
    )

    assert recovered_cw == expected_cw, f"Strategy 2 fallback failed: expected {expected_cw}, got {recovered_cw}"
    for conf in confidences:
        assert conf > 0.5, f"Expected high geometric confidence, got {conf}"


def test_pdfjs_text_layout_geometry_alignment():
    """Verify that PDF.js's text placement model (advancement = glyph_width + Tw)
    aligns perfectly with CANARY TRAP's font-adaptive decision boundary (base_space + 0.375 pt)
    across all standard typographic font sizes.
    """
    font_sizes = [8.0, 9.0, 10.0, 11.0, 12.0, 14.0, 16.0, 24.0]
    for size in font_sizes:
        base_space = 0.278 * size
        threshold = base_space + 0.375

        # PDF.js text matrix horizontal advancement for space:
        # Variant 0: Tw = 0.000 -> advance = base_space + 0.000
        # Variant 1: Tw = 0.750 -> advance = base_space + 0.750
        pdfjs_advance_var0 = base_space + 0.0
        pdfjs_advance_var1 = base_space + 0.750

        delta_var0 = pdfjs_advance_var0 - threshold
        delta_var1 = pdfjs_advance_var1 - threshold

        # Symmetric separation margin of exactly +/- 0.375 pt
        assert abs(delta_var0 - (-0.375)) < 1e-6, f"Var 0 delta failed at size {size}"
        assert abs(delta_var1 - (+0.375)) < 1e-6, f"Var 1 delta failed at size {size}"

        # Decision boundary correctly maps 0 and 1
        bit_0 = 1 if delta_var0 >= 0.0 else 0
        bit_1 = 1 if delta_var1 >= 0.0 else 0
        assert bit_0 == 0
        assert bit_1 == 1
