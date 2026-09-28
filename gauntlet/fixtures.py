"""Deterministic sample documents for demos, benchmarks and tests.

Keeping the fixture text out of the runners means the prose of a demo document
can change without touching demo logic, and it gives the benchmark harness and
the attack scenarios a shared, reproducible corpus.

Everything here writes plain text-only PDFs with PyMuPDF at A4 size (595x842).
The demo runner uses one line per block so that a 21-line directive yields 24
variation blocks across three pages.
"""

from __future__ import annotations

import os
from typing import List, Sequence

import fitz

PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN_X = 60
TOP_Y = 80
LINE_STEP = 85
TITLE_SIZE = 13
BODY_SIZE = 10

#: The 3-page directive used by the end-to-end demo (24 blocks, one per line).
DEMO_PAGES: List[List[str]] = [
    [
        "NATIONAL CYBER DEFENCE DIRECTIVE 2026 - CONFIDENTIAL",
        "EXECUTIVE SUMMARY: Post-Quantum Migration Framework for Infrastructure.",
        "1.1: All designated government entities must implement post-quantum protocols.",
        "1.2: Traditional asymmetric cryptosystems like RSA and ECDSA are deprecated.",
        "1.3: Immediate implementation of NIST FIPS 203 ML-KEM-768 key encapsulation.",
        "1.4: Universal adoption of NIST FIPS 204 ML-DSA-65 digital signatures.",
        "1.5: Inter-agency distribution must be mediated by Byzantine quorums.",
        "1.6: Dynamic cryptographic watermarking shall prevent untraceable leaks.",
    ],
    [
        "SECTION 2: MANDATORY ATTRIBUTION AND PROVENANCE PROTOCOLS",
        "2.1: The 'No Log, No Key' invariant must be strictly enforced on hosts.",
        "2.2: Decryption variant keys remain split under threshold Shamir sharing.",
        "2.3: Plaintext representations shall never be generated unmarked.",
        "2.4: Each recipient session receives a unique micro-typographic variant.",
        "2.5: The variant assignment is evaluated via HMAC-SHA3-256 PRF from commit.",
        "2.6: The resultant word-spacing shifts are imperceptible to readers.",
        "2.7: Any attempt to bypass logging yields unusable ciphertexts.",
    ],
    [
        "SECTION 3: LEGAL ADMISSIBILITY UNDER SECTION 63 BSA 2023",
        "3.1: All evidence bundles generated satisfy Section 63 of BSA 2023.",
        "3.2: The immutable ledger guarantees complete chronological custody.",
        "3.3: Merkle audit proofs establish mathematical binding to block headers.",
        "3.4: In the event of unauthorized leaks, the extractor recovers codeword.",
        "3.5: Statistical correlation against access sessions isolates the leaker.",
        "3.6: Splicing attacks result in definitive attribution of all colluders.",
        "3.7: Official compliance certification signed by National Cyber Centre.",
    ],
]


def write_pages_pdf(
    output_path: str,
    pages: Sequence[Sequence[str]],
    margin_x: int = MARGIN_X,
    top_y: int = TOP_Y,
    line_step: int = LINE_STEP,
    title_size: int = TITLE_SIZE,
    body_size: int = BODY_SIZE,
) -> str:
    """Render ``pages`` (a sequence of line lists) to a PDF at ``output_path``.

    The first line of each page is rendered larger, as a heading.

    Returns:
        ``output_path``, for convenient chaining.
    """
    doc = fitz.open()
    for lines in pages:
        page = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
        y = top_y
        for line in lines:
            page.insert_text((margin_x, y), line, fontsize=title_size if y == top_y else body_size)
            y += line_step
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc.save(output_path)
    doc.close()
    return output_path


def write_demo_directive(output_path: str) -> str:
    """Write the built-in 3-page demo directive and return its path."""
    return write_pages_pdf(output_path, DEMO_PAGES)


__all__ = [
    "DEMO_PAGES",
    "PAGE_HEIGHT",
    "PAGE_WIDTH",
    "write_demo_directive",
    "write_pages_pdf",
]
