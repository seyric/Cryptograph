"""bridge - the recipient-facing service.

Holds recipient private keys locally, signs decrypt requests, and assembles
the watermarked document for viewing. `bridge.pdf_adapter` is the seam over
the PDF library.
"""
