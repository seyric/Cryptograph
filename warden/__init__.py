"""warden - signed requests, policy and key release.

Validates decrypt requests, runs quorum consensus, and releases Shamir
shares once a request is committed. Serves the validator HTTP API.
"""
