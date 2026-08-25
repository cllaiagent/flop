"""Public API for Technocore ProofKit."""

from .core import (
    ProofError,
    canonical_message,
    did_fingerprint,
    finalize_manifest,
    public_key_from_did,
    verify_manifest,
)

__all__ = [
    "ProofError",
    "canonical_message",
    "did_fingerprint",
    "finalize_manifest",
    "public_key_from_did",
    "verify_manifest",
]

__version__ = "0.3.0"
