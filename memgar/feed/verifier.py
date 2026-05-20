"""Ed25519 signature verification for threat-intelligence feed bundles."""

from __future__ import annotations

import base64
import logging

logger = logging.getLogger(__name__)

# The 32-byte Ed25519 public key, base64-encoded.
# Generated 2026-05-19 (rotated). To rotate again: run
# scripts/publish_feed.py with a new private key, then update this
# constant BEFORE publishing the new release — clients use this
# constant to verify every feed they download.
FEED_PUBLIC_KEY_B64: str = "ep1mBVtxffkDooNTUpaCwFOeYSO9stvHWjxGOuisRO4="


class FeedSignatureError(Exception):
    """Raised when feed bundle signature verification fails."""


class FeedVerifier:
    """Verify Ed25519 signatures on feed bundles."""

    def __init__(self, public_key_b64: Optional[str] = None) -> None:  # type: ignore[name-defined]
        self._public_key_b64 = public_key_b64 or FEED_PUBLIC_KEY_B64

    def verify(self, bundle_bytes: bytes, signature_b64: str) -> bool:
        """Return True if *signature_b64* is a valid Ed25519 signature over *bundle_bytes*."""
        # Pre-flight check: `cryptography` is built on `_cffi_backend`, and if
        # the C-extension isn't present the pyo3 layer panics on import and
        # writes a backtrace to stderr BEFORE Python raises. Detect the
        # missing backend first so we can raise a clean ImportError.
        import importlib.util as _ilu
        if _ilu.find_spec("_cffi_backend") is None:
            raise ImportError(
                "Feed signature verification requires 'cryptography'. "
                "Install with: pip install 'memgar[feed]'"
            )
        # Capture stderr around the import so a panicking system-installed
        # cryptography (e.g. distro package with mismatched libffi) doesn't
        # leak a Rust backtrace into the user's terminal — we surface a
        # clean ImportError instead.
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            except BaseException as exc:  # pyo3_runtime.PanicException is BaseException, not ImportError
                raise ImportError(
                    "Feed signature verification requires a functional 'cryptography' "
                    "install. Install with: pip install 'memgar[feed]'"
                ) from exc

        try:
            key_bytes = base64.b64decode(self._public_key_b64)
            sig_bytes = base64.b64decode(signature_b64)
            public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
            public_key.verify(sig_bytes, bundle_bytes)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            logger.debug("Signature verification error: %s", exc)
            return False

    def verify_manifest(self, manifest: "FeedManifest", bundle_bytes: bytes) -> bool:  # type: ignore[name-defined]
        """Convenience wrapper that reads signature from manifest."""
        return self.verify(bundle_bytes, manifest.signature.signature_b64)


# Avoid circular annotation issues on Python 3.9 — import here for type hints only.
from typing import Optional  # noqa: E402

from memgar.feed.models import FeedManifest  # noqa: E402, F401
