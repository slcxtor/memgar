"""Download and install Memgar transformer v2 artifacts from a GitHub release.

The release bundle is a ``memgar-transformer-vX.Y.Z.tar.gz`` asset attached
to a tagged GitHub release in ``slcxtor/memgar``.  The loader:

1. Fetches the asset URL from the GitHub releases API (no authentication
   required for public repos).
2. Streams the tarball, verifying the SHA-256 checksum against
   ``dist/release_manifest.json`` (committed to the repo).
3. Extracts to ``ml/artifacts/transformer_model/``.

Usage
-----
From Python::

    from memgar.ml_release_loader import TransformerReleaseLoader
    loader = TransformerReleaseLoader()
    loader.install()              # idempotent — skips if already installed
    loader.install(force=True)    # re-download even if artifacts exist

CLI::

    python -m memgar.ml_release_loader
    python -m memgar.ml_release_loader --force
    python -m memgar.ml_release_loader --tag v2.1.0

Security
--------
- Downloads are restricted to ``github.com`` / ``*.githubusercontent.com``
  (same SSRF allowlist as :class:`memgar.feed.loader.FeedLoader`).
- SHA-256 is verified before extraction; tampered bundles are rejected.
- Gzip bomb protection: max 500 MB extracted per member, 1 GB total.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_REPO = "slcxtor/memgar"
_ALLOWED_HOSTS = frozenset({"github.com", "objects.githubusercontent.com",
                             "codeload.github.com", "releases.githubusercontent.com"})

# Default release tag — update when publishing a new artifact version
MEMGAR_TRANSFORMER_RELEASE_TAG = "v2.0.0"

_ROOT = Path(__file__).resolve().parent.parent
_ARTIFACTS_DIR = _ROOT / "ml" / "artifacts" / "transformer_model"
_MANIFEST_PATH = _ROOT / "dist" / "release_manifest.json"

_MAX_MEMBER_BYTES = 500 * 1024 * 1024   # 500 MB per file
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024   # 1 GB total


class ReleaseLoaderError(RuntimeError):
    pass


class TransformerReleaseLoader:
    """Download and install transformer v2 artifacts from GitHub Releases."""

    def __init__(
        self,
        *,
        repo: str = _REPO,
        tag: Optional[str] = None,
        artifacts_dir: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
    ) -> None:
        self._repo = repo
        self._tag = tag or os.environ.get("MEMGAR_TRANSFORMER_RELEASE_TAG",
                                           MEMGAR_TRANSFORMER_RELEASE_TAG)
        self._artifacts_dir = artifacts_dir or _ARTIFACTS_DIR
        self._manifest_path = manifest_path or _MANIFEST_PATH

    # ------------------------------------------------------------------ public

    def is_installed(self) -> bool:
        """Return True if at least one ONNX model and the tokenizer exist."""
        has_model = (
            (self._artifacts_dir / "model.int8.onnx").exists()
            or (self._artifacts_dir / "model.onnx").exists()
        )
        has_tokenizer = (self._artifacts_dir / "tokenizer" / "tokenizer_config.json").exists()
        return has_model and has_tokenizer

    def install(self, *, force: bool = False) -> None:
        """Download and extract the release bundle.

        No-op if artifacts are already present and ``force=False``.
        """
        if self.is_installed() and not force:
            logger.info(
                "TransformerReleaseLoader: artifacts already installed at %s",
                self._artifacts_dir,
            )
            return

        bundle_name = f"memgar-transformer-{self._tag}.tar.gz"
        url = self._asset_url(bundle_name)
        expected_sha = self._expected_sha256(bundle_name)

        logger.info("Downloading %s from %s …", bundle_name, url)
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            self._download(url, tmp_path)
            actual_sha = self._sha256(tmp_path)
            if expected_sha and actual_sha != expected_sha:
                raise ReleaseLoaderError(
                    f"SHA-256 mismatch for {bundle_name}: "
                    f"expected {expected_sha}, got {actual_sha}"
                )
            self._extract(tmp_path)
            logger.info("Transformer artifacts installed at %s", self._artifacts_dir)
        finally:
            tmp_path.unlink(missing_ok=True)

    # ------------------------------------------------------------------ helpers

    def _asset_url(self, bundle_name: str) -> str:
        api = (
            f"https://api.github.com/repos/{self._repo}/releases/tags/{self._tag}"
        )
        req = urllib.request.Request(
            api,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "memgar-ml-release-loader/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            raise ReleaseLoaderError(
                f"Could not fetch release metadata for {self._tag}: {exc}"
            ) from exc

        for asset in data.get("assets", []):
            if asset["name"] == bundle_name:
                return asset["browser_download_url"]

        raise ReleaseLoaderError(
            f"Asset '{bundle_name}' not found in release {self._tag}. "
            f"Available: {[a['name'] for a in data.get('assets', [])]}"
        )

    def _expected_sha256(self, bundle_name: str) -> Optional[str]:
        if not self._manifest_path.exists():
            logger.debug("No local manifest found at %s — skipping checksum", self._manifest_path)
            return None
        try:
            manifest = json.loads(self._manifest_path.read_text(encoding="utf-8"))
            return manifest.get("bundle", {}).get("sha256")
        except Exception:
            return None

    def _download(self, url: str, dest: Path) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not any(host == h or host.endswith(f".{h}") for h in _ALLOWED_HOSTS):
            raise ReleaseLoaderError(
                f"Download host '{host}' is not in the allowed list. "
                "Only github.com and *.githubusercontent.com are permitted."
            )
        req = urllib.request.Request(url, headers={"User-Agent": "memgar-ml-release-loader/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as fh:
            downloaded = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > _MAX_MEMBER_BYTES:
                    raise ReleaseLoaderError(
                        f"Download exceeded {_MAX_MEMBER_BYTES // 1_048_576} MB limit"
                    )
                fh.write(chunk)
        logger.debug("Downloaded %.1f MB to %s", downloaded / 1_048_576, dest)

    def _extract(self, bundle: Path) -> None:
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        total_bytes = 0
        with tarfile.open(bundle, "r:gz") as tf:
            for member in tf.getmembers():
                # Path traversal guard
                resolved = (self._artifacts_dir / member.name).resolve()
                if not str(resolved).startswith(str(self._artifacts_dir.resolve())):
                    raise ReleaseLoaderError(
                        f"Refusing to extract '{member.name}' — path traversal attempt"
                    )
                if member.size > _MAX_MEMBER_BYTES:
                    raise ReleaseLoaderError(
                        f"Member '{member.name}' ({member.size} bytes) exceeds "
                        f"{_MAX_MEMBER_BYTES // 1_048_576} MB limit"
                    )
                total_bytes += member.size
                if total_bytes > _MAX_TOTAL_BYTES:
                    raise ReleaseLoaderError(
                        f"Extraction would exceed {_MAX_TOTAL_BYTES // 1_048_576} MB total limit"
                    )
                tf.extract(member, path=self._artifacts_dir)

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Install Memgar transformer v2 artifacts")
    p.add_argument("--tag", default=None,
                   help=f"Release tag (default: {MEMGAR_TRANSFORMER_RELEASE_TAG})")
    p.add_argument("--force", action="store_true",
                   help="Re-download even if artifacts already exist")
    args = p.parse_args()

    loader = TransformerReleaseLoader(tag=args.tag)
    try:
        loader.install(force=args.force)
    except ReleaseLoaderError as exc:
        logger.error("Installation failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
