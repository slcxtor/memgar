"""Bundle trained transformer artifacts for a GitHub release.

Collects the artifacts produced by ``scripts/train_transformer_v2.py``,
creates a compressed tar archive, and writes a ``release_manifest.json``
with SHA-256 checksums for every included file.

Usage
-----
    python scripts/release_transformer.py --version 2.0.0

    # Dry run — print what would be bundled without writing anything
    python scripts/release_transformer.py --version 2.0.0 --dry-run

The release bundle is written to ``dist/`` by default:

    dist/
        memgar-transformer-v2.0.0.tar.gz     ← the artifact bundle
        release_manifest.json                ← checksums + metadata

Uploading
---------
Upload the tarball as a release asset on GitHub, then point
``memgar/ml_release_loader.py`` at the new release tag.  The manifest
is checked into the repo (committed alongside the code that references
the new version) so offline verification doesn't need a network call.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import tarfile
import time
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ARTIFACTS_DIR = ROOT / "ml" / "artifacts" / "transformer_model"
DIST_DIR = ROOT / "dist"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("release_transformer")

# Files that must be present for the bundle to be valid
REQUIRED_FILES = [
    "tokenizer/tokenizer_config.json",
    "tokenizer/vocab.json",
    "metrics.json",
    "categories.json",
    "temperature.json",
]

# At least one model file must exist
MODEL_FILES = [
    "model.int8.onnx",
    "model.onnx",
]

# Optional files included when present
OPTIONAL_FILES = [
    "tokenizer/tokenizer.json",
    "tokenizer/merges.txt",
    "tokenizer/special_tokens_map.json",
    "pytorch_best.pt",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(artifacts: Path) -> tuple[List[Path], List[str]]:
    """Return (absolute paths to include, list of warning messages)."""
    files: List[Path] = []
    warnings: List[str] = []

    for rel in REQUIRED_FILES:
        p = artifacts / rel
        if p.exists():
            files.append(p)
        else:
            warnings.append(f"REQUIRED missing: {rel}")

    has_model = False
    for rel in MODEL_FILES:
        p = artifacts / rel
        if p.exists():
            files.append(p)
            has_model = True

    if not has_model:
        warnings.append(
            "No ONNX model found (model.int8.onnx or model.onnx). "
            "Run `python scripts/train_transformer_v2.py --data <corpus>` first."
        )

    for rel in OPTIONAL_FILES:
        p = artifacts / rel
        if p.exists():
            files.append(p)

    return files, warnings


def build_manifest(
    version: str,
    files: List[Path],
    artifacts: Path,
    bundle_path: Optional[Path],
) -> dict:
    entries: Dict[str, Dict] = {}
    for p in files:
        rel = str(p.relative_to(artifacts))
        entries[rel] = {
            "sha256": sha256(p),
            "size_bytes": p.stat().st_size,
        }

    manifest = {
        "version": version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": entries,
    }
    if bundle_path and bundle_path.exists():
        manifest["bundle"] = {
            "filename": bundle_path.name,
            "sha256": sha256(bundle_path),
            "size_bytes": bundle_path.stat().st_size,
        }
    return manifest


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bundle Memgar transformer v2 artifacts for a GitHub release",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", required=True,
                   help="Release version string, e.g. 2.0.0")
    p.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR),
                   help="Source artifact directory")
    p.add_argument("--dist-dir", default=str(DIST_DIR),
                   help="Output directory for the bundle")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what would be bundled and exit")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    artifacts = Path(args.artifacts_dir)
    dist = Path(args.dist_dir)
    version = args.version

    files, warnings = collect_files(artifacts)

    for w in warnings:
        logger.warning(w)

    fatal = [w for w in warnings if w.startswith("REQUIRED") or w.startswith("No ONNX")]
    if fatal and not args.dry_run:
        logger.error("Cannot build release bundle — required files missing (see warnings above).")
        return 1

    total_mb = sum(p.stat().st_size for p in files) / 1_048_576
    logger.info("Files to bundle: %d  (total %.1f MB)", len(files), total_mb)
    for p in files:
        logger.info("  %s  (%s bytes)", p.relative_to(artifacts), p.stat().st_size)

    if args.dry_run:
        logger.info("--dry-run: skipping archive creation.")
        return 0

    dist.mkdir(parents=True, exist_ok=True)
    bundle_name = f"memgar-transformer-v{version}.tar.gz"
    bundle_path = dist / bundle_name

    with tarfile.open(bundle_path, "w:gz") as tf:
        for p in files:
            arcname = str(p.relative_to(artifacts))
            tf.add(p, arcname=arcname)

    logger.info("Bundle written: %s  (%.1f MB)", bundle_path, bundle_path.stat().st_size / 1_048_576)

    manifest = build_manifest(version, files, artifacts, bundle_path)
    manifest_path = dist / "release_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Manifest:       %s", manifest_path)

    logger.info("")
    logger.info("Next steps:")
    logger.info("  1. Create GitHub release tag v%s", version)
    logger.info("  2. Upload %s as a release asset", bundle_name)
    logger.info("  3. Commit dist/release_manifest.json")
    logger.info("  4. Update MEMGAR_TRANSFORMER_RELEASE_TAG in memgar/ml_release_loader.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
