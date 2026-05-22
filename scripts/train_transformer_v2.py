"""CLI wrapper for the Memgar v2 Transformer training pipeline.

Usage
-----
    python scripts/train_transformer_v2.py --data ml/data/calibration_corpus.json

Full options::

    python scripts/train_transformer_v2.py \\
        --data ml/data/calibration_corpus.json \\
        --aux  ml/data/mined_hard_subset.json \\
        --aux  ml/data/augmented_memory_context.json \\
        --base-model distilroberta-base \\
        --epochs 8 \\
        --batch-size 32 \\
        --max-length 256 \\
        --lr 3e-4 \\
        --lora-r 16 \\
        --no-int8     \\   # skip INT8 quantisation (faster iteration)
        --dry-run         # print config and exit

Outputs (written to ml/artifacts/transformer_model/):
    model.onnx          — fp32 ONNX artifact
    model.int8.onnx     — INT8 quantised artifact (default, ~50 % smaller)
    tokenizer/          — HuggingFace tokenizer files
    metrics.json        — train/val/test metrics + per-category breakdown
    categories.json     — {label: index} mapping
    temperature.json    — fitted temperature scalar
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_v2")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train the Memgar v2 multi-task transformer model",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--data", required=True,
                   help="Primary training corpus JSON (gold calibration_corpus.json)")
    p.add_argument("--aux", action="append", default=[],
                   help="Additional corpus files (may be repeated)")
    p.add_argument("--base-model", default="distilroberta-base",
                   help="HuggingFace model ID or local path")
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--warmup-frac", type=float, default=0.06)
    p.add_argument("--lora-r", type=int, default=16,
                   help="LoRA rank (0 = disable LoRA, full fine-tune)")
    p.add_argument("--lora-alpha", type=float, default=32.0)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--focal-gamma", type=float, default=2.0)
    p.add_argument("--label-smoothing", type=float, default=0.05)
    p.add_argument("--aux-loss-weight", type=float, default=0.3,
                   help="Category loss weight relative to binary loss")
    p.add_argument("--patience", type=int, default=3,
                   help="Early stopping patience (epochs without F1 improvement)")
    p.add_argument("--no-onnx", action="store_true",
                   help="Skip ONNX export (saves time during development)")
    p.add_argument("--no-int8", action="store_true",
                   help="Skip INT8 quantisation")
    p.add_argument("--dry-run", action="store_true",
                   help="Print resolved config and exit without training")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # Collect corpus files
    corpus_paths = [args.data] + args.aux
    for p in corpus_paths:
        if not Path(p).exists():
            logger.error("Corpus file not found: %s", p)
            return 1

    # Build TrainConfig from CLI args
    try:
        from ml.training.transformer_trainer_v2 import TrainConfig, train
    except ImportError as exc:
        logger.error(
            "ML training dependencies not installed: %s\n"
            "Install with:  pip install -e '.[ml-train]' peft",
            exc,
        )
        return 1

    cfg = TrainConfig(
        base_model=args.base_model,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        max_length=args.max_length,
        learning_rate=args.lr,
        warmup_fraction=args.warmup_frac,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        focal_gamma=args.focal_gamma,
        label_smoothing=args.label_smoothing,
        aux_loss_weight=args.aux_loss_weight,
        early_stopping_patience=args.patience,
        seed=args.seed,
    )

    logger.info("=== Memgar Transformer v2 Training ===")
    logger.info("Corpus files : %s", corpus_paths)
    logger.info("Config       : %s", json.dumps(cfg.to_dict(), indent=2))

    if args.dry_run:
        logger.info("--dry-run: exiting without training.")
        return 0

    artifacts = train(
        corpus_paths=corpus_paths,
        cfg=cfg,
        export_onnx_artifact=not args.no_onnx,
        quantize=not args.no_int8,
    )

    logger.info("=== Training complete ===")
    logger.info("PyTorch dir  : %s", artifacts.pytorch_dir)
    logger.info("Tokenizer    : %s", artifacts.tokenizer_dir)
    if artifacts.onnx_path:
        size_mb = artifacts.onnx_path.stat().st_size / 1_048_576
        logger.info("ONNX (fp32)  : %s  (%.1f MB)", artifacts.onnx_path, size_mb)
    if artifacts.onnx_int8_path:
        size_mb = artifacts.onnx_int8_path.stat().st_size / 1_048_576
        logger.info("ONNX (INT8)  : %s  (%.1f MB)", artifacts.onnx_int8_path, size_mb)
    m = artifacts.metrics
    logger.info(
        "Test metrics : F1=%.4f  Precision=%.4f  Recall=%.4f  ECE=%.4f",
        m["test_metrics"]["f1"],
        m["test_metrics"]["precision"],
        m["test_metrics"]["recall"],
        m["test_ece"],
    )
    logger.info("Temperature  : %.4f", artifacts.temperature)

    # Quick quality gate
    f1 = m["test_metrics"]["f1"]
    recall = m["test_metrics"]["recall"]
    precision = m["test_metrics"]["precision"]
    gate_ok = f1 >= 0.94 and recall >= 0.94 and precision >= 0.94
    if gate_ok:
        logger.info("QUALITY GATE PASSED (F1/Recall/Precision >= 0.94)")
    else:
        logger.warning(
            "QUALITY GATE FAILED — F1=%.4f Recall=%.4f Precision=%.4f "
            "(threshold: 0.94 each)",
            f1, recall, precision,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
