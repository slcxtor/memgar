"""Production-grade transformer trainer for Memgar Layer 2-ML.

What this is
------------

A from-scratch rewrite of :mod:`ml.training.transformer_trainer` that
addresses the gaps identified by ``simulation/`` and CLAUDE.md:

* **Multi-task head** — binary attack/benign + threat-category
  multi-class. The auxiliary category loss is a generalisation buff and
  produces a useful per-category prediction at inference time.
* **LoRA** (PEFT) — full-parameter fine-tuning is overkill for a binary
  + multi-class classification problem of this size. LoRA adapters
  train 1-3 % of parameters, fit in 4 GB GPU RAM, and converge faster.
* **Focal loss + class weights** — corpus is imbalanced (~58/42 in v2)
  and within-class the hard negatives must dominate gradients.
* **Label smoothing** — 0.05 to keep logits calibratable.
* **Temperature scaling** — Platt-style probability calibration fitted
  on the validation set after training.
* **Per-category metrics** — recall/precision/F1 reported for every
  subcategory in the validation/test sets.
* **Curriculum** — first 25 % of training only sees examples with
  confidence ≥ 0.9; the rest sees everything.
* **ONNX export with INT8 dynamic quantisation** — production model
  ships at ~50 % size and ~2-3× faster inference than fp32.

This module imports heavy ML deps lazily so simply importing it (e.g.
from a unit test) does not require torch/transformers/peft to be
installed.

Run via :mod:`scripts.train_transformer_v2` (CLI wrapper).
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("transformer_trainer_v2")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ARTIFACTS_DIR = REPO_ROOT / "ml" / "artifacts" / "transformer_model"
TOKENIZER_DIR = ARTIFACTS_DIR / "tokenizer"
ONNX_PATH = ARTIFACTS_DIR / "model.onnx"
ONNX_INT8_PATH = ARTIFACTS_DIR / "model.int8.onnx"
CALIBRATION_PATH = ARTIFACTS_DIR / "temperature.json"
CATEGORY_INDEX_PATH = ARTIFACTS_DIR / "categories.json"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class TrainConfig:
    base_model: str = "distilroberta-base"        # honest CPU/GPU sweet spot
    num_epochs: int = 4
    batch_size: int = 16
    eval_batch_size: int = 32
    learning_rate: float = 2e-5
    weight_decay: float = 0.01
    warmup_ratio: float = 0.06
    max_length: int = 256
    label_smoothing: float = 0.05
    focal_gamma: float = 2.0
    aux_loss_weight: float = 0.3                  # category head weight
    use_lora: bool = True
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    seed: int = 42
    curriculum_warmup_frac: float = 0.25
    early_stopping_patience: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class TrainArtifacts:
    pytorch_dir: Path
    tokenizer_dir: Path
    onnx_path: Optional[Path]
    onnx_int8_path: Optional[Path]
    metrics: Dict[str, Any]
    category_index: Dict[str, int]
    temperature: float
    config: Dict[str, Any]


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build_category_index(samples: List[Dict[str, Any]]) -> Dict[str, int]:
    """A stable str→int mapping for the multi-task category head."""
    cats = sorted({s.get("category", "benign") for s in samples})
    return {c: i for i, c in enumerate(cats)}


# ---------------------------------------------------------------------------
# Loss
# ---------------------------------------------------------------------------

def _focal_loss(logits, target, *, gamma: float = 2.0,
                class_weights=None, label_smoothing: float = 0.0):
    """Multi-class focal loss with optional class weights + label smoothing."""
    import torch
    import torch.nn.functional as F

    log_p = F.log_softmax(logits, dim=-1)
    n_classes = logits.size(-1)
    if label_smoothing > 0:
        target_oh = torch.zeros_like(log_p).scatter_(-1, target.unsqueeze(-1), 1.0)
        target_oh = target_oh * (1 - label_smoothing) + label_smoothing / n_classes
        ce = -(target_oh * log_p).sum(-1)
    else:
        ce = F.nll_loss(log_p, target, reduction="none")
    p = log_p.exp().gather(-1, target.unsqueeze(-1)).squeeze(-1).clamp_min(1e-8)
    focal = ((1.0 - p) ** gamma) * ce
    if class_weights is not None:
        focal = focal * class_weights.to(focal.device)[target]
    return focal.mean()


# ---------------------------------------------------------------------------
# Multi-task model
# ---------------------------------------------------------------------------

def _build_model(base_model: str, *, n_categories: int, cfg: TrainConfig):
    """Build a multi-task model: shared encoder + binary head + category head.

    Returns (model, tokenizer). PEFT/LoRA is applied if cfg.use_lora.
    """
    import torch
    import torch.nn as nn
    from transformers import AutoModel, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    class MultiTaskClassifier(nn.Module):
        def __init__(self, backbone, hidden_size, n_categories):
            super().__init__()
            self.backbone = backbone
            self.dropout = nn.Dropout(0.1)
            self.binary_head = nn.Linear(hidden_size, 2)
            self.category_head = nn.Linear(hidden_size, n_categories)

        def forward(self, input_ids, attention_mask, **_):
            out = self.backbone(input_ids=input_ids,
                                attention_mask=attention_mask,
                                return_dict=True)
            # mean-pool over attention_mask
            last = out.last_hidden_state
            mask = attention_mask.unsqueeze(-1).float()
            pooled = (last * mask).sum(1) / mask.sum(1).clamp_min(1.0)
            pooled = self.dropout(pooled)
            return {
                "binary_logits": self.binary_head(pooled),
                "category_logits": self.category_head(pooled),
            }

    backbone = AutoModel.from_pretrained(base_model)
    hidden = backbone.config.hidden_size
    model = MultiTaskClassifier(backbone, hidden, n_categories)

    if cfg.use_lora:
        try:
            from peft import LoraConfig, get_peft_model, TaskType
            lora_cfg = LoraConfig(
                r=cfg.lora_rank,
                lora_alpha=cfg.lora_alpha,
                lora_dropout=cfg.lora_dropout,
                bias="none",
                task_type=TaskType.FEATURE_EXTRACTION,
                # cover most encoder architectures we might pick
                target_modules=["query", "value", "key",
                                "q_proj", "v_proj", "k_proj"],
            )
            model.backbone = get_peft_model(model.backbone, lora_cfg)
            logger.info("LoRA enabled: rank=%d alpha=%d", cfg.lora_rank, cfg.lora_alpha)
        except ImportError:
            logger.warning("peft not installed — falling back to full fine-tune")

    return model, tokenizer


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

def fit_temperature(logits, labels, *, n_iter: int = 200) -> float:
    """Fit a single-parameter Platt-style temperature on validation logits.

    Parameterised as T = exp(log_T) so the optimiser cannot drift into
    negative values, which would invert the softmax and produce
    nonsensical calibrated probabilities downstream.
    """
    import torch
    import torch.nn.functional as F

    logits_t = torch.as_tensor(logits, dtype=torch.float32)
    labels_t = torch.as_tensor(labels, dtype=torch.long)
    log_T = torch.nn.Parameter(torch.zeros(1))  # T = exp(0) = 1.0
    optim = torch.optim.LBFGS([log_T], lr=0.05, max_iter=n_iter)

    def closure():
        optim.zero_grad()
        T = log_T.exp()
        loss = F.cross_entropy(logits_t / T, labels_t)
        loss.backward()
        return loss

    optim.step(closure)
    T_final = float(log_T.detach().exp().item())
    # Bound to a sensible range — a saturated 99 %+ accuracy model can
    # push T arbitrarily small/large; clamp to keep probs well-behaved.
    return max(0.5, min(T_final, 5.0))


def expected_calibration_error(probs, labels, *, n_bins: int = 15) -> float:
    """Standard ECE over the attack-class probability."""
    import numpy as np
    p = np.asarray(probs)[:, 1]      # attack class
    y = np.asarray(labels)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (p >= lo) & (p < hi) if hi < 1.0 else (p >= lo) & (p <= hi)
        if not mask.any():
            continue
        acc = (y[mask] == 1).mean()
        conf = p[mask].mean()
        ece += (mask.mean()) * abs(acc - conf)
    return float(ece)


# ---------------------------------------------------------------------------
# Per-category report
# ---------------------------------------------------------------------------

def per_category_metrics(preds: List[int], labels: List[int],
                         subcategories: List[str]) -> Dict[str, Dict[str, float]]:
    """precision/recall/F1/support for every distinct subcategory."""
    buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for p, y, sub in zip(preds, labels, subcategories):
        b = buckets[sub or "(unlabelled)"]
        if y == 1 and p == 1:
            b["tp"] += 1
        elif y == 1 and p == 0:
            b["fn"] += 1
        elif y == 0 and p == 1:
            b["fp"] += 1
        else:
            b["tn"] += 1
    out = {}
    for sub, c in buckets.items():
        tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = (2 * prec * rec / max(1e-8, prec + rec)) if (prec + rec) else 0.0
        out[sub] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": tp + fn,
            "support_benign": fp + tn,
        }
    return out


# ---------------------------------------------------------------------------
# ONNX export + quantisation
# ---------------------------------------------------------------------------

def export_onnx(model, tokenizer, *, max_length: int = 256,
                output_path: Path = ONNX_PATH) -> Path:
    import torch
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model.eval()
    dummy = tokenizer("placeholder for tracing",
                       padding="max_length", truncation=True,
                       max_length=max_length, return_tensors="pt")

    class _Wrap(torch.nn.Module):
        """Wrap multi-task forward into a single tensor output suitable
        for ONNX export: concatenate binary_logits + category_logits."""
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, input_ids, attention_mask):
            out = self.inner(input_ids=input_ids, attention_mask=attention_mask)
            return torch.cat([out["binary_logits"], out["category_logits"]], dim=-1)

    wrapped = _Wrap(model)
    torch.onnx.export(
        wrapped,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(output_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=14,
        do_constant_folding=True,
    )
    logger.info("ONNX export → %s (%.1f MB)",
                output_path, output_path.stat().st_size / (1024 * 1024))
    return output_path


def quantize_int8(fp32_path: Path = ONNX_PATH,
                  int8_path: Path = ONNX_INT8_PATH) -> Optional[Path]:
    """Dynamic INT8 quantisation. Halves model size and 2-3× CPU latency.

    Falls back gracefully when onnxruntime is unavailable.
    """
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
    except Exception as e:
        logger.warning("onnxruntime not available — skipping INT8 quantisation (%s)", e)
        return None
    quantize_dynamic(model_input=str(fp32_path),
                     model_output=str(int8_path),
                     weight_type=QuantType.QInt8)
    logger.info("INT8 export   → %s (%.1f MB)",
                int8_path, int8_path.stat().st_size / (1024 * 1024))
    return int8_path


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def train(train_path: Path, val_path: Path, test_path: Path,
          *, cfg: Optional[TrainConfig] = None,
          output_dir: Path = ARTIFACTS_DIR,
          export_onnx_artifact: bool = True,
          quantize: bool = True) -> TrainArtifacts:
    """Main entry point.

    Returns a TrainArtifacts describing every file produced, so that
    :mod:`scripts.release_transformer` can bundle them.
    """
    cfg = cfg or TrainConfig()
    output_dir.mkdir(parents=True, exist_ok=True)
    import numpy as np
    import torch
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    from sklearn.metrics import (precision_score, recall_score, f1_score,
                                   accuracy_score)

    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    train_samples = _read_jsonl(train_path)
    val_samples = _read_jsonl(val_path)
    test_samples = _read_jsonl(test_path)

    category_index = build_category_index(train_samples + val_samples + test_samples)
    n_categories = len(category_index)

    model, tokenizer = _build_model(cfg.base_model, n_categories=n_categories, cfg=cfg)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    # Class weights from the empirical training distribution (inverse-freq).
    label_counts = Counter(s["label"] for s in train_samples)
    total = max(1, sum(label_counts.values()))
    cw = torch.tensor([total / max(1, label_counts.get(0, 1)),
                        total / max(1, label_counts.get(1, 1))],
                       dtype=torch.float32)
    cw = cw / cw.sum() * 2.0
    logger.info("class_weights: benign=%.3f attack=%.3f", cw[0], cw[1])

    class JsonlDataset(Dataset):
        def __init__(self, samples, *, tokenizer, max_length, category_index):
            self.samples = samples
            self.tokenizer = tokenizer
            self.max_length = max_length
            self.category_index = category_index

        def __len__(self):
            return len(self.samples)

        def __getitem__(self, idx):
            s = self.samples[idx]
            enc = self.tokenizer(s["text"], padding="max_length",
                                  truncation=True, max_length=self.max_length,
                                  return_tensors="pt")
            return {
                "input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "label": torch.tensor(int(s["label"]), dtype=torch.long),
                "category": torch.tensor(
                    self.category_index.get(s.get("category", "benign"), 0),
                    dtype=torch.long),
                "confidence": torch.tensor(float(s.get("confidence", 1.0)),
                                            dtype=torch.float32),
            }

    train_ds = JsonlDataset(train_samples, tokenizer=tokenizer,
                              max_length=cfg.max_length,
                              category_index=category_index)
    val_ds = JsonlDataset(val_samples, tokenizer=tokenizer,
                            max_length=cfg.max_length,
                            category_index=category_index)
    test_ds = JsonlDataset(test_samples, tokenizer=tokenizer,
                             max_length=cfg.max_length,
                             category_index=category_index)

    train_loader = DataLoader(train_ds, batch_size=cfg.batch_size, shuffle=True,
                                num_workers=2, drop_last=False)
    val_loader = DataLoader(val_ds, batch_size=cfg.eval_batch_size,
                              num_workers=2)
    test_loader = DataLoader(test_ds, batch_size=cfg.eval_batch_size,
                               num_workers=2)

    optim = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],
                               lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    n_steps_total = max(1, cfg.num_epochs * len(train_loader))
    n_warmup = int(n_steps_total * cfg.warmup_ratio)

    def lr_lambda(step):
        if step < n_warmup:
            return step / max(1, n_warmup)
        progress = (step - n_warmup) / max(1, n_steps_total - n_warmup)
        return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optim, lr_lambda)

    def _eval(loader) -> Tuple[float, Dict[str, Any], List[List[float]], List[int], List[str]]:
        model.eval()
        all_logits, all_labels, all_subs = [], [], []
        with torch.no_grad():
            for batch in loader:
                out = model(input_ids=batch["input_ids"].to(device),
                              attention_mask=batch["attention_mask"].to(device))
                logits = out["binary_logits"].cpu().numpy()
                all_logits.extend(logits.tolist())
                all_labels.extend(batch["label"].tolist())
            for s in loader.dataset.samples:
                all_subs.append(s.get("subcategory") or s.get("category", "?"))
        import numpy as _np
        logits_np = _np.asarray(all_logits)
        preds = logits_np.argmax(-1).tolist()
        metrics = {
            "accuracy": round(accuracy_score(all_labels, preds), 4),
            "precision": round(precision_score(all_labels, preds, zero_division=0), 4),
            "recall": round(recall_score(all_labels, preds, zero_division=0), 4),
            "f1": round(f1_score(all_labels, preds, zero_division=0), 4),
        }
        return metrics["f1"], metrics, all_logits, all_labels, all_subs

    # ---------------- Training loop ----------------
    best_f1 = -1.0
    epochs_without_improve = 0
    history: List[Dict[str, Any]] = []
    curriculum_cut_step = int(n_steps_total * cfg.curriculum_warmup_frac)

    global_step = 0
    t0 = time.perf_counter()
    for epoch in range(cfg.num_epochs):
        model.train()
        for batch in train_loader:
            # Curriculum: first 25 % of steps mask out low-confidence rows.
            confidence_mask = batch["confidence"] >= 0.9 if global_step < curriculum_cut_step \
                else torch.ones_like(batch["confidence"], dtype=torch.bool)
            if not confidence_mask.any():
                global_step += 1
                continue

            optim.zero_grad()
            out = model(input_ids=batch["input_ids"].to(device),
                          attention_mask=batch["attention_mask"].to(device))
            bin_loss = _focal_loss(
                out["binary_logits"][confidence_mask],
                batch["label"].to(device)[confidence_mask],
                gamma=cfg.focal_gamma,
                class_weights=cw,
                label_smoothing=cfg.label_smoothing,
            )
            cat_loss = F.cross_entropy(
                out["category_logits"][confidence_mask],
                batch["category"].to(device)[confidence_mask],
                label_smoothing=cfg.label_smoothing,
            )
            loss = bin_loss + cfg.aux_loss_weight * cat_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim.step()
            scheduler.step()
            global_step += 1

        val_f1, val_metrics, _, _, _ = _eval(val_loader)
        history.append({"epoch": epoch, "val": val_metrics,
                         "lr": scheduler.get_last_lr()[0]})
        logger.info("epoch %d val_metrics=%s", epoch, val_metrics)

        if val_f1 > best_f1 + 1e-4:
            best_f1 = val_f1
            epochs_without_improve = 0
            torch.save(model.state_dict(), output_dir / "pytorch_best.pt")
        else:
            epochs_without_improve += 1
            if epochs_without_improve >= cfg.early_stopping_patience:
                logger.info("early-stop at epoch %d", epoch)
                break

    train_secs = time.perf_counter() - t0
    logger.info("training finished in %.0fs", train_secs)

    # Load best & calibrate
    model.load_state_dict(torch.load(output_dir / "pytorch_best.pt"))
    _, val_metrics, val_logits, val_labels, val_subs = _eval(val_loader)
    temperature = fit_temperature(val_logits, val_labels)
    logger.info("fitted temperature = %.3f", temperature)

    # Final test eval
    _, test_metrics, test_logits, test_labels, test_subs = _eval(test_loader)

    import numpy as _np
    test_logits_np = _np.asarray(test_logits) / max(1e-3, temperature)
    test_probs = (_np.exp(test_logits_np) /
                  _np.exp(test_logits_np).sum(-1, keepdims=True))
    ece = expected_calibration_error(test_probs.tolist(), test_labels)
    test_preds = test_logits_np.argmax(-1).tolist()

    metrics_payload = {
        "training_seconds": round(train_secs, 1),
        "best_val_f1": best_f1,
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
        "test_ece": round(ece, 4),
        "temperature": temperature,
        "history": history,
        "config": cfg.to_dict(),
        "n_categories": n_categories,
        "n_train": len(train_samples),
        "n_val": len(val_samples),
        "n_test": len(test_samples),
        "per_subcategory": per_category_metrics(test_preds, test_labels, test_subs),
    }
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics_payload, indent=2), encoding="utf-8")
    (output_dir / "categories.json").write_text(
        json.dumps(category_index, indent=2), encoding="utf-8")
    CALIBRATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    CALIBRATION_PATH.write_text(json.dumps({"temperature": temperature}), encoding="utf-8")

    # tokenizer
    TOKENIZER_DIR.mkdir(parents=True, exist_ok=True)
    tokenizer.save_pretrained(str(TOKENIZER_DIR))

    onnx_p: Optional[Path] = None
    int8_p: Optional[Path] = None
    if export_onnx_artifact:
        onnx_p = export_onnx(model, tokenizer, max_length=cfg.max_length,
                               output_path=ONNX_PATH)
        if quantize:
            int8_p = quantize_int8(onnx_p, ONNX_INT8_PATH)

    return TrainArtifacts(
        pytorch_dir=output_dir,
        tokenizer_dir=TOKENIZER_DIR,
        onnx_path=onnx_p,
        onnx_int8_path=int8_p,
        metrics=metrics_payload,
        category_index=category_index,
        temperature=temperature,
        config=cfg.to_dict(),
    )
