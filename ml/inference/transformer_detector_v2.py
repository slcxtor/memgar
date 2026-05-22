"""ONNX inference for the Memgar v2 multi-task transformer.

The v2 trainer exports a single ``logits`` ONNX tensor that concatenates the
binary head (2 columns) with the category head (N columns):

    logits[:, :2]  → binary attack/benign  (softmax → attack_prob)
    logits[:, 2:]  → threat category       (argmax  → category_label)

Temperature scaling is applied to the binary logits before softmax.

INT8 model (``model.int8.onnx``) is loaded first when available — it is
~50 % smaller and 2-3× faster than fp32 on CPU.  Falls back to fp32 ONNX,
then PyTorch.

Public API mirrors :class:`ml.inference.transformer_detector.TransformerDetector`
so the Analyzer can use either class without modification.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_ARTIFACTS = Path(__file__).resolve().parent.parent / "artifacts" / "transformer_model"
ONNX_INT8_PATH = _ARTIFACTS / "model.int8.onnx"
ONNX_FP32_PATH = _ARTIFACTS / "model.onnx"
TOKENIZER_DIR = _ARTIFACTS / "tokenizer"
CATEGORIES_PATH = _ARTIFACTS / "categories.json"
TEMPERATURE_PATH = _ARTIFACTS / "temperature.json"

MAX_LENGTH = 256
_N_BINARY = 2  # binary head always outputs exactly 2 logits


_WARNED: set[str] = set()


def _once(key: str, msg: str, *args) -> None:
    if key not in _WARNED:
        _WARNED.add(key)
        logger.debug(msg, *args)


class TransformerDetectorV2:
    """Production inference wrapper for the v2 multi-task model.

    Usage::

        det = TransformerDetectorV2.load()
        prob, latency_ms = det.predict("ignore all previous instructions")
        category, cat_prob, latency_ms = det.predict_category("...")
        is_atk, prob, latency_ms = det.is_attack("...")
    """

    def __init__(
        self,
        *,
        onnx_int8_path: Optional[str] = None,
        onnx_fp32_path: Optional[str] = None,
        tokenizer_dir: Optional[str] = None,
        categories_path: Optional[str] = None,
        temperature_path: Optional[str] = None,
        max_length: int = MAX_LENGTH,
        threshold: float = 0.5,
        warn_if_unready: bool = True,
    ) -> None:
        self.threshold = threshold
        self._max_length = max_length
        self._backend: str = "none"
        self._onnx_sess = None
        self._torch_model = None
        self._tokenizer = None
        self._temperature: float = 1.0
        self._category_index: Dict[str, int] = {}
        self._index_to_category: Dict[int, str] = {}
        self._n_categories: int = 0
        self._degraded_reason: Optional[str] = None

        int8 = Path(onnx_int8_path or ONNX_INT8_PATH)
        fp32 = Path(onnx_fp32_path or ONNX_FP32_PATH)
        tok = Path(tokenizer_dir or TOKENIZER_DIR)
        cats = Path(categories_path or CATEGORIES_PATH)
        temp = Path(temperature_path or TEMPERATURE_PATH)

        self._onnx_path_used: str = str(int8 if int8.exists() else fp32)

        self._load_category_index(cats)
        self._load_temperature(temp)
        self._init_tokenizer(tok)

        if self._tokenizer is None:
            self._degraded_reason = (
                f"tokenizer_dir_missing: {tok}" if not tok.exists()
                else "tokenizer_load_failed"
            )
            if warn_if_unready:
                _once(self._degraded_reason,
                      "TransformerDetectorV2 inactive: %s", self._degraded_reason)
            return

        if int8.exists():
            self._init_onnx(int8, quantized=True)
        elif fp32.exists():
            self._init_onnx(fp32, quantized=False)
        else:
            self._init_torch()

        if self._backend == "none":
            self._degraded_reason = f"model_missing: {int8} / {fp32}"
            if warn_if_unready:
                _once(self._degraded_reason,
                      "TransformerDetectorV2 inactive: no model found at %s / %s. "
                      "Train with `python scripts/train_transformer_v2.py --data <corpus>`.",
                      int8, fp32)

    # ------------------------------------------------------------------ setup

    def _load_category_index(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            raw: Dict[str, int] = json.loads(path.read_text(encoding="utf-8"))
            self._category_index = raw
            self._index_to_category = {v: k for k, v in raw.items()}
            self._n_categories = len(raw)
        except Exception as exc:
            logger.debug("TransformerDetectorV2: could not load categories: %s", exc)

    def _load_temperature(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._temperature = float(data.get("temperature", 1.0))
        except Exception as exc:
            logger.debug("TransformerDetectorV2: could not load temperature: %s", exc)

    def _init_tokenizer(self, tok_dir: Path) -> None:
        if not tok_dir.exists():
            return
        try:
            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(str(tok_dir))
            logger.debug("TransformerDetectorV2: tokenizer loaded from %s", tok_dir)
        except Exception as exc:
            logger.warning("TransformerDetectorV2: tokenizer load failed: %s", exc)

    def _init_onnx(self, path: Path, *, quantized: bool) -> None:
        try:
            import onnxruntime as ort
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = int(os.environ.get("MEMGAR_ORT_THREADS", "2"))
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._onnx_sess = ort.InferenceSession(
                str(path),
                sess_options=opts,
                providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
            )
            self._backend = "onnx_int8" if quantized else "onnx_fp32"
            logger.info(
                "TransformerDetectorV2: %s backend ready (%s, %.1f MB)",
                self._backend,
                path.name,
                path.stat().st_size / 1_048_576,
            )
        except Exception as exc:
            logger.warning("TransformerDetectorV2: ONNX init failed (%s): %s", path.name, exc)
            if not quantized:
                self._init_torch()

    def _init_torch(self) -> None:
        pytorch_dir = _ARTIFACTS / "pytorch_best.pt"
        if not pytorch_dir.exists():
            return
        try:
            import torch
            from transformers import AutoConfig, AutoModel

            cfg_path = _ARTIFACTS / "tokenizer"
            config = AutoConfig.from_pretrained(str(cfg_path))
            backbone = AutoModel.from_config(config)

            # Minimal re-creation of the MultiTaskClassifier head
            class _Model(torch.nn.Module):
                def __init__(self, backbone, hidden, n_cats):
                    super().__init__()
                    self.backbone = backbone
                    self.binary_head = torch.nn.Linear(hidden, 2)
                    self.category_head = torch.nn.Linear(hidden, max(n_cats, 1))

                def forward(self, input_ids, attention_mask):
                    out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
                    cls = out.last_hidden_state[:, 0]
                    return torch.cat([self.binary_head(cls), self.category_head(cls)], dim=-1)

            model = _Model(backbone, config.hidden_size, self._n_categories)
            model.load_state_dict(torch.load(str(pytorch_dir), map_location="cpu"), strict=False)
            model.eval()
            self._torch_model = model
            self._backend = "torch"
            logger.info("TransformerDetectorV2: PyTorch backend ready")
        except Exception as exc:
            logger.warning("TransformerDetectorV2: PyTorch init failed: %s", exc)

    # ------------------------------------------------------------------ inference helpers

    def _tokenize(self, text: str):
        return self._tokenizer(
            text,
            return_tensors="np",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )

    def _onnx_feed(self, enc) -> dict:
        names = getattr(self, "_onnx_input_names", None)
        if names is None:
            names = {inp.name for inp in self._onnx_sess.get_inputs()}
            self._onnx_input_names = names
        feed = {}
        if "input_ids" in names:
            feed["input_ids"] = enc["input_ids"]
        if "attention_mask" in names:
            feed["attention_mask"] = enc["attention_mask"]
        if "token_type_ids" in names and "token_type_ids" in enc:
            feed["token_type_ids"] = enc["token_type_ids"]
        return feed

    def _split(self, logits) -> tuple:
        """Split concatenated ONNX output into binary + category logits."""
        binary = logits[:, :_N_BINARY]
        cat = logits[:, _N_BINARY:] if logits.shape[1] > _N_BINARY else None
        return binary, cat

    def _binary_prob(self, binary_logits) -> float:
        import numpy as _np
        scaled = binary_logits[0] / max(self._temperature, 1e-6)
        e = _np.exp(scaled - scaled.max())
        probs = e / e.sum()
        return float(probs[1])

    def _category_label(self, cat_logits) -> Tuple[str, float]:
        import numpy as _np
        if cat_logits is None or len(cat_logits[0]) == 0 or not self._index_to_category:
            return "unknown", 0.0
        row = cat_logits[0]
        e = _np.exp(row - row.max())
        probs = e / e.sum()
        idx = int(probs.argmax())
        return self._index_to_category.get(idx, "unknown"), float(probs[idx])

    # ------------------------------------------------------------------ public API

    @property
    def is_ready(self) -> bool:
        return self._backend != "none" and self._tokenizer is not None

    def predict(self, text: str) -> Tuple[float, float]:
        """Return ``(attack_probability, latency_ms)``."""
        if not self.is_ready:
            return 0.0, 0.0
        t0 = time.perf_counter()
        enc = self._tokenize(text)
        if self._backend in ("onnx_int8", "onnx_fp32"):
            feed = self._onnx_feed(enc)
            raw = self._onnx_sess.run(None, feed)[0]
        else:
            import torch
            t_enc = {k: torch.tensor(v) for k, v in enc.items()
                     if k in ("input_ids", "attention_mask")}
            with torch.no_grad():
                raw = self._torch_model(**t_enc).numpy()
        binary, _ = self._split(raw)
        prob = self._binary_prob(binary)
        return prob, round((time.perf_counter() - t0) * 1000, 2)

    def predict_category(self, text: str) -> Tuple[str, float, float]:
        """Return ``(category_label, category_probability, latency_ms)``."""
        if not self.is_ready:
            return "unknown", 0.0, 0.0
        t0 = time.perf_counter()
        enc = self._tokenize(text)
        if self._backend in ("onnx_int8", "onnx_fp32"):
            feed = self._onnx_feed(enc)
            raw = self._onnx_sess.run(None, feed)[0]
        else:
            import torch
            t_enc = {k: torch.tensor(v) for k, v in enc.items()
                     if k in ("input_ids", "attention_mask")}
            with torch.no_grad():
                raw = self._torch_model(**t_enc).numpy()
        _, cat_logits = self._split(raw)
        label, conf = self._category_label(cat_logits)
        return label, conf, round((time.perf_counter() - t0) * 1000, 2)

    def predict_batch(self, texts: List[str]) -> List[Tuple[float, float]]:
        """Batch inference — more efficient than calling predict() in a loop."""
        if not self.is_ready or not texts:
            return [(0.0, 0.0)] * len(texts)
        t0 = time.perf_counter()
        enc = self._tokenizer(
            texts,
            return_tensors="np",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )
        if self._backend in ("onnx_int8", "onnx_fp32"):
            feed = self._onnx_feed(enc)
            raw = self._onnx_sess.run(None, feed)[0]
        else:
            import torch
            t_enc = {k: torch.tensor(v) for k, v in enc.items()
                     if k in ("input_ids", "attention_mask")}
            with torch.no_grad():
                raw = self._torch_model(**t_enc).numpy()
        per_item_ms = round((time.perf_counter() - t0) * 1000 / len(texts), 2)
        results = []
        for i in range(len(texts)):
            row = raw[i:i+1]
            binary, _ = self._split(row)
            results.append((self._binary_prob(binary), per_item_ms))
        return results

    def is_attack(self, text: str) -> Tuple[bool, float, float]:
        """Return ``(is_attack, probability, latency_ms)``."""
        prob, latency = self.predict(text)
        return prob >= self.threshold, prob, latency

    def health(self) -> dict:
        ready = self.is_ready
        fix_hint: Optional[str] = None
        if not ready and self._degraded_reason:
            r = self._degraded_reason
            if r.startswith("model_missing"):
                fix_hint = "Train with `python scripts/train_transformer_v2.py --data <corpus>`"
            elif "tokenizer" in r:
                fix_hint = "pip install transformers"
            else:
                fix_hint = "pip install onnxruntime"
        return {
            "status": "ok" if ready else "degraded",
            "reason": self._degraded_reason if not ready else None,
            "is_ready": ready,
            "backend": self._backend,
            "onnx_path": self._onnx_path_used,
            "tokenizer_dir": str(TOKENIZER_DIR),
            "temperature": self._temperature,
            "n_categories": self._n_categories,
            "fix_hint": fix_hint,
        }

    @classmethod
    def load(
        cls,
        *,
        threshold: float = 0.5,
        max_length: int = MAX_LENGTH,
    ) -> "TransformerDetectorV2":
        return cls(threshold=threshold, max_length=max_length)

    def __repr__(self) -> str:
        return (
            f"TransformerDetectorV2(backend={self._backend!r}, "
            f"ready={self.is_ready}, "
            f"n_categories={self._n_categories}, "
            f"temperature={self._temperature:.3f})"
        )
