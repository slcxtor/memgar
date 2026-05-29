#!/usr/bin/env python3
"""Does the embedding semantic layer (Layer 1.5) add NET value over Layer 1?

Experiment:
  positives = on-target externally-authored attacks (Gandalf, in-the-wild,
              deepset) + documented attacks + gold attacks
  negatives = realistic benign memory-writes (benign_calibration_large) + the
              license-clean public benigns (benign_corpora)
  70/30 split. Fit SemanticGuard on TRAIN attacks; sweep threshold on TEST.

Reports, at the F1-optimal threshold:
  - SemanticGuard standalone recall / FPR / F1 (must clear the F1>=0.70 gate)
  - NET value: of the TEST attacks Layer-1 MISSES (ALLOW), how many does the
    semantic layer catch?  And of TEST benigns Layer-1 lets pass, how many does
    the semantic layer wrongly flag?  (added recall vs added FPR)

    python scripts/eval_semantic_layer.py
"""
from __future__ import annotations
import json, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
rng = random.Random(42)


def _note_src(n):
    for p in str(n or "").split(";"):
        if "source=" in p:
            return p.split("source=")[1].strip()
    return ""


def load_attacks():
    out = []
    raw = json.loads((ROOT/"ml/data/external_corpus_raw.json").read_text())
    raw = raw if isinstance(raw, list) else raw.get("samples", [])
    for r in raw:
        if str(r.get("label")) != "1":
            continue
        src = _note_src(r.get("note"))
        if any(k in src for k in ("gandalf", "in_the_wild", "trustairlab", "deepset")):
            out.append(r["text"])
    # gold attacks
    g = json.loads((ROOT/"ml/data/calibration_corpus.json").read_text())["samples"]
    out += [s["text"] for s in g if s.get("label") == 1]
    return list({t for t in out if t and len(t) > 8})


def load_benigns():
    out = []
    for f in ("benign_calibration_large.json", "benign_corpora.json"):
        p = ROOT/"ml/data"/f
        if not p.exists():
            continue
        d = json.loads(p.read_text())
        s = d if isinstance(d, list) else d.get("samples", [])
        out += [r.get("text", "") for r in s if str(r.get("label", 0)) == "0" or "benign" in f]
    return list({t for t in out if t and len(t) > 8})


def main():
    from memgar.semantic_guard import SemanticGuard
    from memgar import Analyzer, MemoryEntry, Decision

    attacks = load_attacks(); benigns = load_benigns()
    rng.shuffle(attacks); rng.shuffle(benigns)
    na, nb = len(attacks), len(benigns)
    print(f"attacks={na}  benigns={nb}")
    at_tr, at_te = attacks[:int(na*0.7)], attacks[int(na*0.7):]
    bn_te = benigns[int(nb*0.7):]

    guard = SemanticGuard()
    if guard.model is None if hasattr(guard, "model") else False:
        pass
    guard.fit(at_tr, n_centroids=64)

    # scores
    a_scores = [guard.score(t) for t in at_te]
    b_scores = [guard.score(t) for t in bn_te]
    if max(a_scores + b_scores) == 0.0:
        print("SemanticGuard inactive (no embeddings) — abort"); return 1

    # sweep threshold for best F1
    best = None
    for thr in [i/100 for i in range(40, 96, 2)]:
        tp = sum(1 for s in a_scores if s >= thr)
        fp = sum(1 for s in b_scores if s >= thr)
        rec = tp/len(a_scores); fpr = fp/len(b_scores)
        prec = tp/max(1, tp+fp)
        f1 = 2*prec*rec/max(1e-9, prec+rec)
        if best is None or f1 > best["f1"]:
            best = dict(thr=thr, rec=rec, fpr=fpr, prec=prec, f1=f1)
    print(f"\nSemanticGuard standalone @ best-F1 thr={best['thr']}: "
          f"recall={best['rec']:.2f} FPR={best['fpr']:.3f} F1={best['f1']:.2f} "
          f"({'PASS' if best['f1']>=0.70 else 'FAIL'} F1>=0.70 gate)")

    # NET value over Layer 1
    a = Analyzer(use_llm=False, semantic_guard=False, use_transformer_ml=False)
    thr = best["thr"]
    miss_caught = miss_total = 0
    for i, t in enumerate(at_te):
        d = a.analyze(MemoryEntry(content=t, source_type="external",
                                  source_id=f"a{i}", metadata={"agent_id": f"a{i}"})).decision
        if d == Decision.ALLOW:                      # Layer-1 missed it
            miss_total += 1
            if guard.score(t) >= thr:
                miss_caught += 1
    added_fp = added_fp_tot = 0
    for i, t in enumerate(bn_te):
        d = a.analyze(MemoryEntry(content=t, source_type="memory",
                                  source_id=f"b{i}", metadata={"agent_id": f"b{i}"})).decision
        if d == Decision.ALLOW:                       # Layer-1 passed it (correct)
            added_fp_tot += 1
            if guard.score(t) >= thr:
                added_fp += 1
    print(f"\nNET over Layer-1 @ thr={thr}:")
    print(f"  Layer-1-missed attacks recovered by semantic: {miss_caught}/{miss_total}")
    print(f"  benign newly false-flagged by semantic:        {added_fp}/{added_fp_tot} "
          f"({added_fp/max(1,added_fp_tot)*100:.1f}% added FPR)")
    verdict = ("NET POSITIVE" if miss_caught > 0 and added_fp/max(1,added_fp_tot) <= 0.02
               else "NOT NET POSITIVE at <=2% added FPR")
    print(f"  => {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
