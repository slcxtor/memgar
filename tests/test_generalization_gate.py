"""
Generalization gate — the gate's own guard rails.

The gate exists because every other corpus in this repo was written
alongside the patterns that score it. Its value depends on two things that
are easy to erode by accident: the corpus staying held-out, and the
regression bounds staying meaningful at a low baseline.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO_ROOT / "ml" / "data" / "generalization_corpus.json"
BASELINE_PATH = REPO_ROOT / "ml" / "artifacts" / "generalization_baseline.json"
GATE_PATH = REPO_ROOT / "scripts" / "check_generalization_gate.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("generalization_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def corpus():
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


class TestCorpusShape:
    def test_every_attack_has_a_structurally_matched_benign(self, corpus):
        """The pairing is what exposes a detector keying on sentence shape
        rather than intent: it cannot score well on one half without
        wrecking the other."""
        samples = corpus["samples"]
        attacks = [s for s in samples if s["label"] == 1]
        benigns = [s for s in samples if s["label"] == 0]
        assert len(attacks) == len(benigns)

        attack_categories = sorted(s["category"] for s in attacks)
        benign_categories = sorted(
            s["category"].removesuffix("_benign_pair") for s in benigns
        )
        assert attack_categories == benign_categories

    def test_samples_are_unique(self, corpus):
        texts = [s["text"] for s in corpus["samples"]]
        assert len(set(texts)) == len(texts)

    def test_corpus_states_the_do_not_optimise_contract(self, corpus):
        """A corpus that gets patterns written against it stops measuring
        generalization, so the contract travels with the data."""
        assert "contract" in corpus
        assert "thermometer" in corpus["contract"]

    def test_no_pattern_was_authored_against_a_sample(self, corpus):
        """Guard against the failure mode that silently voids this gate:
        someone makes it green by matching the samples verbatim."""
        from memgar.patterns import PATTERNS

        literals = {
            p.strip().lower()
            for threat in PATTERNS
            for p in threat.keywords
            if len(p.strip()) > 25
        }
        for sample in corpus["samples"]:
            text = sample["text"].lower()
            for literal in literals:
                assert literal not in text, (
                    f"keyword {literal!r} appears verbatim in a held-out sample"
                )


class TestRegressionBounds:
    """A fractional tolerance is vacuous at a low baseline — 0.05 against a
    recall of 0.026 puts the floor below zero, so detection could collapse
    to nothing and still pass. Bounds are counted in whole samples."""

    def test_floor_never_allows_total_collapse(self, gate):
        floor, _ = gate.bounds({"recall": 1 / 38, "fpr": 0.0}, 38, 38)
        assert floor > 0.0
        assert 0.0 < floor <= 1 / 38 + 1e-9

    def test_floor_is_never_negative(self, gate):
        floor, _ = gate.bounds({"recall": 0.0, "fpr": 0.0}, 38, 38)
        assert floor == 0.0

    def test_slack_opens_up_as_recall_improves(self, gate):
        floor, _ = gate.bounds({"recall": 20 / 38, "fpr": 0.0}, 38, 38)
        assert floor == pytest.approx((20 - gate.SLACK_SAMPLES) / 38, abs=1e-3)

    def test_fpr_ceiling_allows_slack_but_is_bounded(self, gate):
        _, ceiling = gate.bounds({"recall": 0.0, "fpr": 0.0}, 38, 38)
        assert ceiling == pytest.approx(gate.SLACK_SAMPLES / 38, abs=1e-3)


class TestBaselineArtifact:
    def test_baseline_matches_the_corpus_it_was_recorded_against(self, corpus):
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        assert baseline["corpus"] == CORPUS_PATH.name
        assert baseline["n_attack"] == sum(
            1 for s in corpus["samples"] if s["label"] == 1
        )
        assert baseline["n_benign"] == sum(
            1 for s in corpus["samples"] if s["label"] == 0
        )

    def test_recorded_recall_is_reported_not_hidden(self):
        """If this ever reads as a comfortable number, check that the corpus
        was not quietly optimised against."""
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        assert 0.0 <= baseline["recall"] <= 1.0
        assert 0.0 <= baseline["fpr"] <= 1.0
