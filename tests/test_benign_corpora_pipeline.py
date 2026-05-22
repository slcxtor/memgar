"""Tests for the benign-corpora import + memory-write filter pipeline.

These tests run offline — no network. The HF fetch path is mocked.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.import_benign_corpora as ibc
from scripts.import_public_corpora import _detect_language


class TestMemoryWriteFilter:
    """The core filter — what survives is what the trainer sees as benign."""

    @pytest.mark.parametrize("text", [
        "Remember that I prefer dark mode",
        "Save my favorite color as blue",
        "From now on always reply in Turkish",
        "My name is Alex",
        "I prefer concise answers",
        "Please note that my timezone is UTC+3",
        "Don't forget to use formal tone with this client",
        "My email is foo@example.com",
        "Important: I'm vegetarian",
        "Whenever I ask about the weather, give a short answer",
    ])
    def test_legitimate_memory_writes_pass(self, text):
        assert ibc._is_memory_write(text) is True, f"should accept: {text!r}"

    @pytest.mark.parametrize("text", [
        "",                                          # empty
        "hi",                                        # too short
        "a" * 600,                                   # too long
        "What is the capital of France?",            # no memory marker
        "def foo(): return 42",                      # code
        "import numpy as np\nprint('hello')",        # code
        "```python\nprint(1)\n```",                  # code fence
        "I cannot help with that request",           # RLHF refusal
        "As an AI language model, I think...",       # RLHF self-ref
        "Step 1: open. Step 2: close. Step 3: lock.", # CoT
        "<div>save this preference</div>",           # HTML
        "Sure, happy to help! Save this preference", # RLHF intro
        "fuck this, save my preference",             # toxic
    ])
    def test_rejected_content(self, text):
        assert ibc._is_memory_write(text) is False, f"should reject: {text!r}"

    def test_multiparagraph_blocks_rejected(self):
        text = "Remember my preference.\n\nThis is a second paragraph that makes it too long."
        assert ibc._is_memory_write(text) is False

    def test_many_sentences_rejected(self):
        text = ("Remember this. Save that. Note here. "
                "Important now. Don't forget. Always do.")
        assert ibc._is_memory_write(text) is False

    def test_turkish_text_rejected(self):
        # Real Turkish — should be detected and dropped from English benign set.
        text = "Lütfen şunu kayıt et: tercih ettiğim renk mavi"
        assert ibc._is_memory_write(text) is False

    def test_english_with_capital_i_not_misclassified_as_turkish(self):
        """Regression for the _TURKISH_CHARS bug — ASCII capital I was
        previously triggering 'tr' detection on ordinary English."""
        assert _detect_language("I prefer dark mode") == "en"
        assert _detect_language("Remember that I work in New York") == "en"
        assert _detect_language("My name is Ian") == "en"
        # But real Turkish-only chars still detected:
        assert _detect_language("Şu bilgiyi kaydet") == "tr"
        assert _detect_language("dotless ı in middle") == "tr"


class TestSourceParsers:
    """Each parser must extract the user-side memory-write surface from its
    source's native row format."""

    def test_oasst_extracts_prompter_role_only(self):
        blob = (
            b'{"role": "prompter", "text": "Remember that I prefer concise answers", "message_id": "abc"}\n'
            b'{"role": "assistant", "text": "Sure, I will remember that.", "message_id": "def"}\n'
            b'{"role": "prompter", "text": "Save my favorite color as blue", "message_id": "ghi"}\n'
        )
        rows = list(ibc._parse_oasst(blob))
        assert len(rows) == 2
        assert all(r["label"] == 0 for r in rows)
        assert all(r["source"] == "openassistant_oasst1" for r in rows)
        assert rows[0]["_orig_id"] == "abc"
        assert rows[1]["text"] == "Save my favorite color as blue"

    def test_hh_rlhf_extracts_first_human_turn(self):
        blob = (
            b'{"chosen": "\\n\\nHuman: Remember my dietary preference: vegetarian.\\n\\nAssistant: Got it!"}\n'
        )
        rows = list(ibc._parse_hh_rlhf(blob))
        assert len(rows) == 1
        assert "vegetarian" in rows[0]["text"]
        assert "Assistant" not in rows[0]["text"]
        assert rows[0]["source"] == "hh_rlhf_helpful"

    def test_dolly_extracts_instruction(self):
        blob = (
            b'{"instruction": "Save my email as foo@bar.com", "context": "", "response": "Done", "category": "personal"}\n'
        )
        rows = list(ibc._parse_dolly(blob))
        assert len(rows) == 1
        assert rows[0]["text"] == "Save my email as foo@bar.com"
        assert rows[0]["_orig_id"] == "personal"

    def test_lmsys_extracts_first_user_turn(self):
        blob = (
            b'{"conversation": ['
            b'{"role": "user", "content": "Remember my city: Istanbul"},'
            b'{"role": "assistant", "content": "OK, noted."},'
            b'{"role": "user", "content": "Also remember my timezone"}'
            b']}\n'
        )
        rows = list(ibc._parse_lmsys(blob))
        # Only the FIRST user turn is taken per conversation.
        assert len(rows) == 1
        assert rows[0]["text"] == "Remember my city: Istanbul"

    def test_parsers_skip_malformed_rows(self):
        blob = b'not-json\n{"role": "prompter", "text": "save my preference"}\n\n'
        rows = list(ibc._parse_oasst(blob))
        assert len(rows) == 1


class TestFilterAndDedup:
    """Cross-source dedup must keep the seen-hash set consistent."""

    def test_dedup_removes_exact_duplicates(self):
        rows = [
            {"text": "Remember my preference for dark mode", "label": 0, "source": "a"},
            {"text": "Remember my preference for dark mode", "label": 0, "source": "b"},
            {"text": "Save my favorite color as blue",        "label": 0, "source": "c"},
        ]
        seen = set()
        kept = ibc._filter_and_dedup(rows, min_len=10, max_len=500, seen_hashes=seen)
        assert len(kept) == 2
        assert len(seen) == 2

    def test_dedup_carries_across_sources(self):
        rows_a = [{"text": "Remember dark mode preference", "label": 0, "source": "a"}]
        rows_b = [{"text": "Remember dark mode preference", "label": 0, "source": "b"}]
        seen = set()
        kept_a = ibc._filter_and_dedup(rows_a, 10, 500, seen)
        kept_b = ibc._filter_and_dedup(rows_b, 10, 500, seen)
        assert len(kept_a) == 1
        assert len(kept_b) == 0    # filtered as duplicate

    def test_filter_drops_non_memory_writes(self):
        rows = [
            {"text": "Remember my preference for dark mode", "label": 0, "source": "a"},
            {"text": "What is the capital of France?",        "label": 0, "source": "a"},
            {"text": "def foo(): pass",                       "label": 0, "source": "a"},
        ]
        seen = set()
        kept = ibc._filter_and_dedup(rows, 10, 500, seen)
        assert len(kept) == 1
        assert "dark mode" in kept[0]["text"]

    def test_kept_rows_have_content_hash(self):
        rows = [{"text": "Remember my dark mode preference", "label": 0, "source": "a"}]
        seen = set()
        kept = ibc._filter_and_dedup(rows, 10, 500, seen)
        assert "_content_hash" in kept[0]
        assert len(kept[0]["_content_hash"]) == 16


class TestPrepareV2Integration:
    """The prepare_v2_dataset.py wiring must round-trip the new flag."""

    def test_load_benign_corpora_round_trips(self, tmp_path):
        import scripts.prepare_v2_dataset as pvd
        bc_path = tmp_path / "benign_corpora.json"
        rows = [
            {"text": "Remember my dark mode preference", "label": 0,
             "source": "openassistant_oasst1", "category": "benign_memory_write"},
            {"text": "Save my favorite color as blue", "label": 0,
             "source": "dolly_15k", "category": "benign_memory_write"},
        ]
        bc_path.write_text(json.dumps(rows), encoding="utf-8")
        loaded = pvd.load_benign_corpora(bc_path)
        assert len(loaded) == 2
        assert all(ex.label == 0 for ex in loaded)
        # Source provenance preserved per-row (not collapsed to one tag).
        assert {ex.source for ex in loaded} == {"openassistant_oasst1", "dolly_15k"}

    def test_load_benign_corpora_missing_file_is_no_op(self, tmp_path):
        import scripts.prepare_v2_dataset as pvd
        result = pvd.load_benign_corpora(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_benign_corpora_skips_malformed_rows(self, tmp_path):
        import scripts.prepare_v2_dataset as pvd
        bc_path = tmp_path / "bad.json"
        bc_path.write_text(json.dumps([
            {"text": "valid memory write", "label": 0},
            {"no_text_field": "skipped"},
            "not_a_dict",
            {"text": "another valid one", "label": 0},
        ]), encoding="utf-8")
        loaded = pvd.load_benign_corpora(bc_path)
        assert len(loaded) == 2


class TestSourceRegistry:
    """The four sources must be discoverable and license-tagged."""

    def test_all_sources_have_required_fields(self):
        for key, src in ibc.SOURCES.items():
            assert src.name
            assert src.hf_dataset
            assert src.license_name
            assert src.license_url
            assert src.attribution
            assert src.notes
            assert callable(src.parser)

    def test_license_clean_sources_only(self):
        # Hard rule: no CC-BY-NC sources (Alpaca is excluded for this reason).
        for src in ibc.SOURCES.values():
            assert "NC" not in src.license_name, \
                f"non-commercial source not allowed: {src.name}"

    def test_gated_sources_documented(self):
        gated = [s for s in ibc.SOURCES.values() if s.gated]
        assert all("HF_TOKEN" in s.notes or "GATED" in s.notes.upper()
                   for s in gated)
