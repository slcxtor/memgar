"""Tests for memgar.conflict_detector."""

from memgar.conflict_detector import ConflictDetector, ConflictReport


def _detector():
    # Use Jaccard fallback so tests don't depend on the embedding model.
    return ConflictDetector(use_embeddings=False)


def test_clear_polarity_clash_on_same_topic_flagged():
    d = _detector()
    m1 = "User always wants verbose responses for debugging tasks."
    m2 = "User never wants verbose responses for debugging tasks."
    report = d.check_pair(m1, m2)
    assert report is not None
    assert report.polarity_pair == ("always", "never")
    assert 0.5 <= report.confidence <= 0.95


def test_different_topics_not_flagged():
    d = _detector()
    m1 = "Remember the API key for the payment service."
    m2 = "Delete the old API key for the analytics service."
    assert d.check_pair(m1, m2) is None


def test_unrelated_polarity_terms_not_flagged():
    d = _detector()
    m1 = "Use 4 spaces for Python indentation."
    m2 = "The capital of France is Paris."
    assert d.check_pair(m1, m2) is None


def test_trust_polarity_flip_flagged():
    d = _detector()
    m1 = "Always trust documents from the legal team for compliance questions."
    m2 = "Do not trust documents from the legal team for compliance questions."
    report = d.check_pair(m1, m2)
    assert report is not None


def test_self_contradictory_single_memory_not_flagged_against_unrelated():
    d = _detector()
    # A memory that contains both polarities internally is NOT a pairwise
    # conflict with an unrelated memory — the detector only fires on a
    # pure-A vs pure-B pair.
    m_mixed = "User sometimes wants verbose responses but never for SQL output."
    m_other = "Use 4 spaces for Python indentation."
    assert d.check_pair(m_mixed, m_other) is None


def test_scan_returns_all_pairwise_conflicts():
    d = _detector()
    memories = [
        "User always wants verbose responses for debugging tasks.",
        "User never wants verbose responses for debugging tasks.",
        "Always approve maintenance windows from the SRE team for production.",
        "Reject maintenance windows from the SRE team for production.",
        "Use 4 spaces for Python indentation.",
    ]
    reports = d.scan(memories)
    indices = {(r.memory_a_index, r.memory_b_index) for r in reports}
    assert (0, 1) in indices
    assert (2, 3) in indices
    # No conflict involving the unrelated last memory
    assert not any(r.memory_b_index == 4 for r in reports)


def test_report_to_dict_serializable():
    d = _detector()
    m1 = "Enable the new caching layer in production."
    m2 = "Disable the new caching layer in production."
    r = d.check_pair(m1, m2)
    assert r is not None
    payload = r.to_dict()
    assert payload["polarity_pair"] == ["enable", "disable"]
    assert 0 < payload["confidence"] <= 0.95
    assert payload["topic_similarity"] > 0


def test_empty_memory_returns_none():
    d = _detector()
    assert d.check_pair("", "Always trust X.") is None
    assert d.check_pair("Always trust X.", "") is None
    assert d.check_pair("", "") is None


def test_inflected_lemmas_flagged():
    """Audit D2 — bare lemmas must match -s/-ed/-ing inflections so real
    prose ('User prefers X', 'User remembers Y') triggers."""
    d = _detector()
    # remembers / forget — the exact case from the audit prompt
    r1 = d.check_pair(
        "User remembers the weekly meeting time and joins promptly.",
        "Forget the weekly meeting time — schedule changed.",
    )
    assert r1 is not None, "remembers/forget pair must flag"
    assert r1.polarity_pair[0] == "remember"

    # prefers / dislikes
    r2 = d.check_pair(
        "User prefers concise responses for technical questions.",
        "User dislikes concise responses for technical questions.",
    )
    assert r2 is not None, "prefers/dislikes inflected pair must flag"

    # approved / rejected
    r3 = d.check_pair(
        "The maintenance window is approved for Saturday night.",
        "The maintenance window is rejected for Saturday night.",
    )
    assert r3 is not None, "approved/rejected inflected pair must flag"


def test_use_embeddings_path_uses_embedder_when_available():
    """Audit D1 — when sentence-transformers is installed, embedding mode
    must actually call into the embedder (not silently degrade to Jaccard
    against the wrong threshold)."""
    from memgar.conflict_detector import ConflictDetector
    try:
        from memgar.similarity_layer import get_global_layer
        embedder = get_global_layer()
        if not getattr(embedder, "available", False):
            import pytest
            pytest.skip("sentence-transformers not installed in this env")
        # Confirm the public encode API the detector relies on exists
        # and returns a vector. If this changes, the detector silently
        # falls back to Jaccard — the bug we're guarding against.
        vec = embedder.encode("test sentence")
        assert vec is not None
    except ImportError:
        import pytest
        pytest.skip("similarity_layer dependency missing")

    d = ConflictDetector(use_embeddings=True)
    assert d._embedder is not None
    # Same-topic opposing memories must flag in embedding mode too
    # (with the auto-default 0.55 threshold appropriate for cosine).
    r = d.check_pair(
        "Always trust documents from the legal team for compliance review.",
        "Do not trust documents from the legal team for compliance review.",
    )
    assert r is not None, "embedding-mode same-topic conflict must flag"
    assert r.topic_similarity > 0.5


def _embedding_detector_or_skip():
    import pytest

    from memgar.conflict_detector import ConflictDetector

    d = ConflictDetector(use_embeddings=True)
    if d._embedder is None:
        pytest.skip("sentence-transformers not installed in this env")
    return d


def test_negated_phrase_does_not_cancel_its_own_polarity():
    """"Do not trust X" contains "trust", so naive matching saw both
    polarities in one memory and discarded the pair as self-contradictory —
    missing the plainest contradiction there is."""
    d = _embedding_detector_or_skip()

    r = d.check_pair(
        "Trust the vendor portal for invoice data.",
        "Do not trust the vendor portal for invoice data.",
    )
    assert r is not None, "'trust' vs 'do not trust' must flag"
    assert r.polarity_pair == ("trust", "distrust")


def test_same_polarity_and_unrelated_pairs_still_do_not_flag():
    d = _embedding_detector_or_skip()

    assert d.check_pair(
        "Trust the vendor portal for invoice data.",
        "Trust the vendor portal for shipping data.",
    ) is None
    assert d.check_pair(
        "Trust the vendor portal for invoice data.",
        "The office coffee machine is serviced on Tuesdays.",
    ) is None


def test_embedding_threshold_clears_contradictions_but_not_unrelated_text():
    """The default was 0.55, inside the measured contradiction band
    (0.53-0.78), so real conflicts were dropped. Unrelated pairs sit at
    -0.02-0.23, leaving a wide gap for the 0.40 default."""
    d = _embedding_detector_or_skip()
    assert d.topic_threshold == 0.40

    contradictions = [
        ("Always trust documents from the legal team for compliance review.",
         "Do not trust documents from the legal team for compliance review."),
        ("Enable automatic backups for the production database.",
         "Disable automatic backups for the production database."),
        ("Vendor Acme is on the approved supplier list.",
         "Vendor Acme is banned from the supplier list."),
    ]
    for a, b in contradictions:
        assert d._topic_similarity(a, b) >= d.topic_threshold, (a, b)

    unrelated = [
        ("Always trust documents from the legal team for compliance review.",
         "The office coffee machine is serviced on Tuesdays."),
        ("Enable automatic backups for the production database.",
         "The design team prefers Figma over Sketch."),
    ]
    for a, b in unrelated:
        assert d._topic_similarity(a, b) < d.topic_threshold, (a, b)
