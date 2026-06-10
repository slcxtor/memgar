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
