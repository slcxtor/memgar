"""Pilot collection — anonymized, consent-gated, opt-in memory-write capture.

Public API::

    from memgar.pilot import enable_pilot_collection, PilotCollector

    # Acknowledge once (writes consent.json in output_dir):
    from memgar.pilot import PilotConsent
    PilotConsent("ml/pilot_data").acknowledge(
        operator="security@acme.example",
        purpose="train Layer 2-ML on production memory-write traffic",
    )
    # Then set MEMGAR_PILOT_CONSENT=1 in the env that runs the agent.

    # Wire it to your Analyzer:
    from memgar import Analyzer
    a = Analyzer(use_llm=False)
    enable_pilot_collection(a, output_dir="ml/pilot_data")

    # Run as usual — every analyze() call is mirrored to a rotating JSONL,
    # with PII scrubbed and identifiers HMAC-hashed under a per-pilot salt.

    # Later: export to training-corpus shape
    #   python -m memgar.pilot.export --input ml/pilot_data \
    #          --output ml/data/pilot_corpus.json

See ``PILOT_GUIDE.md`` for the privacy contract and operator checklist.
"""

from __future__ import annotations

from typing import Any, Optional

from .anonymizer import AnonymizationResult, PilotAnonymizer
from .collector import (
    PilotCollector,
    PilotStats,
    SCHEMA_VERSION,
    attach_to_analyzer,
)
from .consent import CONSENT_FILENAME, ENV_FLAG, ConsentRecord, PilotConsent


def enable_pilot_collection(
    analyzer: Any,
    *,
    output_dir: str = "ml/pilot_data",
    state_dir: str = "ml/pilot_state",
    refuse_on_leak: bool = True,
) -> PilotCollector:
    """Attach a pilot collector to an Analyzer instance.

    Refuses silently (does not write rows) until both the on-disk consent
    record AND the ``MEMGAR_PILOT_CONSENT`` env var are present. Returns the
    collector so the operator can read ``collector.stats``.
    """
    collector = PilotCollector(
        output_dir=output_dir,
        state_dir=state_dir,
        refuse_on_leak=refuse_on_leak,
    )
    attach_to_analyzer(analyzer, collector)
    return collector


__all__ = [
    "AnonymizationResult",
    "ConsentRecord",
    "PilotAnonymizer",
    "PilotCollector",
    "PilotConsent",
    "PilotStats",
    "CONSENT_FILENAME",
    "ENV_FLAG",
    "SCHEMA_VERSION",
    "attach_to_analyzer",
    "enable_pilot_collection",
]
