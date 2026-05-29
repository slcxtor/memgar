"""Explicit opt-in consent gate for pilot memory-write collection.

Collection is **off by default**. To enable, the operator must either
(a) call ``PilotConsent.acknowledge(...)`` with the data-use statement, or
(b) set ``MEMGAR_PILOT_CONSENT=1`` in the environment AND have written a
``consent.json`` file in the pilot output directory (see PILOT_GUIDE.md).

The consent record is timestamped and includes the Memgar version + a
short note from the operator. The collector refuses to write without it.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


CONSENT_FILENAME = "consent.json"
ENV_FLAG = "MEMGAR_PILOT_CONSENT"


@dataclass
class ConsentRecord:
    acknowledged_at: str
    operator: str
    purpose: str
    memgar_version: str
    notes: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=True)


class PilotConsent:
    """Filesystem-backed consent gate.

    Required fields when acknowledging:
      operator : who is enabling collection (name / team).
      purpose  : short statement of what the data is used for ("train Layer 2-ML
                 on production-shape benign + attack memory writes").
    """

    def __init__(self, output_dir: str | os.PathLike) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.output_dir / CONSENT_FILENAME

    # ---------------------------------------------------------------- ack
    def acknowledge(
        self,
        operator: str,
        purpose: str,
        notes: Optional[str] = None,
    ) -> ConsentRecord:
        if not operator or not purpose:
            raise ValueError("acknowledge() requires both 'operator' and 'purpose'")
        try:
            from memgar import __version__ as version
        except Exception:
            version = "unknown"
        record = ConsentRecord(
            acknowledged_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
            operator=operator,
            purpose=purpose,
            memgar_version=str(version),
            notes=notes,
        )
        self._path.write_text(record.to_json(), encoding="utf-8")
        try:
            os.chmod(self._path, 0o640)
        except OSError:
            pass
        return record

    # --------------------------------------------------------------- check
    def is_satisfied(self) -> bool:
        if not self._path.exists():
            return False
        # Both filesystem consent AND env flag are required for runtime collection.
        return os.environ.get(ENV_FLAG, "").strip() in ("1", "true", "yes", "on")

    def require(self) -> ConsentRecord:
        """Raise ``PermissionError`` unless consent is satisfied; otherwise
        return the stored record so the operator's intent is auditable."""
        if not self._path.exists():
            raise PermissionError(
                "Pilot collection refused: no consent.json found at "
                f"{self._path}. Call PilotConsent(...).acknowledge(...) first.")
        if os.environ.get(ENV_FLAG, "").strip() not in ("1", "true", "yes", "on"):
            raise PermissionError(
                "Pilot collection refused: consent file exists but env var "
                f"{ENV_FLAG} is not set. This second gate is intentional — "
                "every process that collects must opt in explicitly.")
        return ConsentRecord(**json.loads(self._path.read_text(encoding="utf-8")))


__all__ = ["PilotConsent", "ConsentRecord", "CONSENT_FILENAME", "ENV_FLAG"]
