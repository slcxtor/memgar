"""One-time migration: export patterns.py Threat objects → memgar/data/patterns.yaml.

Run once to generate the YAML data file, then the thin patterns.py loader takes over.

    python scripts/export_patterns_to_yaml.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import while the old patterns.py is still in place
from memgar.patterns import PATTERNS  # noqa: E402

OUT = ROOT / "memgar" / "data" / "patterns.yaml"
OUT.parent.mkdir(parents=True, exist_ok=True)

records = []
for t in PATTERNS:
    rec: dict = {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "category": t.category.value,
        "severity": t.severity.value,
        "patterns": list(t.patterns),
    }
    if t.keywords:
        rec["keywords"] = list(t.keywords)
    if t.examples:
        rec["examples"] = list(t.examples)
    if t.mitre_attack:
        rec["mitre_attack"] = t.mitre_attack
    records.append(rec)

OUT.write_text(
    yaml.dump(records, allow_unicode=True, default_flow_style=False,
              sort_keys=False, width=120),
    encoding="utf-8",
)

lines = OUT.read_text(encoding="utf-8").count("\n")
print(f"Exported {len(records)} patterns → {OUT}  ({lines} lines)")
