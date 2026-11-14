"""A/B ablation: same events, two rule sets (or none) — which detections does
each set gain, and which does it lose? The matrix is the artifact; the diff
line says exactly which rule entered or left which technique.
"""

from __future__ import annotations

from typing import Any

from .replay import Fixture
from .runner import match_rules
from .sigma import Rule


def ablate(fixtures: list[Fixture], rules_a: list[Rule], rules_b: list[Rule]) -> dict[str, Any]:
    rows: dict[str, dict[str, Any]] = {}
    for fx in fixtures:
        ha = set(match_rules(rules_a, fx.events))
        hb = set(match_rules(rules_b, fx.events))
        rows[fx.id] = {
            "a": sorted(ha),
            "b": sorted(hb),
            "none": [],  # no rules => no detections, by definition; shown for the baseline row
            "only_a": sorted(ha - hb),
            "only_b": sorted(hb - ha),
        }
    gained = sorted({r for v in rows.values() for r in v["only_b"]})
    lost = sorted({r for v in rows.values() for r in v["only_a"]})
    return {"matrix": rows, "rules_b_gains": gained, "rules_b_loses": lost}


def format_matrix(ab: dict[str, Any]) -> str:
    lines = ["| technique | no rules | rules A | rules B | A-only | B-only |",
             "|---|---|---|---|---|---|"]
    for tid, row in ab["matrix"].items():
        lines.append(
            f"| {tid} | 0 | {len(row['a'])} | {len(row['b'])} | "
            f"{len(row['only_a'])} | {len(row['only_b'])} |"
        )
    lines.append("")
    lines.append(f"rule set B gains {len(ab['rules_b_gains'])} detection(s): "
                 + (", ".join(ab["rules_b_gains"]) or "none"))
    lines.append(f"rule set B loses {len(ab['rules_b_loses'])} detection(s): "
                 + (", ".join(ab["rules_b_loses"]) or "none"))
    for tid, row in ab["matrix"].items():
        if row["only_a"] or row["only_b"]:
            lines.append(f"  {tid}: only-A [{', '.join(row['only_a'])}] only-B [{', '.join(row['only_b'])}]")
    return "\n".join(lines)
