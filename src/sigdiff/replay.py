"""Replay: the recorded technique windows, back through the same parsers and
the same rules, offline and forever. CI runs this; it never needs the host's
live telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capture import capture_events
from .events import Event
from .runner import Technique, match_rules
from .sigma import Rule


@dataclass
class Fixture:
    id: str
    events: list[Event]


def load_fixtures(fixtures_dir: Path) -> list[Fixture]:
    out: list[Fixture] = []
    for audit in sorted(fixtures_dir.glob("*.audit.log")):
        tid = audit.name[: -len(".audit.log")]
        jn = fixtures_dir / (tid + ".journal.jsonl")
        journal = jn.read_text(encoding="utf-8").splitlines() if jn.exists() else []
        events = capture_events(audit.read_text(encoding="utf-8"), journal)
        out.append(Fixture(tid, events))
    return out


def replay(fixtures: list[Fixture], rules: list[Rule], techniques: list[Technique]) -> dict[str, Any]:
    """Per-rule verdicts and per-technique expectation checks."""
    expect_all: set[str] = set()
    for t in techniques:
        expect_all.update(t.expect_hits)

    per_rule: dict[str, int] = {}
    per_tech: dict[str, dict[str, Any]] = {}
    for fx in fixtures:
        hits = match_rules(rules, fx.events)
        for k, n in hits.items():
            per_rule[k] = per_rule.get(k, 0) + n
        tech = next((t for t in techniques if t.id == fx.id), None)
        missed = sorted(set(tech.expect_hits) - set(hits)) if tech else []
        fired_forbidden = sorted(set(tech.forbid_hits) & set(hits)) if tech else []
        per_tech[fx.id] = {
            "events": len(fx.events),
            "hits": sorted(hits),
            "missed_expectations": missed,
            "forbidden_fired": fired_forbidden,
        }

    rule_rows = []
    for r in sorted(rules, key=lambda r: Path(r.path).stem):
        stem = Path(r.path).stem
        n = per_rule.get(stem, 0)
        if not r.ok:
            status = "COMPILE-ERROR"
        elif n > 0:
            status = "FIRED"
        elif stem in expect_all:
            status = "MISSED"
        else:
            status = "NO-HIT"
        rule_rows.append({"rule": stem, "source": r.source or "-", "level": r.level,
                          "hits": n, "status": status, "error": r.error or ""})
    ok = all(not v["missed_expectations"] and not v["forbidden_fired"] for v in per_tech.values())
    ok = ok and not any(r["status"] in ("COMPILE-ERROR", "MISSED") for r in rule_rows)
    return {"rules": rule_rows, "techniques": per_tech, "ok": ok}
