"""Command line for sigdiff.

  compile            validate + compile every rule, report per-rule status
  run                execute techniques live, capture telemetry, match rules,
                     write a run file (the baseline)
  verify             re-run techniques live against a recorded baseline and
                     fail on rule regressions (lost detections)
  replay             match rules against committed fixture windows (offline)
  publish-fixtures   write the raw windows from a run file into fixtures/
  ablate             two rule sets against the same events: gain/loss matrix
  rules              list the compiled rule set
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .ablate import ablate, format_matrix
from .replay import load_fixtures, replay
from .runner import (
    install_audit_rules,
    load_run,
    load_techniques,
    regressions,
    remove_audit_rules,
    run_all,
    save_run,
    sudo_password_from_env,
)
from .sigma import Rule, load_rules

ROOT = Path(__file__).resolve().parents[2]


def _rules(paths: list[str]) -> list[Rule]:
    out: list[Rule] = []
    for p in paths:
        out.extend(load_rules(Path(p)))
    return out


def cmd_compile(args: argparse.Namespace) -> int:
    rules = _rules(args.rules)
    ok = [r for r in rules if r.ok]
    bad = [r for r in rules if not r.ok]
    print(f"rules: {len(rules)} total · {len(ok)} compiled · {len(bad)} with errors")
    by_src: dict[str, int] = {}
    for r in ok:
        by_src[r.source or "?"] = by_src.get(r.source or "?", 0) + 1
    for src, n in sorted(by_src.items()):
        print(f"  source {src}: {n}")
    for r in bad:
        print(f"  ERROR {Path(r.path).name}: {r.error}")
    stems = [Path(r.path).stem for r in ok]
    dups = sorted({s for s in stems if stems.count(s) > 1})
    if dups:
        print(f"  ERROR duplicate rule keys: {', '.join(dups)}")
    return 0 if not bad and not dups else 1


def cmd_run(args: argparse.Namespace) -> int:
    rules = _rules(args.rules)
    techniques = load_techniques(Path(args.techniques))
    pw = sudo_password_from_env()
    if args.audit_rules:
        install_audit_rules(Path(args.audit_rules), pw)
    print(f"run: {len(techniques)} techniques x {sum(1 for r in rules if r.ok)} rules")
    results = run_all(techniques, rules, sudo_pw=pw)
    out = Path(args.out)
    save_run(out, results)
    if args.audit_rules:
        remove_audit_rules(pw)
    print(f"run saved: {out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    base = load_run(Path(args.baseline))
    rules = _rules(args.rules)
    techniques = load_techniques(Path(args.techniques))
    pw = sudo_password_from_env()
    if args.audit_rules:
        install_audit_rules(Path(args.audit_rules), pw)
    fresh = run_all(techniques, rules, sudo_pw=pw, quiet=True)
    if args.audit_rules:
        remove_audit_rules(pw)
    if base["meta"].get("rules_hash") != fresh["meta"].get("rules_hash"):
        print("rules changed since the baseline was recorded (rules_hash differs): "
              "this run is itself the regression demo if rules were removed on purpose")
    reg = regressions(base, fresh)
    total_lost = sum(len(v) for v in reg["lost"].values())
    for tid, lost in reg["lost"].items():
        for rule in lost:
            print(f"REGRESSION: technique {tid} lost the detection {rule}")
    for tid, gained in reg["gained"].items():
        for rule in gained:
            print(f"NEW HIT: technique {tid} now also matches {rule}")
    for tid in reg["telemetry_drift"]:
        print(f"TELEMETRY DRIFT: technique {tid}: normalized events changed but detections held")
    for tid in reg["missing_tech"]:
        print(f"MISSING: technique {tid} absent from the fresh run")
    print(f"\nverdict: {total_lost} lost detection(s), "
          f"{sum(len(v) for v in reg['gained'].values())} new hit(s), "
          f"{len(reg['telemetry_drift'])} telemetry drift(s)")
    return 1 if total_lost or reg["missing_tech"] else 0


def cmd_replay(args: argparse.Namespace) -> int:
    fixtures = load_fixtures(Path(args.fixtures))
    rules = _rules(args.rules)
    techniques = load_techniques(Path(args.techniques))
    res = replay(fixtures, rules, techniques)
    fired = sum(1 for r in res["rules"] if r["status"] == "FIRED")
    [r["rule"] for r in res["rules"] if r["status"] == "MISSED"]
    [r["rule"] for r in res["rules"] if r["status"] == "COMPILE-ERROR"]
    print(f"fixtures: {len(fixtures)} windows · rules: {len(rules)} · fired: {fired} · "
          f"never-fired: {sum(1 for r in res['rules'] if r['status'] == 'NO-HIT')}")
    for row in res["rules"]:
        if row["status"] in ("MISSED", "COMPILE-ERROR"):
            print(f"  {row['status']}: {row['rule']} {row['error']}")
    for tid, v in res["techniques"].items():
        if v["missed_expectations"] or v["forbidden_fired"]:
            print(f"  TECHNIQUE {tid}: missed={v['missed_expectations']} "
                  f"forbidden={v['forbidden_fired']}")
    return 0 if res["ok"] else 1


def cmd_publish_fixtures(args: argparse.Namespace) -> int:
    run = load_run(Path(args.run))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for tid, t in run["techniques"].items():
        (out / f"{tid}.audit.log").write_text(t["raw_audit"], encoding="utf-8")
        (out / f"{tid}.journal.jsonl").write_text("\n".join(t["raw_journal"]) + "\n", encoding="utf-8")
    print(f"fixtures written: {len(run['techniques'])} windows -> {out}")
    return 0


def cmd_ablate(args: argparse.Namespace) -> int:
    fixtures = load_fixtures(Path(args.fixtures))
    a = _rules(args.rules_a)
    b = _rules(args.rules_b)
    res = ablate(fixtures, a, b)
    print(format_matrix(res))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for r in sorted(_rules(args.rules), key=lambda r: Path(r.path).stem):
        state = "ok" if r.ok else "ERR"
        print(f"{state:<4} {Path(r.path).stem:<44} {(r.source or '-'):<8} {r.level}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigdiff",
                                description="detection-as-code: Sigma rules, executed techniques, hashed telemetry baselines")
    p.add_argument("--version", action="version", version=f"sigdiff {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("compile", help="validate and compile rules")
    c.add_argument("--rules", nargs="+", default=[str(ROOT / "rules")])
    c.set_defaults(func=cmd_compile)

    r = sub.add_parser("run", help="run techniques live and capture their telemetry")
    r.add_argument("--rules", nargs="+", default=[str(ROOT / "rules")])
    r.add_argument("--techniques", default=str(ROOT / "techniques" / "techniques.yml"))
    r.add_argument("--audit-rules", default=str(ROOT / "audit" / "rules.list"))
    r.add_argument("--out", default="run.yaml")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="re-run techniques and fail on lost detections")
    v.add_argument("--baseline", required=True)
    v.add_argument("--rules", nargs="+", default=[str(ROOT / "rules")])
    v.add_argument("--techniques", default=str(ROOT / "techniques" / "techniques.yml"))
    v.add_argument("--audit-rules", default=str(ROOT / "audit" / "rules.list"))
    v.set_defaults(func=cmd_verify)

    rp = sub.add_parser("replay", help="match rules against fixture windows (offline)")
    rp.add_argument("--fixtures", default=str(ROOT / "fixtures"))
    rp.add_argument("--rules", nargs="+", default=[str(ROOT / "rules")])
    rp.add_argument("--techniques", default=str(ROOT / "techniques" / "techniques.yml"))
    rp.set_defaults(func=cmd_replay)

    pf = sub.add_parser("publish-fixtures", help="write run windows into a fixtures directory")
    pf.add_argument("--run", required=True)
    pf.add_argument("--out", default=str(ROOT / "fixtures"))
    pf.set_defaults(func=cmd_publish_fixtures)

    ab = sub.add_parser("ablate", help="two rule sets against the same events: gain/loss matrix")
    ab.add_argument("--fixtures", default=str(ROOT / "fixtures"))
    ab.add_argument("--rules-a", nargs="+", default=[str(ROOT / "rules")])
    ab.add_argument("--rules-b", nargs="+", default=[str(ROOT / "rules-b")])
    ab.set_defaults(func=cmd_ablate)

    rl = sub.add_parser("rules", help="list rules and their compile status")
    rl.add_argument("--rules", nargs="+", default=[str(ROOT / "rules")])
    rl.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
