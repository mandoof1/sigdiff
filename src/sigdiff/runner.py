"""The runner: execute a technique, capture its telemetry window, match rules.

Everything a technique touches lives under /tmp/sigdiff-lab (its cwd), and
everything it says carries the `sigdiff` marker or TEST-NET addresses — that
is the capture boundary (see capture.py). Results carry the matched rule set,
a hash of the normalized events, and the raw window text so the same events
can be replayed offline as fixtures forever after.
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import capture as capture_mod
from .capture import Capture
from .events import Event
from .sigma import Rule

WORKDIR = "/tmp/sigdiff-lab/work"


@dataclass
class Technique:
    id: str
    title: str
    mitre: list[str]
    command: str
    needs_root: bool = False
    expect_hits: list[str] = field(default_factory=list)
    forbid_hits: list[str] = field(default_factory=list)
    timeout: int = 60
    # Idempotent journal-only forges. journald drops a logger DGRAM under
    # load (observed under pty harnesses: one forged line vanishes per
    # ~full-run even though its connect() succeeded); re-running such a
    # technique re-forges the line honestly, and the retry is recorded.
    allow_replay: bool = False


def load_techniques(path: Path) -> list[Technique]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = []
    for item in doc["techniques"]:
        out.append(Technique(
            id=item["id"],
            title=item.get("title", item["id"]),
            mitre=list(item.get("mitre", [])),
            command=item["command"],
            needs_root=bool(item.get("needs_root", False)),
            expect_hits=list(item.get("expect_hits", [])),
            forbid_hits=list(item.get("forbid_hits", [])),
            allow_replay=bool(item.get("allow_replay", False)),
            timeout=int(item.get("timeout", 60)),
        ))
    return out


def sudo_wrap(command: str) -> str:
    return "sudo -S bash -c " + _shell_quote(command)


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run_command(tech: Technique, sudo_pw: str | None) -> tuple[int, str, float]:
    cmd = sudo_wrap(tech.command) if tech.needs_root else tech.command
    t0 = time.time()
    try:
        p = subprocess.run(
            ["bash", "-c", cmd],
            cwd=WORKDIR,
            capture_output=True,
            text=True,
            input=(sudo_pw + "\n") if (tech.needs_root and sudo_pw) else "",
            timeout=tech.timeout,
        )
        rc, err = p.returncode, (p.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        rc, err = 124, f"timeout after {tech.timeout}s"
    return rc, err, time.time() - t0


def ensure_audit_readable(sudo_pw: str | None) -> None:
    """give the (unprivileged) runner read access to the audit log; survives
    rotation because run_all re-applies it whenever a read comes back EACCES"""
    uid = os.environ.get("SUDO_UID", os.getuid())
    subprocess.run(["sudo", "-S", "bash", "-c",
                    f"setfacl -m u:{uid}:x /var/log/audit 2>/dev/null; "
                    f"setfacl -m u:{uid}:r /var/log/audit/audit.log 2>/dev/null"],
                   capture_output=True, input=(sudo_pw or "") + "\n",
                   text=True, timeout=30, check=False)


def install_audit_rules(rules_file: Path, sudo_pw: str | None) -> None:
    sudo = ["sudo", "-S", "auditctl"]
    # auditd path-watches require the target to exist; the ld.so.preload
    # technique deletes it, so the installer re-creates the sentinels.
    subprocess.run(["sudo", "-S", "bash", "-c",
                    "systemctl is-active --quiet auditd || systemctl start auditd; "
                    "sleep 0.5; "
                    "mkdir -p /var/log/sigdiff-lab /home/meowman/.ssh "
                    "/tmp/sigdiff-lab/work /etc/sudoers.d /etc/cron.d; "
                    f"chown {os.environ.get('SUDO_UID', os.getuid())} "
                    "/tmp/sigdiff-lab /tmp/sigdiff-lab/work; "
                    "touch /etc/ld.so.preload"],
                   capture_output=True, input=(sudo_pw or "") + "\n",
                   text=True, timeout=30, check=False)
    ensure_audit_readable(sudo_pw)
    # widen the kernel backlog so a busy desktop cannot drop lab events
    subprocess.run(sudo + ["-b", "8192"], capture_output=True, input=(sudo_pw or "") + "\n",
                   text=True, timeout=30, check=False)
    subprocess.run(sudo + ["-D"], capture_output=True, input=(sudo_pw or "") + "\n",
                   text=True, timeout=30, check=False)
    p = subprocess.run(sudo + ["-R", str(rules_file)], capture_output=True,
                       input=(sudo_pw or "") + "\n", text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(f"auditctl -R failed: {(p.stderr or p.stdout).strip()[:300]}")


def remove_audit_rules(sudo_pw: str | None) -> None:
    subprocess.run(["sudo", "-S", "auditctl", "-D"], capture_output=True,
                   input=(sudo_pw or "") + "\n", text=True, timeout=30, check=False)


def match_rules(rules: list[Rule], events: list[Event]) -> dict[str, int]:
    """rule key (file stem) -> number of matching events."""
    hits: dict[str, int] = {}
    by_source: dict[str, list[Rule]] = {}
    for r in rules:
        if r.ok:
            by_source.setdefault(r.source or "", []).append(r)
    for ev in events:
        for r in by_source.get(ev.source, ()):
            key = Path(r.path).stem
            try:
                if r.matcher(ev):  # type: ignore[misc]
                    hits[key] = hits.get(key, 0) + 1
            except Exception:
                hits[key + "!!match-error"] = hits.get(key + "!!match-error", 0) + 1
    return hits


def events_hash(events: list[Event]) -> str:
    """Hash of the normalized event SET (timestamps/pids excluded; identical
    events collapse). Repeated syscalls — a sudo doing 35 vs 38 socket
    connects — are benign drift and must not flip the baseline; what matters
    is that the same distinct normalized events are still there."""
    keys = sorted({ev.key() for ev in events})
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()


def run_all(techniques: list[Technique], rules: list[Rule], *, sudo_pw: str | None,
            quiet: bool = False) -> dict[str, Any]:
    cap = Capture(workdir=WORKDIR)
    Path(WORKDIR).mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {
        "meta": {
            "tool": "sigdiff/0.1.0",
            "host": socket.gethostname(),
            "kernel": platform.release(),
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "rules_hash": rules_hash(rules),
        },
        "techniques": {},
    }
    for tech in techniques:
        off = cap.audit_offset()
        journal: list[str] = []
        audit_text = ""
        attempts = 2 if tech.allow_replay else 1
        for attempt in range(1, attempts + 1):
            if attempt > 1:
                time.sleep(1.0)
            t0 = time.time()
            rc, err, dur = run_command(tech, sudo_pw)
            time.sleep(0.4)  # auditd flushes the window
            # journald barrier: this line is logged after everything the
            # technique logged, and we wait until it is visible before
            # reading the window
            subprocess.run(["logger", "-t", "sigdiff", capture_mod.JOURNAL_BARRIER],
                           check=False, timeout=10)
            capture_mod.journal_barrier_appeared(t0)
            try:
                audit_text = cap.read_audit_since(off)
            except PermissionError:
                # auditd rotated the log mid-technique; the fresh file lost
                # the lab ACL — re-apply it and retry once
                ensure_audit_readable(sudo_pw)
                audit_text = cap.read_audit_since(off)
            # since = exactly t0: techniques run back-to-back and a backward
            # buffer would bleed the previous technique's logger lines into
            # this window; the host clock is the same for both, so no slack
            # is needed. On a replay attempt the audit window still starts at
            # the original offset, so both attempts' syscalls are captured.
            window = cap.journald_window(t0, time.time() + 0.5)
            journal = list(dict.fromkeys([*journal, *window]))
            events = _capture(cap, audit_text, journal)
            hits = match_rules(rules, events)
            if not set(tech.expect_hits) - set(hits) or attempt == attempts:
                break
        results["techniques"][tech.id] = {
            "attempts": attempt,
            "title": tech.title,
            "mitre": tech.mitre,
            "rc": rc,
            "stderr": err,
            "seconds": round(dur, 2),
            "events_hash": events_hash(events),
            "event_count": len(events),
            "hits": sorted(hits),
            "hit_counts": hits,
            "expect_hits": tech.expect_hits,
            "forbid_hits": tech.forbid_hits,
            "raw_audit": audit_text,
            "raw_journal": [ln for ln in journal],
        }
        if not quiet:
            suffix = "  (re-forged once: journald dropped a line)" if attempt > 1 else ""
            print(f"  {tech.id:<34} rc={rc} events={len(events):<4} hits={len(hits)}{suffix}")
    return results


def _capture(cap: Capture, audit_text: str, journal: list[str]) -> list[Event]:
    from .capture import capture_events

    return capture_events(audit_text, journal)


def rules_hash(rules: list[Rule]) -> str:
    parts = []
    for r in sorted(rules, key=lambda r: r.path):
        try:
            parts.append(Path(r.path).stem + ":" + hashlib.sha256(
                Path(r.path).read_bytes()).hexdigest()[:16])
        except OSError:
            parts.append(r.path + ":unreadable")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def regressions(baseline: dict, fresh: dict) -> dict[str, Any]:
    """Compare a fresh run against the recorded baseline.

    Rule regressions (lost hits) are the hard failure: a rule, a mapping or a
    rule-set change removed a detection that used to fire. Telemetry drift
    (the events themselves changed while the hits stayed) means the host
    changed underneath the rules — reported separately, never as a detection
    win or loss.
    """
    out: dict[str, Any] = {"lost": {}, "gained": {}, "telemetry_drift": [], "missing_tech": []}
    base_t = baseline.get("techniques", {})
    for tid, b in base_t.items():
        f = fresh.get("techniques", {}).get(tid)
        if f is None:
            out["missing_tech"].append(tid)
            continue
        lost = sorted(set(b["hits"]) - set(f["hits"]))
        gained = sorted(set(f["hits"]) - set(b["hits"]))
        if lost:
            out["lost"][tid] = lost
        if gained:
            out["gained"][tid] = gained
        if b["events_hash"] != f["events_hash"] and not lost and not gained:
            out["telemetry_drift"].append(tid)
    return out


def save_run(path: Path, results: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(results, sort_keys=True), encoding="utf-8")


def load_run(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def sudo_password_from_env() -> str | None:
    return os.environ.get("SIGDIFF_SUDO_PW")
