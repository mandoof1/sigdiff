"""Live capture windows: auditd by file offset, journald by time window.

auditd capture is offset-based: take the byte offset of /var/log/audit/audit.log
before the technique runs, read exactly what appeared after it. Deterministic,
no clock alignment tricks needed.

journald capture is window-based (`journalctl --since`), then filtered: the
lab's own units, users and source IPs all carry the `sigdiff` marker or the
TEST-NET range 203.0.113.0/24, so unrelated desktop traffic (a browser doing
its thing) never enters the baseline. That filter is not cheating — it is the
documented lab boundary.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .events import AuditLogParser, Event, journald_events

JOURNAL_BARRIER = "sigdiff-flush-barrier"


def journal_barrier_appeared(since: float, timeout: float = 4.0) -> bool:
    """A logger line written AFTER the technique ran must be visible before
    the window is read: journald's /dev/log queue can hold earlier lines
    slightly longer than later ones under load, and missing one makes a
    window non-reproducible. The barrier is logged after every technique's
    own output, so once the barrier is visible the earlier lines are too."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = subprocess.run(
            ["journalctl", "-q", "--no-pager", "-g", JOURNAL_BARRIER,
             "--since", f"@{since:.2f}"], capture_output=True, text=True, timeout=15)
        if p.stdout.strip():
            time.sleep(0.15)  # let same-window neighbours settle
            return True
        time.sleep(0.2)
    return False


AUDIT_LOG = "/var/log/audit/audit.log"
MARKER = "sigdiff"
TESTNET = "203.0.113."
LAB_UID = "1000"


@dataclass
class Capture:
    workdir: str  # techniques run with this as cwd; auditd events outside it are lab noise
    journal_since: float = 0.0

    def audit_offset(self) -> tuple[int, int]:
        """(inode, size): the byte offset alone goes stale across auditd's
        rotation — with num_logs files kept, two rotations in one window can
        make the old offset land in the middle of the wrong rotated file."""
        try:
            st = Path(AUDIT_LOG).stat()
            return (st.st_ino, st.st_size)
        except PermissionError as exc:
            raise RuntimeError(
                f"cannot stat {AUDIT_LOG}: run the live phase as root (sudo) or replay fixtures"
            ) from exc

    def read_audit_since(self, offset: tuple[int, int]) -> str:
        """Read the bytes appended since the (inode, size) anchor. auditd
        rotates audit.log (8 MB) by rename, so the anchor file keeps its
        inode and simply becomes audit.log.N. Walk the rotation chain in
        chronological order (oldest surviving rotation ... current file);
        seek to the anchor offset *in the anchor's file* and read everything
        after it. If the anchor has already aged out of num_logs, take every
        surviving file whole — honestly over-inclusive (older desktop noise),
        and the lab/uid boundary filter removes it."""
        anchor_ino, anchor_off = offset
        cur = Path(AUDIT_LOG)
        chain = [Path(f"{AUDIT_LOG}.{n}") for n in range(9, 0, -1)
                 if Path(f"{AUDIT_LOG}.{n}").exists()]
        chain.append(cur)
        anchor_pos = next(
            (i for i, p in enumerate(chain) if p.exists() and p.stat().st_ino == anchor_ino),
            None)
        if anchor_pos is None:
            anchor_off, anchor_pos = 0, 0  # rotated away: everything that survives
        data = ""
        for i, p in enumerate(chain):
            if i < anchor_pos:  # older than the anchor: not part of the window
                continue
            try:
                with open(p, "rb") as fh:
                    fh.seek(anchor_off if i == anchor_pos else 0)
                    data += fh.read().decode("utf-8", "replace")
            except OSError:
                continue
        return data

    def journald_window(self, since: float, until: float | None = None) -> list[str]:
        # flush journald's in-memory queue first: a kernel-message burst can
        # keep a just-written logger entry out of the readable store, and
        # missing that entry makes a window non-deterministic
        subprocess.run(["journalctl", "-q", "--flush"], capture_output=True,
                       timeout=10, check=False)
        cmd = ["journalctl", "-q", "--no-pager", "-o", "json", "--since", f"@{since:.2f}"]
        if until:
            cmd += ["--until", f"@{until:.2f}"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            raise RuntimeError(f"journalctl failed: {out.stderr.strip()[:200]}")
        return [ln for ln in out.stdout.splitlines() if ln.strip()]


def keep_event(ev: Event) -> bool:
    """The lab boundary: what belongs to a technique run."""
    if ev.source == "auditd":
        if ev.fields.get("syscall") in ("audit_config", "user_cmd"):
            # audit tampering and user commands carry no cwd record; auid tells us
            # who ran them — keep only this lab user's, they are rare by nature
            return ev.fields.get("auid") == LAB_UID
        if not ev.fields.get("cwd"):
            # connect records carry no cwd either; the collection rule already
            # scoped them to auid=1000, so login identity is the boundary
            return ev.fields.get("auid") == LAB_UID
        return ev.fields["cwd"].startswith("/tmp/sigdiff-lab")
    # auth + journald: lab marker (or TEST-NET client) anywhere in the line
    text = ev.raw + " " + " ".join(str(v) for v in ev.fields.values())
    return MARKER in text or TESTNET in text


def capture_events(audit_text: str, journal_lines: list[str]) -> list[Event]:
    evs: list[Event] = []
    evs += [e for e in AuditLogParser().parse_stream(audit_text.splitlines()) if keep_event(e)]
    evs += [e for e in journald_events(journal_lines) if keep_event(e)]
    return evs
