# sigdiff — project state (queue item #3 of CYBER-PROJECTS-PLAN.md)

Owner: Hadi Abdulrahman (mandoof1). Status: **built + live DoD evidence
captured on this host; repo push pending.**

## What exists and was actually run on this host (2026-11-14)

- `sigdiff compile`: 58 rules (50 auditd / 6 auth / 2 journald), 0 errors.
- `sigdiff run` (live, sudo): 34 techniques (33 attack + 1 control) executed
  under auditd collection; every window captured; run.yaml written with a
  SHA-256 event-set hash per technique; `auditctl -s` shows `lost 0`.
- `sigdiff publish-fixtures`: 34 raw windows committed under `fixtures/`
  (1.8 MB of exact auditd log bytes + journalctl -o json lines).
- `sigdiff replay`: `34 windows · 58 rules · fired: 58 · never-fired: 0`,
  exit 0 — every rule fires against real recorded telemetry, every technique
  passes its expect-hits AND its forbid-hits (control-benign fires exactly
  1 rule, 0 of its 24 forbidden).
- Regression demo (live): `verify --baseline run.yaml` on the same rules →
  exit 0, `0 lost detection(s) … 34 telemetry drift(s)` (drift = honest
  desktop noise, documented in README). With two rules removed from a copy
  of the corpus → exit 1 naming exactly `lab-log-deleted` and
  `setuid-bit-granted` as losses. Output reproduced in README.
- Ablation (offline): A vs B vs none matrix over all 34 windows; B loses 3
  targeted detections, gains 2 broad-rule noise hits; committed at
  docs/tables/ablation.md.
- `pytest tests/ -q`: 28 tests green without root (parser, compiler,
  mapping, capture boundary, hashing/verify semantics, replay, ablation,
  auditd-rotation splice incl. the two-rotations-in-one-window case).
- `ruff check src tests tools`: clean.

## Host facts the corpus depends on (the pairing is explicit, not hidden)

- Arch, kernel 7.3.3-1-cachyos, audit userspace 4.2.1 (journald logged
  "Init complete, auditd 4.2.1"), python 3.14.
- auditd is disabled by default here and a KDE session stop can stop the
  service (observed live at 20:12 during a Plasma logout); the installer
  starts it (`systemctl is-active || start`) — that was found by an all-zero
- event run after a host reboot, not assumed.
- `auditctl -R` rejects old-style `-w` rules on this box (`Old style watch
  rules slower` + non-zero exit) → modern `-a exit,always -F dir=… perm=wa`
  syntax throughout. `-F auid==1000` also fails; `-F auid=1000` works.
- /etc/cron.d and /etc/ld.so.preload do not exist on this host → the
  installer creates them (watched paths must exist for auditd).
- auditd rotates audit.log at 8 MB mid-run: `capture.read_audit_since`
  splices `.1`/`.2` files and the runner re-applies its ACL on EACCES.
- journald can hold a just-written logger line in the /dev/log queue longer
  than a later one (one technique lost exactly one auth line in one run);
  the runner logs a flush barrier after each technique and waits for it
  before reading the window.
- journald also silently DROPS a logger DGRAM under load: under a pty
  harness (vhs) each live run lost exactly one forged auth line, in a
  different window each time, although its connect() succeeded (verified
  against the audit EXECVE/connect records and journalctl searches). The
  runner now re-runs the three idempotent `logger`-forge techniques once
  when their expect-hits are missing from the captured window
  (techniques.yml: `allow_replay: true`, baseline records `attempts`).

## Next commands (in order)

1. `make assets` (vhs/asciinema/ffmpeg — tables already generated)
2. `git init -b main && git add -A && git commit`
3. `gh repo create sigdiff --public --source . --push`, add topics
   (security, blue-team), `gh run list` until CI green
4. fresh-clone smoke: `git clone` to /tmp, `pip install -e .`,
   `sigdiff compile && sigdiff replay` (offline, must be exit 0)
5. tick §3 of ~/CYBER-PROJECTS-PLAN.md row 3 and ~/projects/PROGRESS.md

## Notes for the owner

- `run.yaml` (the live baseline, ~2 MB) is git-ignored; `fixtures/` are the
  committed, replayable equivalent. To regenerate the live baseline:
  `make live PW=<sudo pw>`.
- Nothing outside `~/projects/sigdiff` was created by this project except
  the lab paths the tool itself manages (/tmp/sigdiff-lab,
  /var/log/sigdiff-lab, the audit.log ACL, auditd service state).
