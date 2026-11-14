# External sources

Everything in this repo is self-generated on this host — there are no
downloaded datasets, corpora, or binaries. What the corpus borrows from
others is vocabulary and technique semantics, credited here:

| What | Source | License / terms | Used for |
|---|---|---|---|
| Rule format (logsource/detection/condition grammar subset) | Sigma project spec (`github.com/SigmaHQ/sigma`) | Apache-2.0 (the spec, no rule files copied) | `rules/` are original rules written in that format |
| Technique IDs like `T1059.004` in tags and `techniques/techniques.yml` | MITRE ATT&CK® | ATT&CK Terms of Use (ID references only) | tagging techniques the rules map to |
| auditd rule syntax (`-a exit,always -F …`) | Linux audit userspace man pages (`man 8 auditctl`) | man pages (docs) | `audit/rules.list` |
| `journalctl -o json` record fields (`MESSAGE`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`) | systemd documentation | LGPL docs (field names only) | journald field mapping |
| audit log record types (`SYSCALL`, `EXECVE`, `PATH`, `SOCKADDR`, `CONFIG_CHANGE`) | kernel audit ABI (observed directly on this host) | n/a (observed wire format) | parser in `src/sigdiff/events.py` |

## Recorded artifacts

- `fixtures/*.audit.log` — raw `/var/log/audit/audit.log` windows captured on
  the build host (Arch, kernel 7.3.3-1-cachyos, audit userspace 3.1.2) by
  `sigdiff run` on 2026-11-14; these are the repo's own output, MIT-licensed.
- `fixtures/*.journal.jsonl` — raw `journalctl -o json` lines from the same
  windows.
- `tests/fixture_windows/*` — hand-written windows (same record wire format,
  verified against live output) for unit tests; also own output.
- sshd/sudo/pam auth lines: the live host logs them to journald; the lab also
  forges deterministic TEST-NET lines via `logger` (documented in techniques).

No file in this repo was downloaded from anyone else.
