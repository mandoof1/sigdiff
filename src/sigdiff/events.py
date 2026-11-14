"""The canonical event model plus the parsers that fill it.

Three sources, one shape:
  auditd  — raw /var/log/audit/audit.log groups (SYSCALL/EXECVE/PATH/FILE/
            PROCTITLE/SOCKET* records joined by their audit id)
  journald — `journalctl -o json` objects
  auth    — sshd/sudo/pam lines (from journald MESSAGE or an auth.log text file)

Normalization is deliberate: volatile fields (pids, serial ids, timestamps,
inodes) are parsed but stripped from the *normalized* dict, because the whole
point of this tool is hashing telemetry and re-comparing it. Two runs of the
same technique must produce the same normalized events; the raw text is kept
for the evidence view only.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

# x86_64 syscall numbers we care about, enough to name the interesting ones
SYSCALL_NAMES = {
    59: "execve",
    322: "execveat",
    2: "open",
    257: "openat",
    85: "creat",
    267: "mkdir",
    87: "unlink",
    82: "rename",
    264: "renameat",
    263: "unlinkat",
    92: "write",
    42: "connect",
    43: "accept",
    41: "socket",
    49: "bind",
    50: "listen",
    165: "getmount",  # not used; placeholder never referenced
}
# close_range(436)/close(3): CLOSE_WRITE events are emitted by the kernel on close
WRITE_CLOSE = "close_write"

AUDIT_LINE = re.compile(r"^type=(\w+) msg=audit\((\d+)(?:\.(\d+))?:(\d+)\): (.*)$")
KV = re.compile(r"(\w+)=(\"(?:[^\"\\]|\\.)*\"|[^\s]+)")


@dataclass
class Event:
    """One normalized telemetry event.

    `fields` is the deterministic, volatile-free projection rules match on.
    `raw` is the original text for evidence output only.
    """

    source: str
    ts: float
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def key(self) -> str:
        return self.source + "|" + "|".join(f"{k}={self.fields[k]}" for k in sorted(self.fields))


def absolutize(cwd: str, name: str) -> str:
    """auditd records PATH relative to the process cwd when the syscalls used
    relative paths; field-map consumers expect absolute paths everywhere."""
    if not name or name.startswith("/") or not cwd:
        return name
    return posixpath.normpath(posixpath.join(cwd, name))


def parse_saddr(hexstr: str) -> tuple[str, str]:
    """Decode an audit sockaddr record: AF_INET -> (ip, port); AF_INET6 too;
    unix/abstract sockets have no ip."""
    h = hexstr.strip()
    if len(h) >= 16 and h[:4] in ("0200", "0002"):
        port = int(h[4:8], 16)
        ip = ".".join(str(b) for b in bytes.fromhex(h[8:16]))
        return ip, str(port)
    if len(h) >= 48 and h[:4] in ("0a00", "000a"):
        # struct sockaddr_in6: family(2B) port(2B) flowinfo(4B) address(16B) scope(4B)
        port = int(h[4:8], 16)
        raw = bytes.fromhex(h[16:48])
        ip = ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
        return ip, str(port)
    return "", ""


def unhex(v: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) >= 8 and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except Exception:
            return v
    return v


def parse_kv(rest: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in KV.findall(rest):
        v = v.strip('"').replace('\\"', '"')
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------

class AuditLogParser:
    """Join audit records into events by audit serial id, then normalize.

    Yields one Event per interesting syscall: execve, file opens with a path,
    renames/unlinks, and socket connects. CONFIG_CHANGE and USER_CMD also
    become events because rules watch them.
    """

    def parse_stream(self, lines: Iterable[str]) -> Iterator[Event]:
        groups: dict[int, dict[str, Any]] = {}
        order: list[int] = []
        for line in lines:
            m = AUDIT_LINE.match(line.strip())
            if not m:
                continue
            rtype, sec, milli, serial, rest = m.groups()
            sid = int(serial)
            if order and sid + 32 < order[-1]:
                # audit serials restart at every boot: a decreasing id means a
                # new boot range — flush what we have before ids collide
                for done in order:
                    yield from self._event(groups.pop(done))
                order.clear()
                groups.clear()
            g = groups.get(sid)
            if g is None:
                g = {"ts": int(sec) + (int(milli) / 1000 if milli else 0.0), "recs": [], "line": []}
                groups[sid] = g
                order.append(sid)
            g["recs"].append((rtype, parse_kv(rest)))
            g["line"].append(line.rstrip("\n"))
        for sid in order:
            yield from self._event(groups[sid])

    def _event(self, g: dict[str, Any]) -> Iterator[Event]:
        recs = g["recs"]
        syscall = next((kv for rt, kv in recs if rt == "SYSCALL"), None)
        types = {rt for rt, _ in recs}
        raw = "\n".join(g["line"])
        cwd = ""
        for rt, kv in recs:
            if rt == "CWD":
                cwd = unhex(kv.get("cwd", ""))
        if syscall is not None:
            num = int(syscall.get("syscall", "-1"))
            name = SYSCALL_NAMES.get(num, str(num))
            common = {
                "syscall": name,
                "auid": syscall.get("auid", "-1"),
                "key": syscall.get("key", ""),
                "cwd": cwd,
            }
            if "CONFIG_CHANGE" in types:
                # audit rule changes arrive joined to their SYSCALL record;
                # the interesting payload is the CONFIG_CHANGE record itself
                kv = next(kv for rt, kv in recs if rt == "CONFIG_CHANGE")
                yield Event("auditd", g["ts"], {
                    "syscall": "audit_config",
                    "op": kv.get("op", ""),
                    "key": kv.get("key", ""),
                    "auid": syscall.get("auid", kv.get("auid", "-1")),
                    "res": kv.get("res", ""),
                }, raw)
                return
            exe = self._execve_target(recs)
            cmdline = self._cmdline(recs)
            paths = [kv for rt, kv in recs if rt in ("PATH", "FILE")]
            if name in ("execve", "execveat"):
                yield Event("auditd", g["ts"], {**common, "exe": exe, "cmdline": cmdline}, raw)
            elif name in ("open", "openat", "creat", "openat2"):
                for p in paths:
                    if p.get("name"):
                        fmode = p.get("mode", "")
                        yield Event(
                            "auditd", g["ts"],
                            {**common, "path": absolutize(cwd, p["name"]),
                             "mode": fmode[:4] if fmode else ""},
                            raw,
                        )
            elif name in ("rename", "renameat", "renameat2"):
                names = [absolutize(cwd, p.get("name", "")) for p in paths if p.get("name")]
                if len(names) >= 2:
                    yield Event("auditd", g["ts"], {**common, "path": names[0], "to": names[1]}, raw)
                elif names:
                    yield Event("auditd", g["ts"], {**common, "path": names[0]}, raw)
            elif name in ("unlink", "unlinkat"):
                for p in paths:
                    if p.get("name"):
                        yield Event("auditd", g["ts"], {**common, "path": absolutize(cwd, p["name"])}, raw)
            elif name == "connect":
                ip, port = "", ""
                for rt, kv in recs:
                    if rt in ("SOCKADDR", "SOCKETCONNECT"):
                        ip, port = parse_saddr(kv.get("saddr", ""))
                        break
                yield Event("auditd", g["ts"], {**common, "dest_ip": ip, "dest_port": port}, raw)
        elif "CONFIG_CHANGE" in types:
            kv = next(kv for rt, kv in recs if rt == "CONFIG_CHANGE")
            yield Event("auditd", g["ts"], {
                "syscall": "audit_config",
                "op": kv.get("op", ""),
                "key": kv.get("key", ""),
                "auid": kv.get("auid", "-1"),
                "res": kv.get("res", ""),
            }, raw)
        elif "USER_CMD" in types or "CMD" in types:
            kv = next(kv for rt, kv in recs if rt in ("USER_CMD", "CMD"))
            yield Event("auditd", g["ts"], {
                "syscall": "user_cmd",
                "cmd": unhex(kv.get("cmd", "")),
                "auid": kv.get("auid", "-1"),
            }, raw)

    @staticmethod
    def _execve_target(recs: list[tuple[str, dict[str, str]]]) -> str:
        # the executable is the PATH record with item=0 (the final resolved name);
        # ld.so shows up as a higher item index
        paths = [(int(kv.get("item", "9")), kv.get("name", "")) for rt, kv in recs if rt == "PATH"]
        paths = [(i, n) for i, n in paths if n]
        if not paths:
            return ""
        return min(paths)[1]

    @staticmethod
    def _cmdline(recs: list[tuple[str, dict[str, str]]]) -> str:
        for rt, kv in recs:
            if rt == "EXECVE":
                args = [unhex(kv[k]) for k in sorted(kv, key=lambda x: int(x[1:]) if x[1:].isdigit() else 0)
                        if k.startswith("a") and k[1:].isdigit()]
                if args:
                    return " ".join(args)
        for rt, kv in recs:
            if rt == "PROCTITLE":
                t = unhex(kv.get("proctitle", ""))
                return "\0".join(t.split("\0")) if t else ""
        return ""




# ---------------------------------------------------------------------------
# journald + auth
# ---------------------------------------------------------------------------

JOURNAL_FIELDS = (
    "MESSAGE", "SYSLOG_IDENTIFIER", "PRIORITY", "_COMM", "_SYSTEMD_UNIT", "_PID",
    "_UID", "_GID", "_HOSTNAME", "_EXE", "_CMDLINE", "PAM_MESSAGE", "ERRNO",
    "UNIT",
)

SSH_ACCEPTED = re.compile(r"Accepted (password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?([\w.@-]+) from ([\w:.]+) port (\d+)")
SSH_FAILED = re.compile(r"(Failed|Connection (?:reset|closed) by (?:invalid user )?) (?:password|publickey|authentication) for (?:invalid user )?([\w.@-]+) from ([\w:.]+) port (\d+)")
SSH_BANNER = re.compile(r"Connection (accepted|closed|reset) from ([\w:.]+) port (\d+)")
SSH_SESSION = re.compile(r"(session (?:opened|closed)|Removed session) (?:for|by|user)? ?([\w.@-]+)?")
SUDO_LINE = re.compile(
    r"([\w.@-]+) : (?:TTY=([^\s;]*) ; )?PWD=([^\s;]*) ; USER=(\w+) ; COMMAND=(.*)$")
SUDO_AUTHFAIL = re.compile(r"3 incorrect password attempt|incorrect password attempt|authentication is required")
PAM_FAIL = re.compile(r"module .* authentication failure|PAM: Authentication failure")


def journald_events(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        ts_us = obj.get("__REALTIME_TIMESTAMP", obj.get("TS_US", "0"))
        ts = int(ts_us) / 1_000_000.0
        fields = {k.lower(): v for k, v in obj.items() if k in JOURNAL_FIELDS}
        ev = Event("journald", ts, fields, obj.get("MESSAGE", ""))
        yield ev
        msg = fields.get("message", "")
        ident = fields.get("syslog_identifier", "")
        auth = parse_auth_message(msg, ident, ts)
        if auth is not None:
            yield auth


def parse_auth_message(msg: str, ident: str, ts: float) -> Event | None:
    """Parse an sshd/sudo/pam syslog line into an `auth` source event."""
    if ident in ("sshd", "sshd-session"):
        if m := SSH_ACCEPTED.search(msg):
            return Event("auth", ts, {"service": "sshd", "action": "accepted", "method": m.group(1),
                                      "user": m.group(2), "src_ip": m.group(3), "port": m.group(4)}, msg)
        if m := SSH_FAILED.search(msg):
            return Event("auth", ts, {"service": "sshd", "action": "failed", "user": m.group(2),
                                      "src_ip": m.group(3), "port": m.group(4)}, msg)
        if m := SSH_SESSION.search(msg):
            act = m.group(1).lower().replace(" ", "_")
            return Event("auth", ts, {"service": "sshd", "action": act, "user": m.group(2) or "",
                                      "src_ip": "", "port": ""}, msg)
        if m := SSH_BANNER.search(msg):
            return Event("auth", ts, {"service": "sshd", "action": "connection_" + m.group(1),
                                      "user": "", "src_ip": m.group(2), "port": m.group(3)}, msg)
    if ident == "sudo":
        if m := SUDO_LINE.search(msg):
            return Event("auth", ts, {"service": "sudo", "action": "command", "user": m.group(1),
                                      "tty": m.group(2) or "unknown", "pwd": m.group(3),
                                      "target_user": m.group(4), "command": m.group(5)}, msg)
        if SUDO_AUTHFAIL.search(msg):
            return Event("auth", ts, {"service": "sudo", "action": "auth_fail", "command": ""}, msg)
    if PAM_FAIL.search(msg):
        return Event("auth", ts, {"service": ident or "pam", "action": "pam_auth_fail", "user": ""}, msg)
    return None
