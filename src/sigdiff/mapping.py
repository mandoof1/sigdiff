"""Where Sigma's logsource/field vocabulary lands on *our* telemetry.

This file is the whole contract between a rule and a host. If it changes, the
baseline changes, and `sigdiff verify` says so loudly — that is the point.

Sources (canonical names): auditd, auth, journald.
Canonical field names are lowercase with underscores.
"""

from __future__ import annotations

# Sigma logsource -> canonical source. Keyed by (category, service, product);
# more specific keys win (category+service beats service beats product).
LOGSOURCE_MAP: dict[tuple[str, str, str], str] = {
    ("", "auditd", "linux"): "auditd",
    ("process_creation", "", "linux"): "auditd",
    ("process_termination", "", "linux"): "auditd",
    ("file_create", "", "linux"): "auditd",
    ("file_open", "", "linux"): "auditd",
    ("file_delete", "", "linux"): "auditd",
    ("file_modify", "", "linux"): "auditd",
    ("network_connection", "", "linux"): "auditd",
    ("", "sshd", "linux"): "auth",
    ("authentication", "sshd", "linux"): "auth",
    ("authorization", "sudo", "linux"): "auth",
    ("", "sudo", "linux"): "auth",
    ("", "sudo-l", "linux"): "auth",
    ("authentication", "", "linux"): "auth",
    ("", "systemd", "linux"): "journald",
    ("", "cron", "linux"): "journald",
    ("", "pam", "linux"): "journald",
    ("*", "", "linux"): "journald",
    ("", "", "linux"): "journald",
}

# Sigma field names -> canonical field, per source. Sigma's Process_creation
# vocabulary maps onto the auditd exec events; file/network vocabulary onto
# auditd file/socket events; sshd/sudo vocabulary onto the auth source.
FIELD_ALIASES: dict[str, dict[str, str]] = {
    "auditd": {
        "image": "exe",
        "commandline": "cmdline",
        "user": "auid",
        "usertype": "auid",
        "auditkey": "key",
        "syscall": "syscall",
        "targetfilename": "path",
        "filepath": "path",
        "initfilename": "to",
        "oldname": "path",
        "newname": "to",
        "filename": "path",
        "directory": "path",
        "destinationip": "dest_ip",
        "destinationport": "dest_port",
        "protocol": "syscall",
        "eventtype": "syscall",
        "operation": "syscall",
        "file": "path",
        "path": "path",
        "op": "op",
        "key": "key",
        "cwd": "cwd",
        "uid": "uid",
    },
    "auth": {
        "action": "action",
        "status": "action",
        "method": "method",
        "user": "user",
        "username": "user",
        "srcip": "src_ip",
        "sourceip": "src_ip",
        "clientip": "src_ip",
        "ip": "src_ip",
        "srcport": "port",
        "sourceport": "port",
        "port": "port",
        "service": "service",
        "logname": "service",
        "command": "command",
        "cmd": "command",
        "tty": "tty",
        "pwd": "pwd",
        "runas": "target_user",
        "targetuser": "target_user",
        "sudoer": "run_as",
        "run_by": "run_as",
    },
    "journald": {
        "ident": "syslog_identifier",
        "identifier": "syslog_identifier",
        "syslogidentifier": "syslog_identifier",
        "unit": "unit",
        "systemdunit": "_systemd_unit",
        "message": "message",
        "priority": "priority",
        "comm": "_comm",
        "exe": "_exe",
        "cmdline": "_cmdline",
        "pid": "_pid",
        "uid": "_uid",
    },
}

# what a keyword rule (no field, bare substring) searches
KEYWORD_FIELDS: dict[str, tuple[str, ...]] = {
    "auditd": ("cmdline", "exe", "path"),
    "auth": ("command", "user", "service"),
    "journald": ("message",),
}


def canonical_source(category: str, service: str, product: str) -> str | None:
    """Resolve a Sigma logsource to a canonical source name, or None when the
    rule targets something this host does not produce (windows, web logs…)."""
    category, service, product = (category or "", service or "", product or "")
    for key in ((category, service, product), ("", service, product),
                (category, "", product), ("", "", product)):
        if key in LOGSOURCE_MAP:
            return LOGSOURCE_MAP[key]
    return None


def canonical_field(source: str, sigma_field: str) -> str | None:
    return FIELD_ALIASES.get(source, {}).get(sigma_field.lower().split("|", 1)[0])
