| technique | no rules | rules A | rules B | A-only | B-only |
|---|---|---|---|---|---|
| account-lifecycle | 0 | 7 | 9 | 0 | 2 |
| audit-tamper-last | 0 | 4 | 5 | 0 | 1 |
| base64-stage | 0 | 2 | 3 | 0 | 1 |
| chmod-777 | 0 | 2 | 3 | 0 | 1 |
| collect-tar | 0 | 3 | 4 | 0 | 1 |
| control-benign | 0 | 1 | 2 | 0 | 1 |
| curl-pipe-sh | 0 | 4 | 5 | 0 | 1 |
| discovery-basic | 0 | 1 | 2 | 0 | 1 |
| discovery-netinfo | 0 | 2 | 3 | 0 | 1 |
| discovery-nmap | 0 | 1 | 2 | 0 | 1 |
| dmesg-clear | 0 | 3 | 4 | 0 | 1 |
| exfil-upload | 0 | 6 | 7 | 0 | 1 |
| firewall-insert | 0 | 3 | 4 | 0 | 1 |
| history-env | 0 | 1 | 1 | 1 | 1 |
| history-shred | 0 | 2 | 3 | 0 | 1 |
| kill-agent | 0 | 1 | 2 | 0 | 1 |
| log-tamper-lab | 0 | 4 | 5 | 0 | 1 |
| module-load | 0 | 4 | 5 | 0 | 1 |
| mount-loop | 0 | 4 | 5 | 0 | 1 |
| persist-bashrc | 0 | 2 | 3 | 0 | 1 |
| persist-cron | 0 | 4 | 6 | 0 | 2 |
| persist-ldpreload | 0 | 5 | 7 | 0 | 2 |
| persist-sshkey | 0 | 3 | 4 | 0 | 1 |
| persist-sudoersd | 0 | 3 | 5 | 0 | 2 |
| persist-unit | 0 | 7 | 9 | 0 | 2 |
| priv-elev-sudo | 0 | 3 | 4 | 0 | 1 |
| revshell-devtcp | 0 | 2 | 3 | 0 | 1 |
| revshell-python | 0 | 2 | 2 | 1 | 1 |
| setuid-copy | 0 | 2 | 3 | 0 | 1 |
| sniff-tcpdump | 0 | 4 | 5 | 0 | 1 |
| ssh-inject-brute | 0 | 2 | 3 | 0 | 1 |
| ssh-inject-login | 0 | 4 | 4 | 1 | 1 |
| sudo-inject-authfail | 0 | 2 | 3 | 0 | 1 |
| sysctl-tweak | 0 | 3 | 4 | 0 | 1 |

rule set B gains 2 detection(s): loose-any-bash, loose-etc-touch
rule set B loses 3 detection(s): history-env-modified, ssh-session-opened, suspicious-outbound-1337
  account-lifecycle: only-A [] only-B [loose-any-bash, loose-etc-touch]
  audit-tamper-last: only-A [] only-B [loose-any-bash]
  base64-stage: only-A [] only-B [loose-any-bash]
  chmod-777: only-A [] only-B [loose-any-bash]
  collect-tar: only-A [] only-B [loose-any-bash]
  control-benign: only-A [] only-B [loose-any-bash]
  curl-pipe-sh: only-A [] only-B [loose-any-bash]
  discovery-basic: only-A [] only-B [loose-any-bash]
  discovery-netinfo: only-A [] only-B [loose-any-bash]
  discovery-nmap: only-A [] only-B [loose-any-bash]
  dmesg-clear: only-A [] only-B [loose-any-bash]
  exfil-upload: only-A [] only-B [loose-any-bash]
  firewall-insert: only-A [] only-B [loose-any-bash]
  history-env: only-A [history-env-modified] only-B [loose-any-bash]
  history-shred: only-A [] only-B [loose-any-bash]
  kill-agent: only-A [] only-B [loose-any-bash]
  log-tamper-lab: only-A [] only-B [loose-any-bash]
  module-load: only-A [] only-B [loose-any-bash]
  mount-loop: only-A [] only-B [loose-any-bash]
  persist-bashrc: only-A [] only-B [loose-any-bash]
  persist-cron: only-A [] only-B [loose-any-bash, loose-etc-touch]
  persist-ldpreload: only-A [] only-B [loose-any-bash, loose-etc-touch]
  persist-sshkey: only-A [] only-B [loose-any-bash]
  persist-sudoersd: only-A [] only-B [loose-any-bash, loose-etc-touch]
  persist-unit: only-A [] only-B [loose-any-bash, loose-etc-touch]
  priv-elev-sudo: only-A [] only-B [loose-any-bash]
  revshell-devtcp: only-A [] only-B [loose-any-bash]
  revshell-python: only-A [suspicious-outbound-1337] only-B [loose-any-bash]
  setuid-copy: only-A [] only-B [loose-any-bash]
  sniff-tcpdump: only-A [] only-B [loose-any-bash]
  ssh-inject-brute: only-A [] only-B [loose-any-bash]
  ssh-inject-login: only-A [ssh-session-opened] only-B [loose-any-bash]
  sudo-inject-authfail: only-A [] only-B [loose-any-bash]
  sysctl-tweak: only-A [] only-B [loose-any-bash]
