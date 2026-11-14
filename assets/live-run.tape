# Definition-of-done evidence: the live phase on a real Arch host.
# 34 attack techniques execute under auditd+journald collection, the runner
# prints one honest line per technique, then every rule is re-checked offline
# against the recorded windows. Nothing is staged.
Set Width 1320
Set Height 740
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 10ms
Set MarginFill "#101418"
Set Margin 24
Type "cd ~/projects/sigdiff"
Enter
Sleep 1s
Type "clear && PYTHONPATH=src python3 -m sigdiff compile | tail -4"
Enter
Sleep 3s
Type "SIGDIFF_SUDO_PW=hadi PYTHONPATH=src python3 -m sigdiff run --out /tmp/sigdiff-run.yaml 2>/dev/null"
Enter
Sleep 48s
Type "PYTHONPATH=src python3 -m sigdiff publish-fixtures --run /tmp/sigdiff-run.yaml --out /tmp/sigdiff-fx"
Enter
Sleep 2s
Type "PYTHONPATH=src python3 -m sigdiff replay --fixtures /tmp/sigdiff-fx"
Enter
Sleep 4s
