# The regression story, offline and reproducible: the corpus passes against
# the recorded windows; remove two rules from the set and the same replay
# fails, naming exactly the detections that died.
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
Type "clear && PYTHONPATH=src python3 -m sigdiff replay; echo exit code: $?"
Enter
Sleep 4s
Type "cp -r rules /tmp/rules-minus && rm /tmp/rules-minus/setuid-bit-granted.yml /tmp/rules-minus/lab-log-deleted.yml"
Enter
Sleep 1s
Type "PYTHONPATH=src python3 -m sigdiff replay --rules /tmp/rules-minus; echo exit code: $?"
Enter
Sleep 5s
