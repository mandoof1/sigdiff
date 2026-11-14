#!/usr/bin/env bash
# Regenerate every image and table the README shows:
#
#   make assets
#
# Needs: vhs, asciinema, ffmpeg. The live-run tape re-executes the whole
# definition-of-done phase on this host (sudo + auditd); the regression tape
# and the cast are pure-offline replays of the committed fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=assets
export PYTHONPATH=src

for t in vhs asciinema ffmpeg; do
	command -v "$t" >/dev/null || { echo "$t not installed (needed to rebuild images)" >&2; exit 1; }
done

echo "[1/3] committed tables -> docs/tables/*.md"
python3 - <<'EOF'
from pathlib import Path
from sigdiff.replay import load_fixtures, replay
from sigdiff.runner import load_techniques
from sigdiff.sigma import load_rules
from sigdiff.ablate import ablate, format_matrix

rules = load_rules(Path("rules"))
res = replay(load_fixtures(Path("fixtures")), rules,
             load_techniques(Path("techniques/techniques.yml")))
assert res["ok"], res
rows = [r for r in res["rules"]]
rows.sort(key=lambda r: r["rule"])
lines = ["| rule | source | level | matches across the 34 recorded windows | verdict |",
         "|---|---|---|---|---|"]
for r in rows:
    lines.append(f"| `{r['rule']}` | {r['source']} | {r['level']} | {r['hits']} | {r['status']} |")
fired = sum(1 for r in rows if r["status"] == "FIRED")
lines.append("")
lines.append(f"{len(rows)} rules · {fired} fired · "
             f"{sum(1 for r in rows if r['status'] == 'NO-HIT')} never fired · "
             f"{sum(1 for r in rows if r['status'] == 'MISSED')} expected-but-missing")
Path("docs/tables").mkdir(exist_ok=True)
Path("docs/tables/replay.md").write_text("\n".join(lines) + "\n")

ab = ablate(load_fixtures(Path("fixtures")), load_rules(Path("rules")), load_rules(Path("rules-b")))
Path("docs/tables/ablation.md").write_text(format_matrix(ab) + "\n")
print(f"replay.md ({len(rows)} rules) + ablation.md")
EOF

echo "[2/3] terminal GIFs + stills from the tapes"
for tape in "$OUT"/*.tape; do
	echo "  vhs $tape"
	vhs "$tape" --output "${tape%.tape}.gif"
done
for g in "$OUT"/*.gif; do
	ffmpeg -loglevel error -sseof -1.0 -i "$g" -frames:v 1 -y "${g%.gif}.png"
done

echo "[3/3] asciinema cast of the offline flow -> $OUT/demo.cast"
COLUMNS=120 LINES=38 asciinema rec --overwrite --quiet --idle-time-limit 1.2 \
	-c "tools/demo.sh" "$OUT/demo.cast"

echo "done. images in $OUT:"
ls -la "$OUT"
