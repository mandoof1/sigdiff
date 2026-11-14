#!/usr/bin/env bash
# The committed-evidence flow, offline and deterministic:
# compile the corpus, replay it against the recorded telemetry windows,
# ablate the rule sets. No sudo, no live phase — this is what CI runs too.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
sigdiff() { python3 -m sigdiff "$@"; }

echo '$ sigdiff compile'
sigdiff compile
echo
echo '$ sigdiff replay            # the recorded windows, back through the rules'
sigdiff replay
echo
echo '$ sigdiff ablate --rules-a rules --rules-b rules-b | head -14'
sigdiff ablate --rules-a rules --rules-b rules-b | head -14
sleep 1
