#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
family=${1:?family required}
pid=${2:?existing K3 R process required}
while kill -0 "$pid" 2>/dev/null; do sleep 30; done
python3 - "inst/cross-grid-v2/topology-$family-k3.log" "$family" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"family":')]
assert len(rows) == 1
r = rows[0]
assert (r['family'], r['n'], r['p'], r['grid'], r['owners'], r['epsilon']) == (sys.argv[2], 10000, 10, 50, 3, 4)
assert r['oracle_only'] is False
assert text.count('DSLITE_ORACLE_BITWISE_EQUAL') == 1
assert text.count('DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED') == 1
assert 'Execution halted' not in text
PY
shasum -a 256 -c inst/cross-grid-v2/topology-support.sha256 >> "inst/cross-grid-v2/topology-$family-k3-source-check.log"
if [ "$family" = poisson ]; then
  shasum -a 256 -c inst/cross-grid-v2/topology-poisson-sync-wrapper.sha256 >> "inst/cross-grid-v2/topology-$family-k3-source-check.log"
fi
printf 'K3_FAMILY_DONE %s\n' "$family"
