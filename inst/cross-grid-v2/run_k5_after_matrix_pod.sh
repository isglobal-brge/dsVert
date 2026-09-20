#!/bin/sh
set -eu
ulimit -c 0
lane=/workspace/dsvert/crossowner-v2
cd "$lane/validation/dsVert"
export GOMAXPROCS=2 GOMEMLIMIT=4GiB GOGC=25
# Wait for the existing matrix coordinators; never repeat their releases.
for pid in "$@"; do
  while kill -0 "$pid" 2>/dev/null; do sleep 30; done
done
python3 inst/cross-grid-v2/summarize_validation.py "$lane/logs" "$lane/logs/LAYER3_V2.md"
sha256sum -c "$lane/logs/validation-support.sha256"
sha256sum R/*.R ../dsVertClient/R/*.R DESCRIPTION NAMESPACE \
  ../dsVertClient/DESCRIPTION ../dsVertClient/NAMESPACE \
  inst/bin/linux-amd64/dsvert-mpc inst/cross-grid-v2/validate_dslite.R \
  inst/cross-grid-v2/prepare_oracle_noise.R inst/cross-grid-v2/validate_cold_lifecycle.R \
  inst/cross-grid-v2/validate_dslite_sync.R > "$lane/logs/topology-k5-support.sha256"
for family in binomial poisson; do
  sha256sum -c "$lane/logs/topology-k5-support.sha256" > "$lane/logs/topology-$family-k5-source-check.log"
  env DSVERT_GRID_VALIDATION_STATE_PARENT=/var/lib/dsvert-crossowner-v2-validation \
    DSVERT_GRID_VALIDATION_N=2000 DSVERT_GRID_VALIDATION_P=6 \
    DSVERT_GRID_VALIDATION_GRID=2 DSVERT_GRID_VALIDATION_OWNERS=5 \
    DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON=4 \
    DSVERT_GRID_VALIDATION_INSTANCE_COUNT=1 DSVERT_GRID_VALIDATION_REAL_COUNT=1 \
    DSVERT_GRID_VALIDATION_COLD=1 \
    Rscript -e 'source("inst/cross-grid-v2/validate_dslite_sync.R")' .. \
    > "$lane/logs/topology-$family-k5.log" 2>&1
  python3 - "$lane/logs/topology-$family-k5.log" "$family" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"family":')]
assert len(rows) == 1
r = rows[0]
assert (r['family'], r['n'], r['p'], r['grid'], r['owners'], r['epsilon'], r['instance']) == (sys.argv[2], 2000, 6, 2, 5, 4, 1)
assert r['oracle_only'] is False
assert text.count('DSLITE_ORACLE_BITWISE_EQUAL') == 1
assert text.count('DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED') == 1
assert 'Execution halted' not in text
PY
  sha256sum -c "$lane/logs/topology-k5-support.sha256" >> "$lane/logs/topology-$family-k5-source-check.log"
  printf 'K5_FAMILY_DONE %s\n' "$family"
done
printf 'K5_TOPOLOGY_POD_DONE\n'
