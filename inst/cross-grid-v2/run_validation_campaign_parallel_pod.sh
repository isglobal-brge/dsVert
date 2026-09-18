#!/bin/sh
set -eu
ulimit -c 0
lane=/workspace/dsvert/crossowner-v2
cd "$lane/validation/dsVert"
export GOMAXPROCS=2 GOMEMLIMIT=2GiB GOGC=25
check_cell() {
  python3 - "$lane/logs/validation-$1-e$2.log" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"family":')]
assert len(rows) == 20 and [r['instance'] for r in rows] == list(range(1, 21))
assert text.count('DSLITE_ORACLE_BITWISE_EQUAL') == 2
assert text.count('DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED') == 2
assert 'Execution halted' not in text
PY
  sha256sum -c "$lane/logs/validation-support.sha256" >> "$lane/logs/validation-$1-e$2-source-check.log"
}
run_cell() {
  family=$1 epsilon=$2
  sha256sum -c "$lane/logs/validation-support.sha256" > "$lane/logs/validation-${family}-e${epsilon}-source-check.log"
  env DSVERT_GRID_VALIDATION_STATE_PARENT=/var/lib/dsvert-crossowner-v2-validation DSVERT_GRID_VALIDATION_N=2000 DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON="$epsilon" DSVERT_GRID_VALIDATION_INSTANCE_COUNT=20 DSVERT_GRID_VALIDATION_REAL_COUNT=2 DSVERT_GRID_VALIDATION_COLD=1 Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' .. > "$lane/logs/validation-${family}-e${epsilon}.log" 2>&1
  check_cell "$family" "$epsilon"
}
# Adopt the already-running first cell without repeating any release.
adopt_pid=${1:?existing binomial epsilon-one R process required}
(
  while kill -0 "$adopt_pid" 2>/dev/null; do sleep 15; done
  check_cell binomial 1
  run_cell binomial 8
) & first=$!
(run_cell binomial 4; run_cell poisson 4) & second=$!
(run_cell poisson 1; run_cell poisson 8) & third=$!
status=0
wait "$first" || status=1
wait "$second" || status=1
wait "$third" || status=1
test "$status" = 0
printf 'LAYERED_VALIDATION_POD_DONE\n'
