#!/bin/sh
set -eu
ulimit -c 0
cd "$(dirname "$0")/../.."
export GOMAXPROCS=2 GOMEMLIMIT=4GiB GOGC=25
check_release() {
  python3 - "inst/cross-grid-v2/topology-$1-k$2.log" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"family":')]
assert len(rows) == 1 and rows[0]['oracle_only'] is False
assert text.count('DSLITE_ORACLE_BITWISE_EQUAL') == 1
assert text.count('DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED') == 1
assert 'Execution halted' not in text
PY
  shasum -a 256 -c inst/cross-grid-v2/topology-support.sha256 >> "inst/cross-grid-v2/topology-$1-k$2-source-check.log"
}
run_release() {
  family=$1 owners=$2
  if [ "$owners" = 3 ]; then n=10000; p=10; grid=50; else n=2000; p=6; grid=2; fi
  shasum -a 256 -c inst/cross-grid-v2/topology-support.sha256 > "inst/cross-grid-v2/topology-${family}-k${owners}-source-check.log"
  env DSVERT_GRID_VALIDATION_N="$n" DSVERT_GRID_VALIDATION_P="$p" DSVERT_GRID_VALIDATION_GRID="$grid" DSVERT_GRID_VALIDATION_OWNERS="$owners" DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON=4 DSVERT_GRID_VALIDATION_INSTANCE_COUNT=1 DSVERT_GRID_VALIDATION_REAL_COUNT=1 DSVERT_GRID_VALIDATION_COLD=1 Rscript -e 'source(if (identical(Sys.getenv("DSVERT_GRID_SYNCHRONOUS_CONNECTOR"), "1")) "inst/cross-grid-v2/validate_dslite_sync.R" else "inst/cross-grid-v2/validate_dslite.R")' .. > "inst/cross-grid-v2/topology-${family}-k${owners}.log" 2>&1
  check_release "$family" "$owners"
  if [ "${DSVERT_GRID_SYNCHRONOUS_CONNECTOR:-}" = 1 ]; then
    shasum -a 256 -c inst/cross-grid-v2/topology-poisson-sync-wrapper.sha256 >> "inst/cross-grid-v2/topology-${family}-k${owners}-source-check.log"
  fi
}
if [ "${1:-}" = --restart-poisson-sync ]; then
  export DSVERT_GRID_SYNCHRONOUS_CONNECTOR=1
  shasum -a 256 inst/cross-grid-v2/validate_dslite_sync.R > inst/cross-grid-v2/topology-poisson-sync-wrapper.sha256
fi
if [ "${1:-}" = --restart-poisson ] || [ "${1:-}" = --restart-poisson-sync ]; then
  run_release poisson 3
  run_release poisson 5
  printf 'TOPOLOGY_POISSON_RECOVERY_DONE\n'
  exit 0
fi
adopt_pid=${1:?existing binomial K3 R process required}
(
  while kill -0 "$adopt_pid" 2>/dev/null; do sleep 15; done
  check_release binomial 3
  run_release binomial 5
) & first=$!
(run_release poisson 3; run_release poisson 5) & second=$!
status=0
wait "$first" || status=1
wait "$second" || status=1
test "$status" = 0
printf 'TOPOLOGY_VALIDATION_MAC_DONE\n'
