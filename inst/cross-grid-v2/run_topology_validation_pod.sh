#!/bin/sh
set -eu
ulimit -c 0
lane=/workspace/dsvert/crossowner-v2
export GOMEMLIMIT=6GiB
export GOGC=25
while ! grep -q LAYERED_VALIDATION_POD_DONE "$lane/logs/validation-campaign-run.log"; do sleep 30; done
cd "$lane/validation/dsVert"
# Reuse the frozen harness; these are additional releases, not the 120-instance matrix.
run_family() {
  family="$1"
  for owners in 3 5; do
    if [ "$owners" = 3 ]; then n=10000; p=10; grid=50; else n=2000; p=6; grid=2; fi
    sha256sum -c "$lane/logs/validation-support.sha256" > "$lane/logs/topology-${family}-k${owners}-source-check.log"
    env GOMAXPROCS=2 DSVERT_GRID_VALIDATION_STATE_PARENT=/var/lib/dsvert-crossowner-v2-validation DSVERT_GRID_VALIDATION_N="$n" DSVERT_GRID_VALIDATION_P="$p" DSVERT_GRID_VALIDATION_GRID="$grid" DSVERT_GRID_VALIDATION_OWNERS="$owners" DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON=4 DSVERT_GRID_VALIDATION_INSTANCE_COUNT=1 DSVERT_GRID_VALIDATION_REAL_COUNT=1 DSVERT_GRID_VALIDATION_COLD=1 Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' .. > "$lane/logs/topology-${family}-k${owners}.log" 2>&1
    sha256sum -c "$lane/logs/validation-support.sha256" >> "$lane/logs/topology-${family}-k${owners}-source-check.log"
  done
}
run_family binomial
run_family poisson
printf 'TOPOLOGY_VALIDATION_POD_DONE\n'
