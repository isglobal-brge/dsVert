#!/bin/sh
set -eu
lane=/workspace/dsvert/crossowner-v2
export GOMEMLIMIT=6GiB
export GOGC=25
while ! grep -q FULL_MEASUREMENT_POD_DONE "$lane/logs/full-measurement-run.log"; do sleep 30; done
cd "$lane/validation/dsVert"
mkdir -p inst/cross-grid-v2/build
cp inst/bin/linux-amd64/dsvert-mpc inst/cross-grid-v2/build/dsvert-mpc
(cd inst/dsvert-mpc && go test -c -o ../cross-grid-v2/build/cross-grid-oracle.test)
sha256sum inst/cross-grid-v2/validate_dslite.R inst/cross-grid-v2/prepare_oracle_noise.R inst/cross-grid-v2/validate_cold_lifecycle.R > "$lane/logs/validation-support.sha256"
run_family() {
  family="$1"
  for epsilon in 1 4 8; do
    sha256sum -c "$lane/logs/validation-support.sha256" > "$lane/logs/validation-${family}-e${epsilon}-source-check.log"
    env GOMAXPROCS=2 DSVERT_GRID_VALIDATION_STATE_PARENT=/var/lib/dsvert-crossowner-v2-validation DSVERT_GRID_VALIDATION_N=2000 DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON="$epsilon" DSVERT_GRID_VALIDATION_INSTANCE_COUNT=20 DSVERT_GRID_VALIDATION_REAL_COUNT=2 DSVERT_GRID_VALIDATION_COLD=1 Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' .. > "$lane/logs/validation-${family}-e${epsilon}.log" 2>&1
    sha256sum -c "$lane/logs/validation-support.sha256" >> "$lane/logs/validation-${family}-e${epsilon}-source-check.log"
  done
}
run_family binomial
run_family poisson
printf 'LAYERED_VALIDATION_POD_DONE\n'
