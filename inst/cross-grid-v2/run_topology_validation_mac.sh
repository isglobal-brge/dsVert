#!/bin/sh
set -eu
ulimit -c 0
cd "$(dirname "$0")/../.."
export GOMEMLIMIT=4GiB
export GOGC=25
export GOMAXPROCS=2
cp inst/bin/darwin-arm64/dsvert-mpc inst/cross-grid-v2/build/dsvert-mpc
shasum -a 256 inst/cross-grid-v2/validate_dslite.R inst/cross-grid-v2/prepare_oracle_noise.R inst/cross-grid-v2/validate_cold_lifecycle.R > inst/cross-grid-v2/topology-support.sha256
for family in binomial poisson; do
  for owners in 3 5; do
    if [ "$owners" = 3 ]; then n=10000; p=10; grid=50; else n=2000; p=6; grid=2; fi
    shasum -a 256 -c inst/cross-grid-v2/topology-support.sha256 > "inst/cross-grid-v2/topology-${family}-k${owners}-source-check.log"
    env DSVERT_GRID_VALIDATION_N="$n" DSVERT_GRID_VALIDATION_P="$p" DSVERT_GRID_VALIDATION_GRID="$grid" DSVERT_GRID_VALIDATION_OWNERS="$owners" DSVERT_GRID_VALIDATION_FAMILY="$family" DSVERT_GRID_VALIDATION_EPSILON=4 DSVERT_GRID_VALIDATION_INSTANCE_COUNT=1 DSVERT_GRID_VALIDATION_REAL_COUNT=1 DSVERT_GRID_VALIDATION_COLD=1 Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' .. > "inst/cross-grid-v2/topology-${family}-k${owners}.log" 2>&1
    shasum -a 256 -c inst/cross-grid-v2/topology-support.sha256 >> "inst/cross-grid-v2/topology-${family}-k${owners}-source-check.log"
  done
done
printf 'TOPOLOGY_VALIDATION_MAC_DONE\n'
