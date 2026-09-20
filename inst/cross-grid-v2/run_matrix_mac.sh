#!/bin/sh
set -eu
cd "$(dirname "$0")/../dsvert-mpc"
go test -c -o ../cross-grid-v2/build/cross-grid-matrix.test
cd ../cross-grid-v2
for n in 1000 10000; do
  for p in 5 10; do
    for grid in 16 50; do
      env GOMAXPROCS=6 DSVERT_CROSS_FULL_MEASURE=1 DSVERT_CROSS_N="$n" DSVERT_CROSS_P="$p" DSVERT_CROSS_GRID="$grid" DSVERT_CROSS_WORKERS=3 ./build/cross-grid-matrix.test -test.run '^TestCrossGridFullMeasurement$' -test.v -test.count=1 -test.timeout=0 > "matrix-mac-n${n}-p${p}-g${grid}.log" 2>&1
    done
  done
done
printf 'MATRIX_MAC_DONE\n'
