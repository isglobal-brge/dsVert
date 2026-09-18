#!/bin/sh
set -eu
cd /workspace/dsvert/crossowner-v2/dsVert
sha256sum -c inst/cross-grid-v2/full-measurement-source.sha256 > ../logs/full-measurement-source-check.log
cd inst/dsvert-mpc
go test -c -o ../../../cross-grid-measure.test
for n in 10000 2000; do
  env GOMAXPROCS=8 DSVERT_CROSS_FULL_MEASURE=1 DSVERT_CROSS_N="$n" DSVERT_CROSS_P=10 DSVERT_CROSS_GRID=50 DSVERT_CROSS_WORKERS=4 ../../../cross-grid-measure.test -test.run '^TestCrossGridFullMeasurement$' -test.v -test.count=1 -test.timeout=0 > "../../../logs/full-n${n}.log" 2>&1
done
printf 'FULL_MEASUREMENT_POD_DONE\n'
