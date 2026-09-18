#!/bin/sh
set -eu
cd /workspace/dsvert/crossowner-v2
export GOMEMLIMIT=6GiB
export GOGC=25
for n in 1000 10000; do
  for p in 5 10; do
    for grid in 16 50; do
      if [ "$n:$p:$grid" = 10000:10:50 ]; then continue; fi
      for family in binomial poisson; do
        original="logs/matrix-pod-n${n}-p${p}-g${grid}.log"
        resumed="logs/matrix-pod-n${n}-p${p}-g${grid}-${family}.log"
        if grep -h 'FULL_MEASUREMENT {' "$original" "$resumed" 2>/dev/null | grep -q "\"family\":\"$family\""; then continue; fi
        env GOMAXPROCS=8 DSVERT_CROSS_FULL_MEASURE=1 DSVERT_CROSS_N="$n" DSVERT_CROSS_P="$p" DSVERT_CROSS_GRID="$grid" DSVERT_CROSS_WORKERS=4 ./cross-grid-measure.test -test.run "^TestCrossGridFullMeasurement$/${family}$" -test.v -test.count=1 -test.timeout=0 > "$resumed" 2>&1
      done
    done
  done
done
printf 'MATRIX_POD_DONE\n'
