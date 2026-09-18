#!/bin/bash
set -eu
cd /workspace/dsvert/cox
mkdir -p envelope-v2
uname -a > envelope-v2/host.txt
lscpu >> envelope-v2/host.txt
cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us /sys/fs/cgroup/cpu/cpu.cfs_period_us >> envelope-v2/host.txt
cd dsVert/inst/dsvert-mpc
GOMAXPROCS=4 go test -c -o /workspace/dsvert/cox/cox-shared.test
cd /workspace/dsvert/cox
sha256sum cox-shared.test > envelope-v2/binary.sha256
GOMAXPROCS=2 ./cox-shared.test -test.run='^TestCoxGridCrossShared(Profiles|Protocol|PlanAndTopology|CompactTopologyBinding|ReceiptNeedsPrivateKey)$' -test.v -test.timeout=15m > envelope-v2/targeted.log 2>&1
running=0
for n in 2000 4000 10000; do
 for j in 16 32 50; do
  (
   export GOMAXPROCS=2 DSVERT_COX_ENVELOPE=1 DSVERT_COX_N="$n" DSVERT_COX_J="$j"
   export DSVERT_COX_REPORT="/workspace/dsvert/cox/envelope-v2/n${n}_j${j}.json"
   set +e
   ./cox-shared.test -test.run='^TestCoxGridCrossSharedEnvelope$' -test.v -test.timeout=4h > "envelope-v2/n${n}_j${j}.log" 2>&1
   echo "$?" > "envelope-v2/n${n}_j${j}.exit"
  ) &
  running=$((running+1))
  if [ "$running" -ge 2 ]; then wait -n; running=$((running-1)); fi
 done
done
wait
