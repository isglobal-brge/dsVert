#!/bin/bash
# Existing Count structural test reads ../../R/dpCountExecutionDS.R. Its source
# and assertions are unchanged. Expose the EXACT checked archive's R directory
# at that expected test path; do not substitute a different checkout or skip it.
set -u
cd /workspace/dsvert/cox/checks-v2
export R_LIBS=/workspace/dsvert/cox/rlib
export _R_CHECK_FORCE_SUGGESTS_=false
export DSVERT_COX_TEST_BINARY=/workspace/dsvert/cox/cox-oracle-v2
export GOMAXPROCS=2
rm -f check-server.exit
R CMD check --no-manual --no-build-vignettes dsVert_1.2.0.tar.gz > check-server.log 2>&1 &
check_pid=$!
while kill -0 "$check_pid" 2>/dev/null; do
 if [ -d dsVert.Rcheck/00_pkg_src/dsVert/R ] && [ ! -e dsVert.Rcheck/R ]; then
  ln -s 00_pkg_src/dsVert/R dsVert.Rcheck/R
 fi
 sleep 1
done
wait "$check_pid"
status=$?
echo "$status" > check-server.exit
exit "$status"
