#!/bin/sh
set -eu
ulimit -c 0
lane=/workspace/dsvert/crossowner-v2
check=/var/lib/dsvert-crossowner-v2-checks
while ! grep -q MATRIX_POD_DONE "$lane/logs/remaining-matrix-run.log"; do sleep 30; done
cd "$check"
sha256sum -c dsVert/inst/cross-grid-v2/final-check-inputs.sha256 > "$lane/logs/final-check-inputs-before.log"
mkdir -p library
export R_LIBS_USER="$check/library:${R_LIBS_USER:-}"
export GOMAXPROCS=2
export GOMEMLIMIT=6GiB
export GOGC=25
export NOT_CRAN=true
Rscript -e 'p <- c("DSMolgenisArmadillo", "DSOpal", "opalr", "pkgdown"); missing <- p[!vapply(p, requireNamespace, logical(1), quietly=TRUE)]; if (length(missing)) install.packages(missing, repos="https://cloud.r-project.org", Ncpus=2)' > "$lane/logs/check-dependencies.log" 2>&1
(cd dsVert/inst/dsvert-mpc && DSVERT_COMPARE_CAPACITY=1 go test ./... -count=1 -timeout=0 > "$lane/logs/full-go-tests.log" 2>&1) &
go_pid=$!
R CMD build dsVert > "$lane/logs/build-server.log" 2>&1
R CMD INSTALL --library="$check/library" dsVert_1.2.0.tar.gz > "$lane/logs/install-server.log" 2>&1
R CMD build dsVertClient > "$lane/logs/build-client.log" 2>&1
R CMD check --no-manual dsVert_1.2.0.tar.gz > "$lane/logs/check-server.log" 2>&1
R CMD check --no-manual dsVertClient_1.2.0.tar.gz > "$lane/logs/check-client.log" 2>&1
wait "$go_pid"
sha256sum -c dsVert/inst/cross-grid-v2/final-check-inputs.sha256 > "$lane/logs/final-check-inputs-after.log"
printf 'FINAL_CHECKS_POD_DONE\n'
