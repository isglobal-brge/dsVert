#!/bin/sh
set -eu
lane=/workspace/dsvert/crossowner-v2
check=/var/lib/dsvert-crossowner-v2-checks-corrected
cd "$check"
export R_LIBS_USER="/var/lib/dsvert-crossowner-v2-checks/library:${R_LIBS_USER:-}"
sha256sum -c dsVert/inst/cross-grid-v2/final-check-inputs.sha256 > "$lane/logs/server-packaging-final-inputs.log"
version=$(Rscript -e 'cat(read.dcf("dsVert/DESCRIPTION")[1,"Version"])')
R CMD build dsVert > "$lane/logs/build-server-final.log" 2>&1
R CMD check --no-manual --no-tests "dsVert_${version}.tar.gz" > "$lane/logs/check-server-packaging-final.log" 2>&1
printf 'SERVER_PACKAGING_FINAL_DONE\n'
