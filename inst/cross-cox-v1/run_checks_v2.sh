#!/bin/bash
set -eu
cd /workspace/dsvert/cox
mkdir -p checks-v2
export R_LIBS=/workspace/dsvert/cox/rlib
export _R_CHECK_FORCE_SUGGESTS_=false
export DSVERT_COX_TEST_BINARY=/workspace/dsvert/cox/cox-oracle-v2
export GOMAXPROCS=2
(cd dsVert/inst/dsvert-mpc && go test -c -tags dsvert_cox_plaintext_test -o "$DSVERT_COX_TEST_BINARY") > checks-v2/build-oracle.log 2>&1
(
 set +e
 ./cox-shared.test -test.run='^TestCoxGridCross' -test.v -test.timeout=60m > checks-v2/go-family.log 2>&1
 echo "$?" > checks-v2/go-family.exit
) &
R CMD INSTALL --library="$R_LIBS" dsVert > checks-v2/install-server.log 2>&1
R CMD INSTALL --library="$R_LIBS" dsVertClient > checks-v2/install-client.log 2>&1
(
 cd checks-v2
 R CMD build --no-build-vignettes --no-manual ../dsVert > build-server.log 2>&1
 set +e
 R CMD check --no-manual --no-build-vignettes dsVert_1.2.0.tar.gz > check-server.log 2>&1
 echo "$?" > check-server.exit
) &
(
 cd checks-v2
 R CMD build --no-build-vignettes --no-manual ../dsVertClient > build-client.log 2>&1
 set +e
 R CMD check --no-manual --no-build-vignettes dsVertClient_1.2.1.tar.gz > check-client.log 2>&1
 echo "$?" > check-client.exit
) &
wait
