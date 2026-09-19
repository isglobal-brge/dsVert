#!/bin/bash
# Run in an isolated workspace containing the pinned dsVert/dsVertClient pair.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: bash dsVert/inst/cross-grid-v2/integrator-validation/prepare-release-workspace.sh SERVER_SHA CLIENT_SHA" >&2
  exit 2
fi
for repo in dsVert dsVertClient; do
  expected="$1"
  shift
  test "$(git -C "$repo" rev-parse HEAD)" = "$expected"
  git -C "$repo" diff --quiet HEAD --
done
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
(cd dsVert/inst/bin && sha256sum -c SHA256SUMS)
Rscript --vanilla - <<'RS'
packages <- c("pkgload", "callr", "DSI", "DSLite", "testthat", "survival")
for (repo in c("dsVert", "dsVertClient")) {
  imports <- read.dcf(file.path(repo, "DESCRIPTION"), fields = "Imports")[[1]]
  packages <- c(packages, trimws(gsub("\\s*\\(.*?\\)", "", strsplit(imports, ",")[[1]])))
}
missing <- unique(packages[!vapply(packages, requireNamespace, logical(1), quietly = TRUE)])
if (length(missing)) stop("Install validation dependencies in R_LIBS_USER: ", paste(missing, collapse = ", "))
RS
mkdir -p logs dsVert/inst/cross-grid-v2/build
if [ ! -e integrator-validation ]; then
  ln -s dsVert/inst/cross-grid-v2/integrator-validation integrator-validation
fi
test "$(readlink -f integrator-validation)" = "$(readlink -f dsVert/inst/cross-grid-v2/integrator-validation)"
(cd dsVert/inst/dsvert-mpc && go test -c -o ../cross-grid-v2/build/cross-grid-oracle.test .)
echo "RELEASE_WORKSPACE_PREPARED (readiness and promotion require separate evidence)"
