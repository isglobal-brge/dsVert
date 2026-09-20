#!/bin/sh
# Execute from /workspace/dsvert/crossowner-v2/dsVert. Synthetic component only.
set -eu
export GOMAXPROCS=8
export PYTHONDONTWRITEBYTECODE=1
LOGS=/workspace/dsvert/crossowner-v2/logs
python3 inst/cross-grid-v2/generate_exp_reduced.py --check > "$LOGS/exp-reduced-certificate.log" 2>&1
Rscript inst/cross-grid-v2/validate_exp_reduced.R > "$LOGS/exp-reduced-r.log" 2>&1
Rscript inst/cross-grid-v2/validate_pooled_objective.R > "$LOGS/pooled-objective-r.log" 2>&1
(cd inst/dsvert-mpc && go test -run '^(TestCrossGridExpReducedV2|TestCrossGridBinomialV2BatchProtocol$|TestExactGCProtocolEndToEnd$|TestExactGCProtocolFreshArithmeticShares$|TestExactGCSecureRecords)' -json -count=1) > "$LOGS/exp-reduced-targeted.jsonl" 2>&1
Rscript inst/cross-grid-v2/benchmark_exp_reduced.R . > "$LOGS/exp-reduced-bench.log" 2>&1
printf 'EXP_REDUCED_POD_DONE\n'
