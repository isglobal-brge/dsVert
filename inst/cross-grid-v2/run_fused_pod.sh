#!/bin/sh
set -eu
cd /workspace/dsvert/crossowner-v2/dsVert
sha256sum -c inst/cross-grid-v2/fused-source.sha256 > ../logs/fused-source-check.log
Rscript inst/cross-grid-v2/validate_fused_vectors.R > ../logs/fused-r.log 2>&1
cd inst/dsvert-mpc
go test -run '^(TestCrossGridKernel(Integer|Round|Predictor|SharedVectors|RejectsPublicPlanAndShares|TwoAuthority|JointNoise|PurposeAndAdmissionGate|BoundarySlack)|TestCrossGridPWV2Optimizer|TestCrossGridExpReducedV2NotAdmittedAsV1|TestExactGCProtocolEndToEnd|TestExactGCSecureRecords)' -json -count=1 > ../../../logs/fused-targeted.jsonl
go test -run '^$' -bench '^BenchmarkCrossGridFusedBatch$' -benchtime=1x -count=1 -timeout=0 > ../../../logs/fused-bench.log 2>&1
printf 'FUSED_POD_DONE\n'
