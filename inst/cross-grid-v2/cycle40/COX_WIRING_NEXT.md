# Cox after cycle40

Server catalog preflight now recognizes the signed Cox wrapper and preserves it
through local and global workload normalization. It uses time/event descriptors,
requires their common advertising owner to own both columns in the signed
dataset, and resolves time/event/predictors by owner+column+dataset without
adding implicit public moment coordinates. K2/K3/K5 tests use the real catalog
functions and signed Cox schema/contract validation, without catalog mocks.
These are catalog normalization tests, not complete signed draft assembly.

Public workload artifact admission remains explicitly closed in
`dpCapsuleWorkload.R` until the remaining production lifecycle is wired.
The existing exact contract, N<=400 staged guard, numeric arithmetic and DP
mechanisms are unchanged. The new code does not enable a Cox fleet job.

Next concrete boundaries:
- Client `dp_capsule_manifest.R:423` still assumes every cross-grid catalog
  wrapper has `spec$outcome$owner_peer`; add Cox time/event owner validation
  and exact version/dataset/analysis binding there before signed draft assembly.
- Server workload artifact loop must validate the signed Cox contract against
  the actual schema and project `.dsvert_dp_cox_cross_workload_artifact`, with
  the same sensitivity accounting as the existing grouped branch.
- Client discovery/artifact projection/source layout, compilation and certificate
  dispatch still need Cox branches. Reuse the existing authenticated Cox reader.
- Owner-first staged bind: call time owner first, validate and pass its signed
  public routing receipt to the evaluator. `dpCoxGridCrossPrepare.R` and the
  exported server bind already authenticate this receipt; no raw private route
  may cross to the client. Then use the existing prepare/start/store/finalize.
- Prove a complete small signed source-sharing/persistence and DP release with
  recovery, cold replay and tamper rejection before declaring fleet readiness.

LMM compile reuse is already present. Relay batching needs the bounded,
individually authenticated envelope protocol described in cycle35's
LMM_BATCHING_NEXT.md. Old-source K5 now has oracle/cold/tamper PASS but exceeds
6h (22,774.592s); retain its source pin and do not promote from those checks.
GEE remains separately owned; do not edit its kernels/contracts/oracles.
