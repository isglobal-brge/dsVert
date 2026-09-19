# Six structured-family release harnesses

`validate_{lmm,binomial_glmm,poisson_glmm,binomial_gee,poisson_gee,cox}_dslite.R`
invoke the common `validate_structured_dslite.R`. They provision isolated
synthetic custodians, pin identities, request PSI alignment, sign the family
contract/schema, and call the existing public family API. They require real
release, induced durable interruption, recovery, certificate authentication,
independent integer/noise equality, sticky replay, tamper rejection and cold
lifecycle checks. Oracle-only and omitted cold/interruption modes are rejected.
No callback, mock reader, reference-only DP draw or registration flag enables
a release. An API failure is a nonzero harness exit, not a successful rejection
test. The new scripts are **not authenticated-release proofs**.

The independent R oracle uses the retained f264 LMM arithmetic, factorial-free
shifted GH5 selection, v3 GEE whitening/bread/meat and direct Cox risk sets.
The test-only Go noise entry replays captured synthetic two-authority sampler
seeds. It requires every workload coordinate and rejects overlapping chunks.
It adds no production command. Build with the manifest's `go test -c` command.

Current dependencies still prevent fleet readiness:

- Generic manifest/profile/source dispatch does not yet accept these six
  contracts. Grouped materialization and grouped/Cox release readers fail closed.
- Authenticated once-only routing, durable stage receipts, final validity/cap
  fusion and joint-DP injection remain to be integrated. Harnesses target the
  existing lifecycle; they do not implement it.
- Grouped C<=64, B<=16 (GEE B<=8,p<=3) and two-owner restrictions remain. n2000
  and K3/K5 need measured shape/owner admission; no restriction is bypassed by
  choosing a smaller fixture when the requested run says n2000.
- Initial grouped n4/K2 attempts fail during Padded PSI finalization, followed
  by an unresolved DSI lifecycle rejection. Cox now passes signed spec construction and snapshot fixed-point checking,
  then rejects at synopsis bootstrap: `A custodian Gaussian specification is
  not locally owned`. The public snapshot projection recognizes these plan
  versions without enabling the missing producer. These runs are neither
  kernel failures nor capacity measurements.

Use `run-structured-oracles.R` with the tagged test executable to verify the
independent family oracles. Those checks passed all six families on pod4 in
cycle4; they do not establish authenticated release readiness. The release
manifest lists all 1800 jobs and explicitly keeps every job non-fleet-ready.
