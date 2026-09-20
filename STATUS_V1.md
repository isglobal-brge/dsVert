# Status V1 — contract and reference

Step 1 implementation is complete; full-suite verification is running. Promotion requires independent review. No release path is enabled.

## Delivered

- Server and client new-version-only signed spec, artifact, source-layout and numeric validators, with real Ed25519 signature checks and fixed transcript-safe failures.
- Go structs matching the signed R envelope, a numeric validator, and a strict-decoding interoperability test using a synthetic signed R fixture.
- Exact integer batch references in Go test code and pure R test helpers; binomial mux, Poisson bounded integer outcome and log-factorial lookup, common validity masking, clamping, ties-to-even output quantization and sums.
- Reproducible outward-interval coefficient generation and analytic uniform-error/width proofs. See `NUMERIC_CERTIFICATE_V1.md` and `.json`.
- Sensitivity parity checks against the actual existing server workload builder and client loss-bound helper.
- Decisions, including numeric edge cases and bounded-target interpretation, in `DECISIONS_V1.md`.

All source and test changes are confined to the two requested repositories. Existing production files, registrations, tags, package versions and remote branches are unchanged. The only modified existing test file adds same-owner sensitivity comparisons.

## Verification

Authoritative before-version Go run uses a pristine tracked-file archive of server commit `9067cc7`. Authoritative before-version R runs use a paired local checkout of `9067cc7` / `f5ed18a` with the expected `dsVert` / `dsVertClient` directory names. This matters because existing companion and end-to-end tests inspect those paths. After-version runs use the feature checkouts. No test filter, short mode or E2E family restriction is set for the full suites.

Commands:

```sh
# In each corresponding inst/dsvert-mpc directory:
go test -json -timeout 0 ./...

# In each R package root, with PROCESSX_NOTIFY_OLD_SIGCHLD=true:
Rscript -e 'r <- testthat::test_local(".", reporter="silent", stop_on_failure=FALSE, stop_on_warning=FALSE); d <- as.data.frame(r); print(colSums(d[,c("nb","failed","skipped","error","warning","passed")]))'
```

The client baseline explicitly sets `DSVERT_SERVER_SOURCE` to its paired pristine server checkout. Go's package-wide timeout is disabled because the existing unskipped multi-authority integration tests are long; their own deadlines remain intact.

| Suite | Before passed | Before failed / errors | Before skipped | After passed | After failed / errors | After skipped |
| --- | ---: | --- | ---: | ---: | --- | ---: |
| Go, top-level tests | pending | pending | pending | pending | pending | pending |
| Go, all test/subtest terminal events | pending | pending | pending | pending | pending | pending |
| Server testthat expectations | pending | pending | pending | pending | pending | pending |
| Client testthat expectations | pending | pending | pending | pending | pending | pending |

Focused final checks so far: server contract 175 assertions / 10 blocks; client contract 260 assertions / 14 blocks; R integer reference 178 assertions / 6 blocks per package; server sensitivity parity 24 assertions / 1 block; client sensitivity parity 84 assertions / 1 block; Go 8 top-level tests / 13 including subtests. All focused checks passed, with zero failures, errors, warnings or skips. The numeric generator's `--check` reproduces the fixture byte-for-byte.

Interrupted exploratory runs are excluded from the table. One exploratory client baseline completed using an unrelated installed server inventory because its temporary archive lacked the expected companion path: 24,810 passed, 3 failed assertions, 1 error, 44 skipped. Those environment failures are not classified as pre-existing repository defects; the authoritative paired baseline replaces that run.

The full Go runs currently share these five failing top-level tests; complete counts remain pending:

| Existing test | Observed failure / assessment |
| --- | --- |
| `TestFormalGLMPublicEndpointResolveK2ClosedSelector` | Reject-non-binomial expectation conflicts with the existing supported-family path; unchanged test/implementation. |
| `TestFormalGLMRegisteredPhase19LoaderHotLoopUsesValidationContextV3` | Source-text scan extends past the target loop into another function and finds `store.contract`; unchanged source/test. |
| `TestFormalGLMRegisteredPhase19ScheduleTailK2` | Reconstructed coordinate 512 versus expected 1024 on both revisions; underlying pre-existing cause requires a separate Phase19/Phase15 audit. |
| `TestFormalGLMRegisteredPhase20JobControlHostRunsK2K3K5FromPendingIngress` | Phase21 inbound chunk out of order. Baseline failed Poisson K2/K3; after also failed binomial K2/K3. |
| `TestFormalGLMRegisteredPhase21StageTaskK2K3K5` | Stage relay rejected, with different K subcases before/after. |

All existing Go source and test files match the pristine baseline byte-for-byte. A read-only relay audit found an existing timing race: the relay signs a delivery acknowledgment before the asynchronous consumer advances `inbound.ack`, but the next chunk's admission checks that consumption cursor. The relay unit fixture manually advances it. This explains a possible timing-dependent rejection, but is not proof that every differential failure has that cause. An isolated pristine baseline binomial/K2 run passed twice; it did not reproduce the extra after-version binomial failures. Those differences remain validation uncertainty and are not hidden behind matching top-level failure counts. No existing test expectations or production paths were changed to suppress these failures.

The shared machine was heavily oversubscribed during verification: at 13:35 on 2026-09-18, load average was 78.50 on 8 logical CPUs, with 33% free memory. The six full-suite processes remained active but received substantially less CPU time. This is execution context, not proof that any particular failure is environmental. No other workloads or runtime priorities were changed.

## Open risks and limits

1. This is a contract and reference implementation. It does not supply a secure GC kernel, source producer, binding lifecycle, authorized result evidence, output-share persistence, or release injection. Artifact state strings and `result_evidence_required` never substitute for those controls.
2. Degree-256 softplus with conservative 192-bit products has unmeasured circuit cost. The public batch traversal is frozen, but no runtime, gate, OT, memory or resource-admission claim is made.
3. The error certificate applies to the real loss clamped to the same signed cap. The inherited binary64 public loss-bound formula is not an outward interval proof that its integer ceiling encloses the unclamped transcendental loss. The exact clamp still proves sensitivity. This distinction and the `exp(log(12))` boundary example are recorded in the decisions.
4. Future source preprocessing must meet the normalized-input encoding contract, keep invalid/padded records private, and round only after the complete multi-owner dot product. The test references are cleartext arithmetic oracles and make no constant-time or malicious-peer claim.
5. A final quantization boundary can differ from the existing same-owner R helper. The new contract promises bounded numerical error, not bitwise agreement with floating-point R losses.
6. Full-domain Poisson at g=18 permits at most 3,866 patients from the coordinate bound alone. Larger capacities require smaller public candidate bounds or lower output precision, and every workload must pass the signed exact-integer and layout checks.

## Concrete Step 2 proposal — binomial engine kernel

Implement only the binomial typed producer first, behind `binomial_grid_cross_v1` and operation `dp.binomial-grid-cross.v1`. Continue to exclude release integration until its separate authorization/evidence work is complete.

The frozen public ABI is the Go `CrossGridSignedContractV1` envelope in `inst/dsvert-mpc/cross_grid_contract_v1.go`: `CrossGridSpecV1`, `CrossGridArtifactV1`, `CrossGridSourceContractV1`, `CrossGridPrivateLayoutV1`, `CrossGridTranscriptV1`, and `CrossGridNumericContractV1`. The matching R entry validators are `.dsvert_dp_glm_grid_cross_contract_validate`, `_spec_validate`, `_artifact_validate`, `_source_contract_validate` and `_numeric_validate`. The signed synthetic `inst/cross-grid-v1/public_contract_fixture.json` round-trips through the Go structs with unknown nested fields and trailing JSON rejected by the interoperability test.

Kernel inputs must be server-minted bindings to that validated envelope, its source-contract/layout/profile/certificate hashes, the exact compute pair, authenticated committed source claims, and the existing session/alignment context. Client-selected private slots, coefficients, capacities, profile tables or batch boundaries are forbidden. Attach runtime source snapshot/claim-set hashes and recipient-specific commitments through the existing source transport rather than treating the static declaration as a completed binding.

Private ABI: each authority supplies its Ring128 shares of N f50 feature records and N f0 validity records for every ordered predictor, then N bounded f0 outcome records and N validity records, plus the existing private alignment shares. The circuit reconstructs values internally and validates bit/range obligations through a private fail-closed validity gate. It substitutes bounded zero inputs for invalid rows before the dot product, nonlinear evaluation or table selection, so malformed Ring128 inputs cannot invalidate the width proofs. It never opens inputs, per-row loss, complete-case count, eta, or lookup indices. Invalid rows contribute zero to every candidate. Admission/transport inconsistencies use the fixed transcript-safe boundary.

For each signed row batch of min(32,N) and candidate batch of min(8,m), in the signed row-first traversal, accumulate public coefficient products at f100, include the intercept exactly once, round once to q64, evaluate the pinned softplus polynomial with the documented Clenshaw recurrence, apply the private binary mux and validity mask, clamp, quantize to g and reduce into candidate sums. Compile against proven signed192 intermediate bounds; narrower wires may be used only with an equivalent demonstrated bound. The only outputs are independently masked additive candidate-sum shares to the two compute authorities. No plaintext coordinates leave the kernel.

Before protected input resolution, calculate AND gates, peak live wires/memory, OT bytes and signed resource limits for the actual public plan. The implementation may stream gates internally but must preserve the signed arithmetic, batch traversal, transcript shape and output ABI. If the plan cannot be executed within the measured limit, reject it without data access; do not silently change the profile or leak an observed cohort size.

Require exact equality with the Go and R integer oracles on endpoint, rounding-slack, valid/invalid/padded and saturation fixtures; randomized bounded batches; both compute directions and K=2/3/5 source ownership layouts; source/profile/beta/order/compute-pair tamper rejection before data access; a fixed transcript independent of outcomes/missingness; and authenticated output-share persistence/replay tests. Record compiled gate/OT/round/memory/runtime measurements. Define and verify typed bilateral result evidence binding session, source claims, plan, profile, ordered coordinate output and persisted shares before any later one-time release-prefix injection can be considered. Re-run the full suites and submit those concrete results for reviewer promotion.
