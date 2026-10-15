# v3impl02 — Phase B1 implementation report

2026-10-15. B1 implementation and targeted synthetic validation are complete;
maintainer Claude-session milestone review is pending. No MPC/circuits, remote
R/DSI lifecycle, inference engine or live demonstration was implemented or run.

The maintainer's `claude-session-review-phaseA.md` was read first. No `claude`
CLI was invoked. The design remains byte-identical, SHA256
`f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`.
Only the two v3 worktrees were edited, on `feature/v3-dp-irls`, based on server
`f2b919e13932cf50b9be1aba63e983fc606498af` and client
`5245af5efffc762cd8b0f6f806a1d1bc8a9b440c`. Both packages are `1.5.0.9000`, with
development NEWS entries. Both working trees are clean. No pushes or GitHub
writes occurred. Every new commit ends with:
`Claude-Session: https://claude.ai/code/session_014vmGJDh1R1RPiYA7iGUK1G`.

Runtime commands sourced `/workspace/dsflower/.tmp/v3/env.sh`. `gmp 0.7-5.1` was
installed into `.tmp/v3/rlib`. The environment now also uses its own GOPATH and
GOMODCACHE (the existing module cache was copied first), alongside its separate
GOCACHE. The inherited toolchain and baseline R libraries are reused for reads;
the only binary build target was `.tmp/v3/bin/dsvert-mpc`. The 1.4.2 worktree
files and `.tmp/vertcor/bin` were not modified.

Commits, in order:

**v3-dsVert**

| Commit | Change |
|---|---|
| `224856c` | Start isolated DP-IRLS development version |
| `8dda79c` | Add bounded exact rational IRLS update and shared arithmetic fixtures |
| `3320144` | Add signed IRLS contract identities and exact path accounting |
| `58d6b5f` | Cover ten-coefficient and 256-bit rational IRLS updates |
| `62a5607` | Use exact curvature lookup and bound certificate admission early |
| `bc632cc` | Test retained curvature epochs and concurrent successor forks |
| `f370c75` | Reserve and dual-sign deterministic IRLS successors durably |
| `f37ffdf` | Validate additive IRLS formula and coefficient declarations |
| `ffa2f7b` | Document B1 contract schema and durable state boundary |

**v3-dsVertClient**

| Commit | Change |
|---|---|
| `66487ef` | Start isolated DP-IRLS verifier development version |
| `994954b` | Add independent exact DP IRLS arithmetic verifier |
| `0a1450a` | Add shared exact IRLS fixtures and cross-language checks |
| `d7085ab` | Validate signed IRLS contracts with client trust anchors |
| `6a9d44a` | Verify signed IRLS chains with independent public updates |

What exists now:

| File | Main functions and behavior |
|---|---|
| Server `R/dpIRLSContract.R` | `.dsvert_dp_irls_contract_normalize`, `_contract_validate`, `_estimand_formula`, `_certificate_check`: all seven required groups, exact rational normalization, strict signed form, explicit additive formula grammar, complete frozen epochs, external pins/unanimous Ed25519 signatures, public numeric ceilings and fail-closed consistency checks. |
| Same contract file | `_root`, `_start_digest`, `_stage_id`, `_lane_id`, `_payload_digest`: root binds every signed semantic field and version; optimizer/audit stages and g/H children; payload digest covers ordered g then H or the exact signed prior-H reference. |
| Same contract file | `_accounting`: exact lane/stage/path epsilon, pilot and auxiliary allocations, alpha checks, reject under/over-allocation, deduplicated observations, partial-lane records and full reserved epsilon without refunds. |
| Server `inst/dsvert-mpc/dp_irls_path.go` | `DPIRLSCanonicalUpdate`, `irlsValidate`, `irlsPSD`, `irlsShift`, `irlsSolve`, `irlsRound`; CLI `dsvert-mpc dp-irls-update` reads/writes canonical JSON. Translation, smallest diagonal shift, fraction-free elimination, exact solve, damping then trust, projection and nearest-even lattice rounding. |
| Server `R/dpIRLSState.R` | `_store_create`, `_successor_prepare`, `_successor_commit`, `_successor_accounting`, `_stage_body`, `_go_update`: independent authority recomputation, durable `(root,t)` reservations, matching dual signatures, frozen chain/epoch checks and retained replay. SQLite FULL synchronization, transactions and process locks. |
| Client `R/dp_irls_verify.R` | `.dsvert_dp_irls_verify_update`, `_verify_update_json`, `_numeric_limits`: independent R/gmp implementation; no Go or server calls. |
| Client `R/dp_irls_contract.R`, `R/dp_irls_chain.R` | Mirrored wire/schema validation using existing client trust helpers; `.dsvert_dp_irls_verify_chain` recomputes each update with R, checks exact signed bytes and latest-H reuse, and reports endpoint and accounting. |
| Both repositories' fixture directories | Shared canonical arithmetic JSONL and two signed synthetic three-stage chain fixtures (full refresh and score-only reuse), including validly dual-signed false arithmetic for rejection. |
| Server `inst/docs/dp_irls_{arithmetic,contract}_v1.md`, `dp_irls_b1_state.md` | Canonical ABI, static resource proof, schema, public/internal API and storage/recovery assumptions. |
| Both `tools/test-dp-irls-b1.R`; client `tools/check-dp-irls-byte-agreement.R` | Small reproducible targeted validation drivers. |

The previous pivot in fraction-free PSD elimination starts at one and is updated
only after a successful positive pivot. Skipping a zero residual row leaves it
unchanged. The solve uses fixed-order Bareiss elimination and exact determinant
back substitution. The ABI derives `k_max` from finalizer bounds, derives a
bounded common denominator, and enforces `L=p*w+ceil((p/2)*log2(p))+2` and exactly
`8L+16w+64` temporary bits, with integer-only ceiling calculations and checked
intermediates. Contract admission rejects invalid bounds before heavy work.

Verification commands (run from the indicated worktree after sourcing the env;
each uses `nice -n 10 timeout 14m`, with no full suite):

```sh
# Server worktree; only the three new B1 R test files.
nice -n 10 timeout 14m Rscript tools/test-dp-irls-b1.R

# Server inst/dsvert-mpc; new arithmetic plus existing affected CLI/runtime tests.
nice -n 10 timeout 14m go test . \
  -run '^(TestDPIRLS|TestRuntimeCapabilitiesContract$|TestRuntimeCapabilitiesJSONIsDeterministic$|TestCLIInputFailuresReturnOnlyCleanJSON$)' \
  -count=1 -json

# Build target, from server inst/dsvert-mpc.
nice -n 10 timeout 14m go build -o /workspace/dsflower/.tmp/v3/bin/dsvert-mpc .

# Client worktree; only the two new B1 R test files.
nice -n 10 timeout 14m Rscript tools/test-dp-irls-b1.R
nice -n 10 timeout 14m Rscript tools/check-dp-irls-byte-agreement.R

# Reproducible arithmetic fixture generation, client worktree.
nice -n 10 timeout 14m Rscript tools/generate-dp-irls-fixtures.R
```

| Target | Exact result |
|---|---|
| Server contract | 8 test blocks, 473 assertions |
| Server state/crash | 2 test blocks, 24 assertions |
| Server adversarial state | 3 test blocks, 21 assertions |
| Server R total | 13 test blocks, 518 assertions |
| Client arithmetic | 4 test blocks, 312 assertions |
| Client chain | 3 test blocks, 32 assertions |
| Client R total | 7 test blocks, 344 assertions |
| Go targeted package | 319 tests/subtests: 305 arithmetic and 14 existing CLI/runtime compatibility checks; package runtime 11.801 seconds |
| Full built CLI versus independent R | **269/269 byte-identical; zero mismatches** |

All counts above have zero failures, errors, warnings and skips. Go's count
includes named parent/subtests, not 319 independent fixture datasets. The shared
set contains **29 known answers + 240 seeded random fixtures**, covering positive
definite/semidefinite/zero-row/negative-pivot matrices, shift bracketing and k_max,
negative coordinates, damping/trust/box/rounding ties, p=10 dense matrices and
256-bit rational solves. Go additionally covers 22 malformed/resource rejection
cases and nine local known-answer subtests.

Contract tests delete every required named field independently and exercise
normalization, inconsistent fields/formulas, external pins/signatures, epoch
closure, stage/lane identity, exact budgets, pilot/auxiliary composition and
partial observations. State tests reject alternate beta, predecessor, forks,
stale or tampered H references, validly re-signed mid-path epochs, altered pins
and signatures. Concurrent fork requests yield exactly one durable winner.
Crash tests retain byte-identical PREPARE/COMMIT records, including one-authority
commit recovery. Deleted/corrupt records and missing stores fail closed. Client
verification rejects incorrect arithmetic despite two valid signatures and still
works with both binary environment variables pointing to nonexistent paths.

Final binary SHA256:
`c6459749c1bad5c0248e8da4efa91157f0374a168f4e02d49e6a617c2c582b83`.
Identical server/client arithmetic-fixture SHA256:
`598a001cfa247b3287d8dfeb5c6901f387d390c249157a5c564a6f9c8a669ed7`.
Logs are `.tmp/v3/B1-server-tests.log`, `B1-client-tests.log`,
`B1-byte-agreement.log` and `go-irls-package-tests.jsonl`.

Design clarifications and conservative restrictions:

* The mathematical update follows §4. Canonical sorted JSON and `{d,n}` rational
  spelling settle the previously unspecified wire encoding; no old artifact
  bytes or domains changed. Contract flags use integer strings; derived update
  flags use canonical JSON booleans.
* The initial contract supports Tier-1 families, split lanes and pure v4 Laplace
  allocation only. A finite protected validity/conversion law must explicitly
  add its implementation delta before producer admission. Statistical tail
  allowances remain separate. Effective g/H lattice units combine scale and
  quantum; signed integer caps determine lane calibration.
* B1's formula grammar is additive only, with declared contrast expansion and
  exact offset/exposure semantics. It rejects interactions/transforms/functions
  it cannot validate without a later compiler. This closes a consistency gap
  rather than interpreting arbitrary R formula code.
* The public arithmetic engine has hard ceilings p<=128, input_bits<=4096,
  temporary_bits<=5,000,000, input<=4 MiB and integer strings<=1500 characters.
  These are not production shape certificates. The fixtures are explicitly
  synthetic; score/link/approximation/compiler identifiers are signed metadata,
  not evidence that a protected producer is correct or available.
* Existing analysis/registry identifiers and canonical helpers, Synopsis
  catalog pinset/provenance normalization, and Ed25519 helpers are reused.
  Actual catalog selector registration and R/DSI exposure remain B3/B4, preserving
  existing mechanism semantics. Client wire validation mirrors the schema;
  arithmetic is independently implemented and tested.
* Durable state assumes private local storage. Complete privileged rollback of
  a database and its entire directory requires an external monotonic witness;
  B1 does not claim that guarantee. Missing/corrupt state has no automatic reset.
  Parent/child MPC publication barriers and production recovery belong to B4.
* Pilot history is authenticated as a unanimous signed digest/beta/composition
  declaration; opening its historical artifact is a later lifecycle adapter.
  Auxiliary budgets are fully reserved and accounted exactly, but no auxiliary
  producer is implemented. Client `chain_complete` covers optimizer/audit stages;
  `complete` stays false for contracts awaiting auxiliary evidence.

Open B2 work/questions: bind the authenticated public beta/stage ABI to one fused
protected score/H evaluation; certify actual score and curvature definitions,
protected source/intermediate ranges, approximation errors, person aggregation,
rounding sensitivity, translation/headroom and validity law; freeze smoke
lattices/scales/caps and the real numeric profile before measurement. Admit p=3
first; p=5/p=10 need their own protected shape/cost evidence. Keep g/H lanes tied
to one committed evaluation and retain fixed semantic noise identities.

The binding showcase profile and refusal pre-check are retained in
`B1_QUESTIONS.md`: choose the smallest n with at least 80% public-simulation
acceptance at epsilon=8,p=3 before any live run; run the approximately 200-dataset
smoke/showcase pre-check and accepted-fit coverage before B5. B1 neither chose n
without that simulator nor ran a demo. B3's week-2 gate and its stop-on-failure
rule remain unchanged. This report is for the maintainer's Claude session;
automated implementation checks are not its milestone approval.
