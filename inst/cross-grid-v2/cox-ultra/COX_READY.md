# Cox fleet-ready — 2026-09-20

All five integration boundaries are closed. Cox Breslow finite-grid authenticated
Synopsis release is enabled for the N<=400 cluster scope. Four epsilon-8 fleet
jobs are emitted in `integrator-evidence/RELEASE_MANIFEST.jsonl`. No heavy fleet
release was launched. Fleet capacity measurement and promotion remain pending;
the jobs retain `promoted=false` and the method inventory retains quarantine.

The committed source pair is:

- dsVert: `c97cd193c06dbae695792b4a03644c05fa733f8f`
- dsVertClient: `28be3cd6fea312d8f1c2442c810b453ad81080ce`

The source pair is pinned in every Cox row and in the Cox-specific preparation
command in `RELEASE_MANIFEST_STATUS.json`. A subsequent evidence-only commit
archives this report without changing executable source. The shared-root
`COX_READY.md` records that archive commit.

## Closed boundaries

1. Fresh publication and durable cold replay collect signed Cox evidence using
   authenticated pins, designated authorities, capacity, grid bits, adjacency,
   and signed schema. The result context retains it. Cold replay reconstructs
   compilation without re-reading Claims or invoking the producer/sampler.
2. Cox certificate descriptors require their signed evidence. Offline verification
   reconstructs that evidence, retains common-lattice coordinate bounds, and
   dispatches the Cox finite-grid moment. The dedicated release helper completes
   the authenticated Synopsis flow. An actual released certificate verifies in
   a fresh R process with independently retained trusted pins and zero peer calls;
   removing Cox evidence is rejected.
3. Client/server runtime flags are enabled and N<=400 is enforced. Generic grid
   discovery admits Cox; legacy GLM result injection explicitly excludes it.
   Dedicated Cox injection, private validity and sampling remain in control.
   Mixed Cox/GLM artifacts are rejected; time values never enter a GLM outcome
   block. The Cox staged transport operation has strict Ring128/scale/purpose
   validation.
4. The DSLite harness pins the time/event owner as the actual garbler before
   signing, enforces the scoped fixture, and exercises native recovery, the
   independent integer oracle, authenticated cold readers and tamper rejection.
   All five recovery boundaries passed: prepared, bilateral_prepare,
   unilateral_commit, committed and unilateral. PREPARE/PREPARE and
   PREPARE/COMMIT states were observed in actual native workers.
5. Two fresh signed small source -> native -> joint-DP proofs passed before the
   family-only generator emitted Cox's four fleet jobs. All 20 other release
   rows remain byte-for-byte unchanged. The selection manifest was not rewritten.

## Proof and suite evidence

Evidence in this directory is a compact copy of the original shared-root
`integrator-evidence/cox-ultra/` records; `server-suites/` copies
`integrator-evidence/cox-ultra-runtime/`. [ARCHIVE_INDEX.json](ARCHIVE_INDEX.json)
maps every retained original path and SHA256. Full immutable source snapshots
and private synthetic durable stores remain outside the archive.

| Signed proof | Fixture | End-to-end seconds | Serialized RPC bytes | Result |
| --- | --- | ---: | ---: | --- |
| [Baseline](proof-r3/logs/metrics.json) | N4, P5, K2, grid2, epsilon8 | 459.721 | 57,636,070 | exit 0, loss gap 0 |
| [Recovery](proof-r4-recovery/logs/metrics.json) | N4, P5, K2, grid2, epsilon8 | 859.279 | 115,504,697 | exit 0, loss gap 0 |

Both proof logs contain exact integer-oracle equality, sticky replay, tamper
rejection, direct cold lifecycle verification and
`DSLITE_COX_COLD_EXPORTED_API_EQUAL_AUTHENTICATED`. Recovery additionally records
`DSLITE_COX_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED`.
These small proofs establish integration and recovery, not N400 fleet capacity.

The [offline certificate record](baseline-offline-verification.json) records
caller-anchored authenticity, integrity validity, zero peer calls, unanchored
status without caller pins, and rejection of missing Cox evidence. Its public
[certificate](baseline-certificate.json) and independent
[trusted pins](baseline-trusted-pins.json) are retained.

| Focused suite | Cases | Passed assertions / tests |
| --- | ---: | ---: |
| Server Cox + signed schema + GLM contract | 56 | 3,328 assertions |
| Client Cox | 24 | 1,002 assertions |
| Client transport | 32 | 273 assertions |
| Client registry/inventory | 18 | 1,105 assertions |
| Adjacent LMM publication regression | — | 177 assertions |
| Native Go Cox | 12 top-level | 43 tests including subtests |
| Manifest generator | 4 | 4 tests |

All passed, with zero failures, errors, warnings or skips in the R suites and
zero failed/skipped native tests. The R total is 5,885 assertions; publication
and staged Cox assertions already included in the client total are not counted
twice. See [SUITE_COUNTS.json](SUITE_COUNTS.json), CSV results and logs.

The server suite includes the real K2/K3/K5 workload manifest -> source-contract
-> Cox source-context path (82 assertions), using signed schemas and actual
catalog/transport validators. Actual K2/K3/K5 native handoffs also passed.

Both signed-proof snapshots match the committed pair across 2,078 executable
and harness dependencies: [SOURCE_PROOF_EQUIVALENCE.json](SOURCE_PROOF_EQUIVALENCE.json).
Snapshot checkout HEADs predate the final source commits; the audit binds their
actual bytes explicitly rather than relabeling the original provenance.

Independent N400/P5/grid2/epsilon8 oracle-only K2/K3/K5 runs all passed and
produced commitment
`ba5d77ddffabca8ce5b9be5f516aee3662b90b6e44a2ef0bfb886da6c8bb950d`.
[ORACLE_SOURCE_EQUIVALENCE.json](ORACLE_SOURCE_EQUIVALENCE.json) binds the retained
results to the committed pair. K5 dependency bytes match exactly; K2/K3 differ
only in the explicitly reviewed Cox transport registration unused by oracle-only
execution. Bound copies retain original metrics hashes and source attribution.
These runs did not invoke a real fleet release or measure capacity.

## Emitted jobs

| Job ID | Owners | Mode | Fixture |
| --- | ---: | --- | --- |
| cox-e8-k2-i01-baseline | 2 | baseline / capacity measurement | N400, P5, grid2 |
| cox-e8-k3-i01-baseline | 3 | baseline | N400, P5, grid2 |
| cox-e8-k5-i01-baseline | 5 | baseline | N400, P5, grid2 |
| cox-e8-k2-i01-recovery | 2 | bilateral and unilateral recovery | N400, P5, grid2 |

All jobs require an authenticated real release, cold replay and tamper checks;
stdin is detached with `</dev/null`. Capacity limits remain 256,000,000,000 bytes
and 28,800 seconds. Only K2 recovery enables interruption. The final release
manifest SHA256 is
`39337a1ffd1911cc0a5cee4375739ecbf22ea9036af92956c42a820265dca3f2`.
See [MANIFEST_VALIDATION.json](MANIFEST_VALIDATION.json) and the independent
[FINAL_MANIFEST_REVIEW.md](FINAL_MANIFEST_REVIEW.md). The global status remains
`fleet_ready=false` because other pending families retain their own gates;
all four Cox rows are `fleet_ready=true`.

## Boundary commits

| Repository | Commit | Change |
| --- | --- | --- |
| client | `1f81bfee402631e2ad39d404c19458e2857999df` | Publication evidence and cold replay |
| client | `f4e99d09cf75049a15e7cf6c54763226053c4a06` | Signed certificates and offline reconstruction |
| client | `f011cc40158a9fa43f2a837ab8b2581b569e4851` | Exported API and scoped inventory |
| client | `37f19caca4a75347bf94f08fad53aa06659556aa` | Authenticated staged transport registration |
| client | `28be3cd6fea312d8f1c2442c810b453ad81080ce` | Authenticated release and 400-row admission |
| server | `a477cc6f0f7c7568af615ea5b026a6f9813abef9` | Runtime, injection isolation and strict bind framing |
| server | `84d8487dbda9f4e4cfdf6d7e2abf273ccb32b8cf` | Scoped family-only manifest generation |
| server | `c97cd193c06dbae695792b4a03644c05fa733f8f` | Native recovery and cold DSLite proof harness |

The coherent edits left by the paused cycle were reviewed and incorporated.
Earlier smoke attempts exposed assembly gaps in private-layout enablement,
bind wire framing and the client operation allowlist; all are covered by the
final green tests/proofs. A stale test-only oracle binary was rebuilt from
unchanged Go source, and the harness now verifies the required test is present.
Original failed-attempt records remain under `integrator-evidence/cox-ultra/`;
they are superseded by the two complete green proofs.

Exact arithmetic, rounding, caps, epsilon/delta, native production kernels and
the staged executor are unchanged. Shared optional-Gaussian handling and all
GEE files/branches remain unchanged. Frozen LMM/GLMM/pod4 jobs were not touched.
No push, tag or thesis edit was performed. See [SCOPE_CHECK.json](SCOPE_CHECK.json).
