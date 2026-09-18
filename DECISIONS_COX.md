# Cox decisions

## 2026-09-18 resumed
- Apply DECISION_DAY1_ARITHMETIC_ROUTE.md and REVIEW_NOTE_PRIMITIVE.md. Frozen f50/f100 source encoding is retained; one rounding after the two-owner sum produces q16 eta. Nonlinearities use pinned 64-piece linear profiles, 32-bit scalar operands, q20 outputs. Prefix and cohort sums use exact wider integers.
- Minimize negative Breslow partial log likelihood (the negative of the user equation), with one whole-cohort ties-even quantization and clamp. No per-row independent-loss sensitivity claim: changing one record changes other risk sets. Conservative whole-coordinate range bounds cover both adjacencies.
- Chunk schedule per candidate: prepare at most 32 rows, Beneš tiles of at most 64 switches, forward prefix tiles of at most 32 padded rows, backward tie-denominator propagation and loss tiles in reverse order, finalize. Every lane receives a fresh mask. Carry W/H/L and private validity must persist across chunks. Outcome owner supplies private descending-time routing/tie ends; input order remains PSI order.
- Registration is an internal integration boundary. No RPC or production plaintext fallback. Tests alone cannot promote the signed states; source/lifecycle wiring remains explicitly fail closed until the separate integration session connects authenticated joint DP publication.
- Keep all work additive except the single export(dp_cox_grid) client registration. Preserve same-owner and generation-one code.

## 2026-09-18 resumed — compiled verification
- Pinned MPCL lower-bound literals must be emitted as `-int64(magnitude)` (as the primitive already does for int192). `int64(-magnitude)` incorrectly rejected eta=0 in a compiled comparison. Added permanent predicate, endpoint, slack, rounding and chunk-carry tests; no compiler/shared primitive edits.
- Use the compiler's standard dead-gate pruning and array multiplication options in a family-local bounded wrapper. Public coefficient-bit decision diagrams share identical table subfunctions. Exact same profile constants, domains and rounding remain pinned; no external Boolean optimizer or other session's uncommitted code is incorporated. Scalar costs including normalization are 1514/1486 non-XOR gates (exp/log), below 2000. All switches remain the approved Beneš geometry.
- Narrow log mantissa to 21 bits only after the right-normalization proof establishes m<2^21. Scalar operands stay <=32 bits. Source/profile identities and a compiler-profile string are signed; existing runner caps remain unchanged.
- Stream schedule hashing and reconstruct public switch geometry rather than serializing repeated switch arrays for every candidate. Verify actual supplied endpoints/control indices before hashing; public shape, candidate, ordinal and predecessor receipts remain bound.
- Artifacts report contract-only/pending state while production is disabled. The requested final state strings are pinned in required_result_states. This follows DESIGN_COX section 9: a signed template must not claim completed materialization before lifecycle gates pass.
- DSLite uses PUBLIC synthetic fixtures and a test-tagged Go evaluator only. Its two independent reference-noise contributions exercise utility/postprocessing, not the production exact sampler or sticky release proof. The test report explicitly says production_protocol=false. No test helper is exported or installed as an R production function.

## 2026-09-18 resumed — public-surface gate
The first full client R check found that exporting the disabled entry adds a
name outside the exact 97-analysis/13-non-inference inventory. Registering it
requires coordinated inventory and maturity-registry changes (and their fixed
count/status tests), which belong with release integration. Removed our own
NAMESPACE export; the implemented `dp_cox_grid` entry is now returned by
`.dsvert_dp_cox_grid_cross_client_register()$entry` and remains namespace-internal.
No pre-existing tests or registry tables were modified or bypassed. The complete
existing inventory suite and the Cox contract suite pass together after this
change (39 Cox expectations). INTEGRATION_COX.md lists the exact public-export
registration that remains. This supersedes the initial single-export decision;
the final diff contains only new family files in both repositories.

## 2026-09-18 resumed — revised clauses 4 and 5

Both repositories were clean. The prior whole-envelope gate is superseded.
Restructuring uses one packed Ring128-share permutation per release, local
Ring64 prefix/loss sums, OT private tie selection, scalar-only profile batches,
and the topology-bound compact framing from fetched step-2 commit 0006f1a.
Private event counts require padded log batches. Authentication/fusion remains
the step-2 integration boundary; no plaintext or production fallback is added.

The OT switch sender retains -r and sends (r, r + right - left) with checked
COT; the outcome owner selects its private routing bit and locally routes its
own shares. Both update the two outputs by +/- their selected-difference share.
The original Beneš topology/control numbering is unchanged; disjoint switches
are batched in public layers. All J joined f100 dots, live and event are packed
in one row, so there is exactly one permutation invocation per release.

A reverse doubling scan selects the last prefix in each private time tie using
OT on shares; ties spanning chunks are not opened or approximated. Logs run on
ALL public padded slots, with private live/event masking. Running only a public
number of actual events would disclose that number. Prefix and loss additions
use local modulo-2^64 arithmetic with the existing no-wrap certificate.

The initial encrypted regression exposed a legacy helper named
uint128FromLabel that silently truncates to Ring127. The additive Cox decoder
reads all 128 label bits directly; the shared helper is untouched. Exp consumes
the frozen Ring128 ABI but remasks only Ring64 outputs (public-zero upper words),
which preserves the exact integer result and avoids unnecessary mask gates.

Within one authenticated connection, reuse the pinned library's explicitly
supported shared COT mode: one checked extension for GC input transfer and a
separate, opposite-role checked extension for permutation/tie selection. The
library advances cipher.Stream PRGs across calls and generates fresh correlation
checks/hash seeds. Never reset these streams, persist/reuse their outputs, share
one object between roles, or reuse a session ID on retry. This preserves checked
OT while avoiding a new 128-base-OT setup for every tiny chunk. The mode is signed
in both the Go plan and R transcript. Local encrypted equality still passes;
onlinearity kernels including ABI checks/remasking cost 146975/32=4592.97
non-XOR per exp and 69567/32=2173.97 per log at the maximal row tile.

The pod advertises CPUs 0..95 but its actual cgroup-v1 quota is 765000/100000,
**7.65 CPU cores**, shared with other work. Limit the final envelope matrix to two
concurrent processes (GOMAXPROCS=2 each), record this in host evidence, and measure
elapsed time honestly. The nine initial exploratory jobs were stopped before any
completed envelope and archived separately; they are not gate evidence.
