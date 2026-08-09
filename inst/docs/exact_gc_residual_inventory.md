# Exact arithmetic promotion boundary and residual inventory

This file is a release boundary, not a claim that every arithmetic path in the
repository is exact or disclosure-safe. The machine-readable companion is
`exact_gc_residual_inventory.json`.

## Certified primitive boundary

The exact-GC worker implements authenticated, purpose-bound two-peer
`truncate-floor`, `count-guard`, signed `clamp-count` and the purpose-specific
Ring127 `joint-dp-laplace-v2` Count operation. The first three operate over
Rings 63–4096. Checked
multiply/truncate has two exact backends: the fast Ring127/f50 crossed-OT path
when a public bound proves raw-product headroom, and a direct wide-product GC
for Rings 63–4096 when only the exactly floored output is proved to fit. Both
produce fresh additive output shares, peer-only aggregate validity and
zero-on-invalid behavior. The client is only an opaque relay between two signed
pinned peers.

The promoted Count adapter uses one purpose-specific Ring127 circuit. It
reconstructs the two additive Count shares only inside GC, verifies both
capsule-bound seed commitments, combines one private seed contribution from
each pinned peer, samples exactly one bounded discrete-Laplace/geometric
variate, adds it, and saturates the result to `[0, unit_capacity]`. The
data-free compiler accepts only the public Count policy and commitments; it
has no protected-share or private-seed input fields. Source shares and seeds
enter only per-peer worker configurations which are unlinked before readiness.
Only byte-identical durable releases signed independently by both peers are
accepted. The relay never receives a source share, seed contribution, noise
variate or final GC share, and retries/restarts replay the same materialized
release rather than drawing again.

Residues are encoded with `big.Int` into canonical little-endian containers of
64, 128, 256, 512, 1024, 2048 or 4096 bits. Unused high bits must be zero. The
planner accepts canonical public operand bounds up to 1200 decimal digits and
chooses the minimum signed ring that proves operand and exactly truncated-output
headroom. Direct-multiplication chunks are not fixed: they decrease from 64 at
Ring512 to 16 at Ring1024, 4 at Ring2048 and 1 at Ring4096 under the published
typed-input and quadratic multiplication-bit budgets. These are per-circuit
resource bounds, not request quotas and not dependent on prior use.

The adversary claim remains **two pinned, semi-honest, non-colluding peers**.
KOS hardens OT consistency with abort; it does not make the complete Yao
protocol malicious-secure. Pinned peers remove the analyst/relay from the
trusted computing base, but do not protect against peer collusion.

Checked multiplication is deliberately **not promoted as a generic remote
primitive**. The cross-contingency cell-product, GLM weighted-residual and
binomial-softplus producers mint one-shot opaque handles bound to method,
session, invocation/snapshot, peer set, shape, numeric policy, source digests,
destination CAS, arithmetic plan and purpose; the remote claim presents only
that handle. Other existing workloads still depend on the legacy
`exactGCVecmulBindInputsDS`, which lets the analyst name server session slots.
That endpoint cannot be removed without breaking those methods until each
producer is migrated. `checked_mul_truncate`, runtime bound, overflow and
workload E2E capability flags therefore remain false. `dynamic_ring_fallback`
is true for the certified exact primitive: it never denotes a fallback to
legacy local truncation or plaintext arithmetic.

The `chisq.cross.cell-products` workload is numerically certified for its
actual admitted domain: aligned finite one-hot inputs, Ring63/f20,
`n <= 2147483647`, and `K*L <= 4096`. Each operand is exactly 0 or `2^20`, the
checked direct-wide circuit enforces that bound and exact floor truncation, and
the largest possible accumulated count is below `2^51`; therefore neither the
product nor its local linear reduction can wrap Ring63. The exact count vector
is not a release. The former positive-cell authorization bit is data-dependent
and could be used as an adaptive relay oracle, so the production client does
not execute it. Counts remain sealed pending a fixed-shape joint-DP
clamp/noise/opening whose transcript and error state do not depend on that bit;
the statistical method therefore remains provisional.

## Fail behavior

There is no fallback from an exact operation to Beaver/local truncation, DCF or
plaintext reconstruction. Missing DSI responses retry the identical
offset-addressed exchange until the public wall-clock deadline. Present
malformed responses, authentication/context mismatches, KOS failures, bound
failures and permanent timeout abort the operation. Cleanup removes spools,
hidden output shares and any lone locally completed destination share; nothing
is returned as an exact result through the relay.

## Residual non-exact or non-promoted arithmetic

| Runtime command/path | Residual behavior | Known R/client consumers | Status |
|---|---|---|---|
| `k2-beaver-vecmul-round2` | local/asymmetric fixed-point truncation unless the internal exact-defer flag is used | `beaverVecmulDS.R`, Ring63/Ring127 legacy branches, `dsvertLMMGramDS.R` | legacy, not promoted |
| `k2-full-iter-r3` | local truncation in the monolithic iteration handler | `k2InputSharingDS.R`, legacy GLM paths | legacy, not promoted |
| `k2-ring127-local-scale-share` | local Ring127 scaling/truncation | no registered public R endpoint; retained runtime compatibility command | internal, not promoted |
| `k2-cmp-gen`, `k2-cmp-round1`, `k2-cmp-round2` | DCF comparison and coordinator-generated material | `k2CmpDS.R`, other legacy comparison paths | legacy, not promoted |
| `k2-wide-spline-full` | DCF comparison plus legacy Beaver/local truncation | `k2WideSplineFullDS.R`, older Ring63 spline workflows | legacy, not promoted |
| `k2_exp127.go`, `k2_recip127.go`, `k2_softplus127.go`, `k2_log_shift127.go`, `k2_log_shift_wide127.go`, `k2_recip127_cheb.go`, `k2_sigmoid127.go`, `k2_secure_exp.go` | plaintext/reference helpers call local `TruncMulSigned`; public coefficient getters do not process secret shares | reference tests and public coefficient commands | reference/internal, not a promoted secret path |

Exact `compare-signed` is implemented and property-tested in the circuit core,
but has no producer-bound DSI adapter and is not advertised as an available
operation. Nonlinear polynomial accuracy is a separate numerical approximation
question: any future promoted implementation may approximate the nonlinear
function, but its comparisons and fixed-point truncations must use certified
exact primitives.

The missing GLM E2E adapter is not one client-side dispatch branch. The
existing GLM state and helper commands encode only Ring63/Ring127 records;
`k2-compute-eta-fp` locally truncates public-beta products;
`k2-full-iter-r3` locally truncates the accumulated gradient matvec; and most
sigmoid/exp/reciprocal products still reach exact GC through the legacy
analyst-selected slot binder rather than a producer-minted manifest. A real
Ring63-through-Ring4096 fallback therefore requires a variable-width input and
session adapter, producer-bound exact eta/nonlinear/matvec stages, checked
accumulator bounds, and operation-complete runtime plus estimator-error
attestation. Until that whole path has a plaintext-reference E2E oracle, the
client must return `client_backend_adapter_unavailable`; routing the current
GLM shares into the standalone exact primitive would be an incomplete and
incorrect promotion.

## Precision and Ring127 failure

Exact standalone truncation and the checked-multiplication core support
`0 <= frac_bits < ring_bits` through Ring4096 (`max_frac_bits=4095` at the
primitive boundary). Before sharing, the planner chooses the smallest ring that
proves both operand and truncated-output headroom. For already-created Ring127
shares it never lifts or reinterprets them: it uses the fast Ring127/f50 OT path
when the raw product fits, otherwise the direct wide-product GC while returning
Ring127 shares if the truncated output fits. If that proof fails, the operation
fails closed and the producer must create fresh shares under a wider planned
ring. Transport unavailability retries the identical offset-addressed request;
cryptographic, context or bound failures abort rather than switching to a
different arithmetic path.

The published exact domain is `2^4096`, with public decimal operand fields
limited to 1200 digits. A valid operand/output-bound combination that cannot fit
any signed ring through Ring4096 raises the typed condition
`numeric_backend_unrepresentable`; a shape outside the published typed-input or
multiplication-work budget is an explicit infrastructure/resource failure. It
is never reported as a Ring127 result and never silently wraps or downgrades.
Tests cover canonical encoding at Ring4096, two-peer Ring4096 signed comparison
and truncation, and a complete two-worker checked multiplication at Ring513.
