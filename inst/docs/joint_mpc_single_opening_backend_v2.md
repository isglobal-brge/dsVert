# Joint MPC single-opening backend: v2 status and v3 requirements

## Release status

`joint_mpc_single_opening_v1` remains unavailable. The v1 opening token and
the v2 backend preflight token both contain `capability_available = false`.
There is no DS endpoint that returns a seed, exact aggregate, noise sample, or
individual result share.

The control plane now has an authenticated, durable private result spool and
cross-signed result/delivery receipts. Exact payload bytes are committed to a
canonical query and opening transcript before a delivery token can exist;
retries and lost acknowledgements therefore cannot select a fresh payload.
Result receipt v2 uses a domain-separated HMAC-SHA256 commitment under the
private persistent ledger key, not an enumerable public payload hash. The
relay can therefore bind and replay a low-entropy result share without gaining
an offline dictionary predicate; v1 result receipts fail closed.
This is control-plane foundation only: it is not yet bound to the v2 worker or
to a DSI delivery adapter, and no payload-returning capability is enabled.

The Go runtime now contains a real two-party exact-GC primitive for a bounded
Ring63 or Ring127 vector. The circuit:

1. receives one private additive statistic share and one private 256-bit seed
   from each pinned peer;
2. verifies `SHA-256(commitment_context || seed_raw)` for both seeds;
3. performs RFC 5869 extract-and-expand with HMAC-SHA-256 over the ordered
   seeds and the transcript hash;
4. expands the joint key with AES-128-CTR (the exact-GC stack already has a
   128-bit security level);
5. samples one fixed-shape global noise vector as the difference of two
   capped geometric variables per coordinate;
6. reconstructs the bounded aggregate, adds and clamps the result inside the
   circuit, and returns only deterministic additive output shares plus a
   masked validity bit.

The authenticated exact-GC record layer, KOS-checked OT, pinned identities,
purpose digest, fixed input shape, circuit-source digest, and spool result
before `done` are all retained. There is no plaintext or Beaver fallback for
this exact-GC operation. A separate, explicitly unpromoted independent-full-
draw convolution backend exists as a lower-utility contingency design; see
`joint_dp_independent_full_draw_convolution.md`. It is absent from the runtime
capability manifest and cannot activate this exact-GC capability.

Packaged runtimes carry only the required AES-128, HMAC-SHA256, and SHA-256
MPCL assets from the pinned dependency revision. On startup they verify each
asset's decompressed size and SHA-256 digest and expand it with private
directory/file permissions. The exact `MkdirTemp` root is held as an internal
lease only while the compiler loads the assets; `MPCLDIR` is then restored and
the root is removed on both success and error. Real two-OS-process
packaged-runtime tests pass for both Ring63 and Ring127 without a developer
MPCL checkout and assert that no `dsvert-mpcl-*` directory survives.

Ring127 failure never authorises Ring63 substitution, a locally sampled noise
fallback, or a new random draw. A retry must reuse the same signed request,
transcript, sticky seeds, circuit contract, and deterministic output masks.
Only the encrypted transport-attempt domain changes, which prevents AEAD nonce
reuse without changing the logical query or DP draw. Before retry, the worker
rejects or removes stale transcript and terminal artifacts; a failure removes
`result.json`, `done`, and `ready` before publishing a typed failure marker.
The result remains durable-pending until the same computation succeeds; if a
peer or both exact implementations are unavailable, the request fails before
any share is delivered. This preserves validity and avoids abort-driven
resampling bias, but cannot promise liveness when a pinned peer or its host is
down.

The public failure classes are deliberately coarse:

- `infrastructure_unavailable` and `numeric_backend_unavailable` may retry the
  same logical operation under the no-reroll contract;
- `bound_exceeded` and `non_identifiable` are non-retryable until a new,
  independently authorised query changes the public contract.

For checked fixed-point multiplication, lack of raw Ring127 product headroom
is handled at planning time by the exact `direct-wide` circuit (a 256-bit raw
product followed by exact division back into Ring127). This is not a runtime
fallback and does not alter the declared ring. If neither the certified
Ring127 OT path nor that exact wide path is available, the result is
`numeric_backend_unavailable`, never an approximate or Ring63 answer.

This is a tested primitive, not an enabled biomedical release path.

## Exact rounding contract

`truncate-floor` remains a distinct exact operation. For denominator
`D=2^f`, it returns the mathematical floor for positive and negative values;
it is not truncation toward zero. Its error in output ULPs is `-r/D` for
residue `r in [0,D-1]`, so its maximum absolute error is `(D-1)/D < 1` ULP and
its exact mean error under uniform residues is `-(D-1)/(2D)` ULP.

The core also implements the separate, currently unpromoted operation
`truncate-nearest-ties-to-even`. Its maximum absolute error is exactly `0.5`
ULP. Over all residues and two consecutive quotient parities its exact mean
error is zero, including ties and negative values. Exhaustive small-ring tests
and Ring63/Ring127/Ring256/Ring512 boundary tests compare the generated circuit
against an independent multiprecision reference; a real Ring127 protocol test
covers positive and negative half-way cases and both signed endpoints.

The two modes are never substituted for each other. Exact-GC context v2 binds
the explicit rounding mode. Checked multiplication continues to declare
`floor` in its v2 planner certificate and plan digest because changing that
estimand silently would invalidate existing fixed-point protocols. A future
nearest-even multiplication must therefore use a new declared operation and
certificate, not reinterpret `mul-truncate-checked`.

The v2 bounded-source validator also avoids floating-point range checks. It
constructs the signed endpoints as canonical decimal integers and enforces
`[-2^(k-1), 2^(k-1)-1]`; the text-length cap is derived from `k`, including
the optional minus sign, instead of using a fixed 40-digit limit. Endpoint and
one-step-overflow tests cover Ring63, Ring127, Ring128, Ring256, and Ring512.

## Finite-sampler accounting

Let the stop probability be the dyadic value `q=m/2^B`, `p=1-q`, and let the
integer query sensitivity be `Delta`. The unbounded difference-of-geometric
mechanism has effective privacy parameter

`epsilon_eff = -Delta * log(p)`.

The planner selects the largest dyadic `m` for which an exact rational Taylor
prefix lower bound proves

`1/(1-q) <= exp(epsilon_declared / Delta)`.

This directly certifies
`Delta * [-log(1-q)] <= epsilon_declared` without evaluating a floating-point
logarithm.  A finite positive Taylor prefix is always below the true
exponential, so the comparison is conservative.  It is materially tighter
than the former `q/(1-q)` inequality: for `epsilon=Delta=1` and an 8-bit
Bernoulli, it selects `m=161` instead of `128`, using an effective epsilon of
about `0.991` rather than `0.693` while remaining below the declared value.
The circuit implements `min(G,L)` using exactly `L` Bernoulli trials. Although
the capped output has mass `p^L` at `L`, the coupling differs from the
unbounded geometric only for `G>L`, with probability `p^(L+1)`. A conservative
vector total-variation bound is therefore

`TV <= 2 * d * p^(L+1)`.

If both neighbouring output distributions are within `TV` of an
`epsilon_declared`-DP mechanism, then

`delta_impl <= (1 + exp(epsilon_declared)) * TV`.

The planner computes an exact rational upper bound on `exp(epsilon_declared)`
from a Taylor prefix plus a geometric remainder, selects the smallest `L` for
which `delta_impl` fits the allocated delta, and binds the exact numerator and
denominator into the worker policy. The worker recomputes the entire plan; it
does not trust a supplied delta fraction by itself. Pure-DP allocations with
`delta=0` are typed unavailable.

## Why v1 cannot be activated by a flag

The v1 control plane commits to

`SHA-256("dsVert/.../v1|" || seed_hex)`.

The v2 circuit verifies

`SHA-256(context32(transcript, role, peer) || seed_raw32)`.

This incompatibility is deliberate. The separate v2 preflight reproduces the
raw-seed commitment without exposing the seed and cross-signs both commitment
contexts, but it explicitly reports that no worker attestation is available.
A production bridge must validate both v2 tokens, the durable ledger record,
both pinned roles, exact sampler plan, actual circuit digest, and staged-source
contract locally before creating a worker config. It must then persist the
two result shares before any delivery. Changing either existing boolean is not
a valid promotion procedure.

## Current performance blocker

The v2 sampler uses `2*d*L` Bernoulli trials and is therefore linear in
`L ~= (Delta/epsilon) log(1/delta)`. It is practical for modest integer count
sensitivity but not a general solution for fine fixed-point grids or large
sensitivity-to-epsilon ratios. A secret binary search over a public inverse-CDF
table does not solve this in a Boolean circuit: secret branches and table
selection still require the unselected paths or an oblivious lookup.

The planner exposes the exact Bernoulli-trial and AES-block counts and refuses
plans above the fixed circuit policy. This performance limitation is one of
the reasons the capability stays unavailable.

## v3 sublinear sampler inventory

The primary candidate is Keller et al., *Secure Noise Sampling for
Differential Privacy in MPC with Finite Precision* (IACR ePrint 2023/1594),
building on the exact discrete-noise constructions of Canonne, Kamath, and
Steinke. A faithful implementation must add, with fixed public iteration
counts and failure probability charged to delta:

- exact `RandInt(t)` with bounded rejection and no modulo bias;
- the alternating-series `BernoulliExp1(x)` construction, including exact
  Bernoulli(`x/k`) substeps and a fixed-loop failure certificate;
- `Geo(1-exp(-1))` and the paper's `GeometricExp` composition;
- oblivious `Sel` of the first successful candidate;
- exact wide multiply, floor, and division for `(v*t+u)/s`;
- sign sampling plus the zero/sign rejection used by discrete Laplace;
- finite-domain tail and all fixed-repeat failure terms added to delta;
- for discrete Gaussian, the additional Laplace proposal and exact
  exponential acceptance step.

IBM's Apache-2.0 `discrete-gaussian-differential-privacy` reference is useful
for independent arithmetic tests. Its variable-time loops cannot be copied as
an MPC protocol without the fixed-iteration transformation and accounting
above. No floating-point exponential, logarithm, inverse CDF, or empirical-only
error estimate should be substituted for these proofs.

## Promotion gates still missing

- a server-local v2 token-to-worker attestation bridge that writes the exact
  worker output bytes into the existing durable result state machine;
- an end-to-end product-bound adapter test (the independent packaged
  two-process tests already pass for Ring63 and Ring127);
- end-to-end crash injection across worker completion, durable result
  persistence, DSI acknowledgement, and replay (the control-plane-only crash
  and lost-acknowledgement tests already pass);
- either retain the explicit at-least-one-durable-honest-peer result-spool
  assumption or extend the optional external CAS receipt to the ordered
  delivery-commit head;
- define the K>2 contract: either bind an explicit custodian-owned two-peer
  computation subset while securely incorporating every site's share, or
  generalise allocation and sampling to K peers; implicit first-two selection
  is forbidden;
- wrong peer, pin, role, transcript, bounds, source, reorder, tamper, and
  concurrent-retry tests across that bridge;
- representative Count, Mean/Variance, Describe, and Survival cost/utility
  budgets using their real server-minted sensitivities and clipping domains;
- complete producer provenance (including one-hot/query-domain validation for
  chi-square) before any method can consume the backend;
- a sublinear v3 sampler, or a deliberately narrow promoted scope whose cost
  bound is acceptable to operators.
