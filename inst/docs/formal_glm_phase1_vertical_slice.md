# Formal GLM Phase 1 exact-GC vertical slice

Status: **internal, one-iteration research slice; not advertised, not a remote
method and not production-release ready**.

This note records what the Phase 1 Go implementation actually establishes. It
does not promote the workload or weaken the exit criteria in the formal GLM
design.

## Implemented contract

`k2_formal_glm_phase1.go` compiles one complete projected-gradient iteration
into one purpose-bound Yao circuit. Its private input has the fixed public shape

`C x (p + 3) = [weight, design_1, ..., design_p, outcome, offset]`.

The garbler and evaluator each supply one additive share of every coordinate.
The circuit reconstructs values only on wires, applies the registered clipping
and validity rules, selects the registered monotone fixed-point PWL link,
computes weighted scores in capacity-slot order, divides by the public capacity,
applies the public dyadic step and coefficient box, and returns only fresh
additive coefficient shares. It has no score, gradient, residual, validity,
deviance or coefficient-opening output.

The current certified slice is intentionally narrow:

- binomial/logit-PWL and Poisson/log-PWL;
- exactly one iteration from the required public zero coefficient vector;
- `C <= 8`, `p <= 4`, `2 <= J <= 8` and one common fixed-point scale with
  `8 <= frac_bits <= 256`;
- one aligned record per patient, duplicate/conflict and complete-tuple
  missingness mapped to zero weight;
- numeric clipping, registered binary indicators, bounded weights, bounded
  outcomes and bounded offsets;
- signed floor after every multiplication, fixed capacity normalisation and
  box projection; and
- full positive ridge is policy-bound, although its first-iteration value is
  exactly zero because the only admitted start is `beta_0 = 0`.

The public policy digest binds the artifact, capsule, snapshot, pinset,
compiler, theorem and link-table commitments; adjacency; all custodians; the
two designated compute peers and their roles; family, shape, layout, scale,
bounds, coefficients, PWL table and error; missingness/collapse/reduction and
rounding semantics; and the sealed-output contract. Any change produces a
different purpose and authenticated record context.

## Numeric behaviour

The planner includes every public computational operand and intermediate bound,
including asymmetric eta bounds, PWL knots, widths, values and slopes, step,
ridge, boxes, residuals and fixed-order accumulators. It selects Ring128 as the
minimum route and increases `k` when required. Multiplication uses a `2*w`
circuit type, so the untruncated product cannot wrap its `w`-bit container.
The runtime also recomputes the exact rational `alpha <= 2/(m+L)` and `q < 1`
conditions from the registered feature, weight, slope and full-ridge bounds,
and requires the PWL domain to cover every eta reachable over the complete
coefficient box, not merely the zero starting point.

If the proved signed range needs more than Ring4096, planning returns the typed
`numeric_backend_unrepresentable` error. If the selected container and public
shape exceed the exact-GC typed-input envelope, it returns the typed
`public_circuit_shape_unrepresentable` error. Neither condition has a runtime
fallback, and no modularly wrapped value is returned as a result.

An independent big-integer lattice oracle specifies every signed-floor step.
A separate `big.Rat` oracle evaluates the same clipped PWL iteration without
fixed-point truncation. The planner publishes a conservative one-iteration
`rho_steps_upper`; randomized boundary tests verify the observed joint L1
lattice error does not exceed it. The PWL-to-true-link error remains the
separately bound, cross-signed `link_error_upper`; it is not silently included
in `rho`.

The tested dynamic circuit is Ring129 in a uint256 container. Ring513 and
greater-than-Ring2048 execution, multi-iteration error propagation and the
complete Phase 0 compiler-to-runtime certificate mapping remain promotion
requirements.

## Threat model and transcript

The policy supports `K >= 2` custodians but designates exactly two pinned
compute peers. The intended privacy claim is the existing pinned, authenticated,
semi-honest, non-colluding two-peer model with at least one compute peer honest;
the analyst/relay receives only authenticated ciphertext records. Collusion of
the two compute peers, deliberate source disclosure and malicious compute-peer
deviation are not solved by this slice. KOS-checked OT and AEAD records do not
turn Yao into a malicious-secure computation without an additional integrity
construction such as cut-and-choose or authenticated MPC.

Authenticated records bind session, purpose, peer identities, roles, ring,
rounding and shape. They reject ciphertext tamper, role/context/key substitution
and replay/out-of-order sequence numbers. Every tested private dataset uses the
same gate graph and logical write schedule. The present third-party OT/garbling
encoding showed a one-to-two-byte variation between fresh randomized runs with
the same public shape; this randomness is independent of the protected value,
but exact byte-count padding has not been demonstrated. The public cost contract
therefore reports
`fixed_logical_schedule_randomized_encoded_byte_count_padding_audit_pending`,
and this is a promotion blocker rather than a hidden claim.

## Public pre-data cost contract

`formalGLMPhase1PublicCost()` derives, before any private share exists:

- policy and generated-source digests;
- ring and container widths;
- garbler, evaluator and output bit counts;
- exact compiled gate, wire, XOR and non-XOR counts;
- compiler-relative cost; and
- the explicit `single_composite_exact_gc_ot_no_runtime_fallback_v1` backend.

Measurements below used Darwin/arm64, Apple M2, Go's in-process `net.Pipe`, one
benchmark iteration and no DSI connector. They are engineering measurements,
not cross-platform latency guarantees:

| Workload | Boolean compute | Gates | Non-XOR gates | In-process Yao+OT | Allocated bytes |
|---|---:|---:|---:|---:|---:|
| `C=1, p=1` | 1.63 ms | 581,400 | 164,308 | 100.4 ms | 135.9 MB |
| `C=2, p=2` | not separately recorded | 1,313,565 | 374,736 | 208.6 ms | 303.3 MB |
| `C=4, p=2` | 5.28 ms | 1,942,845 | 569,208 | not run | 1.95 MB for clear Boolean evaluation only |

Command:

```text
go test -run '^$' -bench 'BenchmarkFormalGLMPhase1(CircuitCompute|InProcessTwoParty)$' -benchtime=1x -benchmem -count=1
```

The non-XOR count and Yao allocation growth make a monolithic patient-level GC
unsuitable as the final large-cohort route. This implementation is therefore
not promoted. A scalable design needs fixed public row-block circuits,
streaming sealed reductions and bounded concurrency/backpressure, while keeping
intermediate aggregates sealed and preserving one fixed public schedule.

## Tests completed for this slice

- deterministic public planning for K2 and K3 custodians with exactly two
  compute peers;
- Ring128, dynamic Ring129, typed greater-than-Ring4096 and typed public-shape
  failure;
- binomial and Poisson integer/rational oracle checks;
- composite circuits for `C=1,p=1` and `C=2,p=2`, including randomized
  clipping, invalid indicators/outcomes, negative values, offsets and bounds;
- two-party Yao/OT execution for binomial K2 and Poisson K3, reconstructing
  only inside the test harness;
- snapshot, adjacency, link-certificate, peer-role, peer-set and master-key
  substitution; secure-record replay rejection; and
- public cost determinism and private-value-independent circuit/frame shape.

## Work still required before promotion

1. A producer-owned adapter must verify the Phase 0 cross-signatures and exact
   canonical artifact, then map every separate numeric scale and certificate
   field into this runtime policy. The Go slice currently receives an already
   authenticated policy representation; it does not verify custodian
   signatures itself.
2. The fixed-capacity source materializer must clip/check in arbitrary
   precision before modular encoding, bind source/CAS digests, and fan each of
   the K custodians' row-block shares to exactly the two compute peers. Without
   that adapter, a value wrapped before sharing cannot be distinguished from a
   legitimate ring residue. The adapter must also prove registered factor
   one-hot grouping; the circuit currently validates each indicator bit but
   does not carry factor-group metadata.
3. Worker and DSI orchestration, durable replay/reconnect, pinned-key
   authentication and multi-process K2/K3/K4/K5 tests are absent for this
   workload. No capability bit or command handler advertises it.
4. `T > 1` must keep coefficient state sealed across a fixed iteration count,
   import the complete Phase 0 interval/rho recurrence and avoid the compiler's
   unverified reusable-helper lowering. The first-iteration circuit removed the
   mathematically dead `ridge * beta_0` call after differential testing exposed
   incorrect lowering of that reusable helper call.
5. Row-block streaming must be benchmarked against the cost contract. No
   hidden legacy Ring63/127 DCF, local truncation, plaintext aggregation or
   runtime estimator fallback is acceptable.
6. Exact transcript-byte padding, malicious-deviation policy, races, crashes,
   spool/backpressure and real DSLite/Opal/Armadillo deployments still require
   validation.
7. Phase 2's one sticky joint-DP coefficient release is not present. There is
   intentionally no opening, no DP sampler and no public result in this slice.
8. No NAMESPACE entry, client API, server endpoint, runtime capability or
   packaged binary has been added or rebuilt.
