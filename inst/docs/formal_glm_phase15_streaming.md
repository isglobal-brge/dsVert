# Formal GLM Phase 1.5: signed fan-in and bounded-memory T>1 execution

Status: **internal, not promoted, not a package capability**.  No R endpoint,
`NAMESPACE` entry, command handler, advertised capability, or release binary is
added by this phase.

## Public lifecycle status (security-profile schema v4)

This note preserves component-level research evidence; it is not readiness
evidence for a public route. Schema v4 reports
`route_claims$formal_glm_ready = FALSE` with state
`sealed_no_registered_r_dsi_joint_dp_release_lifecycle`. The top-level client
`ready` value and the server compatibility alias `formal_dp_claim_eligible`
describe the biomedical joint-DP capsule route only; neither promotes formal
GLM or formal Cox.

Formal GLM remains sealed until the protected materializer, the complete
registered R/DSI schedule, the durable common finalizer and the route-level
end-to-end numeric certificate are bound into one tested release lifecycle.
None of the Phase-1.5 results below closes that lifecycle by itself.

## What is implemented

- A server-authoritative producer adapter converts each custodian's fixed-shape
  local block into two additive Ring2^k shares.
- Each share is encrypted to one designated compute peer with X25519 +
  HKDF-SHA256 + AES-256-GCM and is signed with the custodian's pinned Ed25519
  identity.
- Every envelope binds the unanimous public plan, logical snapshot, run id,
  sender, recipient, block, row count, ring and the two-recipient ciphertext
  pair.  Hashes are over randomized ciphertexts, never over a low-entropy
  patient value.
- All K custodians are required exactly once.  Arrival order is irrelevant.
  Missing, duplicated, altered, misrouted, cross-run or conflicting packets
  fail closed.  A byte-identical retry is idempotent and is not a request
  quota.
- A MAC-authenticated durable ledger preserves this idempotency across worker
  restarts.
- Both compute peers derive the same fan-in root from the signed pair
  commitments.  That root is part of the exact-GC secure-record purpose.  A
  relay that gives the peers different valid packet sets causes a context
  mismatch, not a model result.
- Binomial and capped-Poisson projected-gradient GLMs run for a public fixed
  T>=1 schedule.  Every row validation, clipping, PWL link evaluation,
  signed-floor multiplication/division, ridge term, step and coefficient-box
  projection occurs inside exact Yao GC with checked OT.
- Beta and gradient state are always additive shares.  Every GC output is
  freshly masked.  No beta, gradient, residual, validity flag, count or
  row-level value is opened by Phase 1.5.
- Ring selection starts at Ring128 and increases to the required dynamic
  Ring2^k up to Ring4096.  The planner accounts for the complete-capacity
  accumulator, full coefficient boxes and every fixed-point intermediate.  A
  value outside Ring4096 returns a typed pre-data failure; modular wrap is never
  reported as a result.
- The physical block size is automatically reduced without changing rows,
  iterations, estimand or allowed request count.  The signed cost contract
  contains exact gates, wires, XOR/non-XOR gates and compiler cost, plus a
  conservative working-memory estimate.  The current envelope is 768 MiB per
  circuit and at most `block_capacity * p = 4`.
- The segmented DSI spool retains unacknowledged bytes by absolute offset,
  handles short/repeated transfer, applies bounded backpressure and survives a
  temporary relay disconnect.  A process crash never resumes OT/garbling
  mid-transcript: the last committed sealed state is retained and both peers
  use a fresh random session id.
- A result becomes committed only after both pinned compute peers sign a
  pending-state receipt for the same plan, step and attempt.  This closes the
  asymmetric-crash window between protocol completion and state advancement.
- Every committed step advances a common authenticated execution-transcript
  root over the previous root, fixed step index and exact secure-record
  purpose.  Because a block purpose contains its fan-in root and fresh attempt
  id, the final cross-signed receipt pair commits the complete accepted source
  sequence; mixing two otherwise valid executions is rejected.
- An internal DP bridge reconstructs a final signed/dynamic-ring beta only
  inside exact GC, clips it again to the signed coefficient boxes, applies an
  exact signed-floor quantization and emits fresh non-negative Ring128 shares.
  These shares remain sealed.  No R endpoint, handler or opening was added.

## Numerical contract

For finite inputs satisfying the signed public bounds, a covered PWL link
domain and the public contraction condition, execution is bit-for-bit equal to
an independent signed-integer lattice oracle for the same fixed schedule.  A
second independent `big.Rat` oracle evaluates the same clipped PWL optimizer
without fixed-point floors.  The plan publishes a conservative T-step L1 rho
bound; tests verify the observed lattice/rational difference is below it.

The block grouping introduces no extra statistical approximation.  Scores are
added exactly in the selected ring and divided once by total capacity in the
iteration finalizer.  Invalid categorical/outcome tuples receive zero weight,
and the last physical block is padded with signed-plan zero rows.

This contract does not claim that every dataset is statistically identifiable.
Identifiability, non-convergence alternatives (for example Firth or ridge) and
the final disclosure-safe/DP release remain higher-level method concerns.

## Threat model and claims that are defensible

Under the explicit assumptions below, the analyst/relay cannot reconstruct the
input and cannot silently alter a packet or GC context:

1. exactly two pinned compute peers are selected from K>=2 custodians;
2. at least one compute peer is honest and does not collude with the other;
3. pinned private keys and local additive shares remain inside their server;
4. the current Yao/checked-OT implementation is used in its documented
   semi-honest model; and
5. custodians follow the signed source plan for their own data.

Two colluding compute peers can add their shares and reconstruct source/state.
No two-party sharing protocol can prevent that without changing the trust
architecture.  A deliberately dishonest custodian can lie about its own local
value; signatures establish provenance, not truth.  Preventing that requires
source attestation or malicious-secure input proofs.  The current exact-GC
backend is not a malicious-secure 2PC proof against a compute peer that deviates
from garbling/OT.

The relay can still delay or drop traffic (denial of service), but cannot turn
that into a silently different accepted input.  A local root administrator can
roll back both a checkpoint and its local files; promotion needs the deployment
rollback/monotonic anchor already required by the wider durable control plane.

Phase 1.5 performs **no opening and no DP release**.  The bridge publishes a
machine-checkable universal joint L1 sensitivity bound
`2 * sum(ceil(box_j / quantization_quantum))`; it is valid for any pair of
datasets because the exact circuit projects every released coordinate into
the certified box.  This is intentionally a conservative fallback and may
have poor utility.  A mandatory strong-convexity/capacity sensitivity field is
marked `not_machine_proven`; an asserted smaller number is rejected.  Future
selection may use the minimum of multiple machine-proven bounds, never a
heuristic or merely cross-signed claim.

The actual joint-DP worker compilation returns the typed blocker
`common_release_capsule_glm_manifest_not_e2e_verified`.  Formal DP can only be
claimed after the common durable sticky-noise capsule admits this GLM manifest,
binds the final receipt pair and transcript root, adds noise before the sole
opening, and applies the signed-coefficient postprocessing contract.  This code
must not be presented as DP by itself.

The intended data-free mapping into that common vector release is explicit:
Ring128, frac=0, `total_coordinate_count=p`, zero scale shifts, per-coordinate
raw upper bound `2*ceil(box_j/quantum)`, and the selected machine-proven joint
L1 sensitivity.  The DP transcript must additionally hash the bridge plan,
release contract, final receipt pair, accumulated execution transcript,
snapshot, pinset and both sticky-seed commitments.  After the one DP opening,
public postprocessing subtracts `ceil(box_j/quantum)` and divides by
`2^output_lattice_bits`.  Backend selection remains the common public cost
policy (currently exact one-draw GC only for its promoted coordinate ceiling,
otherwise the certified convolution path); this bridge must not override that
selection after seeing private shares.

## Performance and scalability result

Memory is bounded by public block shape rather than total N:

`memory = O(block_capacity * p)`, while work and traffic remain
`O(T * N * p / block_capacity)` for this compiled Boolean-circuit backend.

Measured on Apple M2 for binomial p=2, physical block capacity 2:

- 935,935 gates per block;
- public conservative estimate: 322,059,944 working bytes;
- direct Boolean evaluation: about 2.50 ms and 0.94 MiB allocations;
- in-process Yao + checked OT: about 109 ms and 222.7 MiB allocations.

A one-million-row, T=8 public plan therefore has 500,000 blocks per iteration
and 4,000,008 logical steps.  The path is memory-safe but **not production-fast
at that scale**.  DSI reconnect/spooling removes avoidable retransmission and
unbounded buffering; it cannot remove the cryptographic O(NT) work.

Promotion for large biomedical cohorts requires a specialized vector/block
kernel (and bounded parallel block waves) that amortizes garbling and DSI
round-trips while preserving the same source-root, numeric and sealed-state
contracts.  Increasing an unbounded monolithic GC is not an acceptable
solution.

## Validation recorded

- K=2, K=3 and K=5 unanimous plans and complete fan-in.
- Binomial and Poisson, T=2/T=3, final partial block and dynamic Ring>128.
- Typed Ring>4096 rejection before source materialization.
- Exact circuit equality to the centralized integer oracle and bounded error
  against the independent rational oracle.
- Randomized weights, covariates, categorical indicators, outcomes and offsets
  at/inside/outside every clipping boundary.
- Actual Yao/OT T=2 with coefficient and gradient shares only.
- Actual Yao/OT of the signed/dynamic-to-Ring128 DP bridge, including exact
  negative signed-floor quantization and a Ring>128 source.
- Full T=2 checkpoint-worker execution over segmented spools, including relay
  pause, close/reopen between steps and absolute-offset continuation.
- Tamper, omission, duplicate/conflicting replay, ciphertext reroll, pair mix,
  fan-in-root mix, plan mutation, receipt replay, checkpoint corruption and
  asymmetric crash/restart.
- Universal sensitivity endpoint equality, rejection of a forged tighter
  sensitivity, transcript/receipt mixing rejection, completed-checkpoint-only
  loading and the typed common-release blocker.

Still required before promotion of the public route:

- server-owned all-K registry authorization of the protected materializer;
- a registered R/DSI coordinator for the complete durable schedule and its
  restart semantics;
- binding the Phase-1.9 DP shares and hidden validity into the durable common
  one-draw finalizer and signed public adapter;
- a route-level end-to-end numeric certificate rather than only component
  certificates;
- real multi-process DSLite, Opal and Armadillo E2E evidence for K=2,3,4,5,
  including restart, tamper, replay and peer substitution;
- a specialized scalable vector kernel, transcript-padding audit, supported-
  platform RSS gates and deployment rollback-anchor integration; and
- a machine-verified tighter strong-convexity/capacity sensitivity recurrence
  if useful accuracy is to improve over the safe coefficient-box fallback.
