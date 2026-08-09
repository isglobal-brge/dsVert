# Joint-DP result confidentiality and release boundary

Status: the registered biomedical-vector path carries allocation, bounded
source materialization, joint sampling, finalization, durable publication and
replay end to end. Its productive receipts report
`capability_available=TRUE`. The older generic scalar receipt state machine is
unregistered and is not a statistical release route.

## Current product flow

The server-authoritative manifest fixes the cohort/snapshot, adjacency,
contribution bounds, coordinate layout, mechanism, privacy parameters, complete
logical-name pinset and two designated noise peers before private material is
read. For K greater than two, every data owner's contribution is bound to that
same manifest and source contract before it is aggregated at the designated
pair. The analyst cannot select a different pair, recipient key, source,
workload, bound or backend.

The selected backend is also fixed before private material is read:

- a scalar Laplace vector uses one joint exact-GC draw;
- a wider Laplace vector uses two independent complete-vector draws and their
  convolution; and
- the fixed-work dyadic discrete-Gaussian route is used only when the signed
  manifest's deterministic mechanism plan selects it.

Each designated peer persists its sticky seed commitment and private noised
chunks. PREPARE persists only an authenticated candidate; sibling candidates
may coexist until the first valid `StartDS` at a designated peer atomically and
irrevocably persists its per-capsule instance claim before local staged-source
access or sampling. Source transport may already have staged encrypted
protected material, but START has not yet produced a noised share or public
output. Exact same-instance chunk/restart replay is idempotent. `ResultDS`
publishes only a signed commitment to the complete local
result. `FinalShareDS` transfers a purpose-bound, typed ciphertext to the
identity-pinned peer. `ReleaseDS` consumes both committed inputs, reconstructs
only the authorised noised value, applies the single fixed public clamp and
durably stores public DP chunks under a signed Merkle root. `ReplayDS` reads
only those final public chunks and their Merkle proofs; it does not read source
material or invoke a sampler again.

Each claim is local authenticated history. A split relay can make different
peers claim sibling candidates, but cannot obtain the matching bilateral
RESULT, FinalShare and RELEASE evidence needed to publish either one while at
least one designated peer is non-colluding and retains its complete history.

## Frozen vector receipt and store ABI

This is the pre-release baseline:

| Artifact | Exact version |
|---|---|
| Joint-DP control protocol | `dsvert-joint-dp-control-v3` |
| Canonical capsule identity | `dsvert-joint-dp-capsule-identity-v3` |
| PREPARE signed receipt | `dsvert-joint-dp-vector-prepare-v6` |
| START signed receipt | `dsvert-joint-dp-vector-chunk-start-v5` |
| RESULT signed receipt | `dsvert-joint-dp-vector-local-result-v5` |
| RELEASE signed receipt | `dsvert-joint-dp-vector-release-root-v5` |
| ACK signed receipt | `dsvert-joint-dp-vector-finalization-ack-v5` |
| Authenticated durable STORE schema | `dsvert-joint-dp-vector-store-v6` |
| Per-capsule instance claim | `dsvert-joint-dp-vector-instance-claim-v1` |
| Authenticated instance-claim set | `dsvert-joint-dp-vector-instance-claim-state-v1` |
| Replay response | `dsvert-joint-dp-vector-replay-v4` |

Every signed phase receipt and replay response attests exactly
`history_gate=TRUE`, `request_limit=FALSE`, and `operation_limit=TRUE`.
Signatures bind the complete public receipt to its pinned peer; STORE rows are
separately HMAC-authenticated durable state and are not relay-minted receipts.

Control v3 and capsule identity v3 bind the lifetime fields and biomedical
workload v7. STORE v6 makes both claim-v1 artifacts required durable
invariants. Their v2 artifacts, like pre-baseline v4/v5 stores, are legacy.
There is deliberately no automatic upgrade or re-signing of any of them. A
deployment must start with empty DP capsule state or wait for a future audited
offline migration; encountering legacy state fails closed. This rollout
does not discard a production release history: prior Opal deployments reported
`POLICY_READY=FALSE`, did not publish DP capsules, and used ephemeral local
K-site state.

The exact-GC route uses the existing authenticated peer-to-peer record layer.
The analyst/DSI process relays opaque records but cannot stage an arbitrary
source, consume a worker output, replace a peer identity, change the circuit
binding or obtain an output/validity share. The scalable Laplace and Gaussian
routes use the fixed vector-specific encrypted-share capability; the generic
typed store cannot reinterpret that ciphertext under another producer,
consumer, peer, context or shape.

## Closed low-entropy commitment oracle

The retired v1 generic result receipt exposed

```
SHA256(public_query_context || payload)
```

to the analyst/relay. That construction was binding but not hiding: a
low-entropy exact payload could be recovered by hashing every candidate. The
retained, unregistered v2 compatibility implementation instead computes

```
payload_commitment = HMAC-SHA256(
  K_ledger,
  canonical(protocol, query_id, opening_set_hash, result_contract_hash)
    || 0x00 || payload
)
```

where `K_ledger` is derived from persistent private server state and never
returned through DSI. Under the HMAC-SHA256 PRF assumption, a relay without
that key has no offline predicate for candidate payloads. Legacy v1 receipts
fail closed.

This HMAC rule is defence in depth for retained compatibility code; it is not
what makes the productive biomedical result releasable. The current vector
route never publishes a commitment to an exact low-entropy statistic. Hashes
and Merkle proofs that become public bind ciphertext, signed protocol state or
the already-authorised final DP chunks. A keyed commitment alone would not
make an exact statistic disclosure-safe.

## Relay-visible and private state

The relay can observe public manifests, fixed dimensions/chunk indices,
backend identifiers, signed phase receipts, opaque ciphertext, public
implementation-error certificates, final DP values and their Merkle proofs.
It may replay, delay, reorder, duplicate, fork or suppress those messages.
Signatures, exact logical-name pins, context-bound ciphertext and durable state
make modification or cross-context substitution detectable; suppression and
delay remain availability attacks.

The relay does not receive a patient identifier, source share, exact source
aggregate, private seed, random stream, sampled noise, noised share,
pre-clamp value, private ledger key or candidate-verification oracle. Result
preparation and source materialization are internal operations. No registered
method accepts analyst-provided payload bytes or private randomness.

Private records live in owner-only authenticated SQLite state and bounded
transport spools. This protects against the analyst/relay and an
unprivileged local user under the documented filesystem assumptions. It does
not protect against root/service-account compromise. A retained honest peer's
signed and durable release state detects unilateral conflicting replay or
rollback; simultaneous rollback of every durable copy to a mutually
consistent image remains outside the local-only guarantee unless an external
monotonic anchor covers it.

## Privacy and threat-model boundary

The defensible privacy statement is computational, patient-level bounded
lifetime DP for at most `N` immutable, contribution-bounded capsule releases,
per stable privacy accountant namespace, followed by unlimited post-processing
of each exact durable release. The server-owned `N` defaults to one, and exact
composition requires
`N * epsilon <= 8` and `N * delta < 1`. It depends on:

- server-owned, consistent cohort/snapshot and contribution-bound metadata;
- two correctly pinned semi-honest designated peers;
- independent persistent roots, with at least one designated peer's root and
  private protocol state remaining unknown to the other peer and relay, and
  that same non-colluding peer retaining and using complete authenticated
  monotonic history;
- one stable, unique privacy accountant namespace across domain, cohort,
  policy, pinset and ledger reconfiguration for each protected privacy
  universe;
- the certified sampler implementation and its charged implementation delta;
  and
- authenticated durable release state for sticky replay.

The guarantee is not malicious-secure. A compromised host or deviating peer
can bias a result or create a side channel; collusion of both designated noise
peers removes the one-hidden-root argument. Timing, traffic analysis,
availability, malicious custodian input semantics and simultaneous compromise
or rollback of all durable peers are not covered. Pinning authenticates who is
participating; it does not prove that a peer is honest.

Namespace continuity is currently a custodial deployment assumption. The
package neither enforces uniqueness across independently configured namespaces
nor automatically migrates burned reservations when a ledger or pinset is
reconfigured.

The guarantee is bounded lifetime DP, not a promise for arbitrarily many
logical capsules. A new privacy epoch, snapshot or overlapping cohort is a
distinct capsule and consumes one non-refundable unit at allocator commit,
before data access or sampling. The registry records reservations; publication
is counted separately and each capsule has at most one public release instance.
The history can therefore deny a new capsule, but it is deliberately not a
request quota: exact replay and supported post-processing never spend another
unit or reduce accuracy. Historical exact/adaptive methods outside the
registered DP capsule do not inherit this claim.

## Verification boundary

Focused R integration tests cover K=2 and K>=3 allocation, manifest/backend
binding, relay tamper, non-designated peers, sticky restart/replay, response
loss, concurrent identical commits, root rotation, authenticated release
ledger recovery, typed ciphertext binding, final-only output, Merkle replay and
post-release compaction. Exact-GC adapter tests cover data-free compilation,
pinned role assignment independent of relay order, deterministic retry,
internal secret staging, durable consume and validity/pre-clamp checks. Runtime
tests cover the sampler/finalizer schemas and numeric certificates.

These tests exercise the complete package protocol and simulated connector
failure boundaries. A real multi-host Opal/Armadillo deployment still requires
normal deployment validation of TLS, persistence, permissions, clocks,
resource limits and operational backup/rollback controls; that is an
environmental validation obligation, not a disabled package capability.
