# Joint MPC single-opening DP control plane

Status: implemented and adversarially unit-tested as the durable allocator
underlying the manifest-bound biomedical vector route. Its registered product
surface is the five `dsvertJointDPVectorAllocation*DS` endpoints. The former
seven-phase generic scalar DSI frontdoor and its result/delivery contracts are
hard-deleted. The shared receipt codec and commit/authorize/open helpers remain
internal because the vector allocator uses them. The generic result-spool
schema remains historical internal state pending a separate schema-removal
decision; no service endpoint stages or retrieves a payload through it. The
stateless Count route does not use this control plane.

## Objective and threat model

One authoritative, server-minted full-capsule identity should consume one
global allocation, instead of calibrating every local opening to `epsilon/K`.
The allocator has no request-count quota: an identical capsule replays forever.
A previously unseen capsule is admitted only while one of the server-owned
`lifetime_max_distinct_capsules` units remains; the default is one.
That bound is per stable privacy accountant namespace. The privacy claim
assumes one stable, unique namespace across domain, cohort, policy, pinset and
ledger reconfiguration for each protected privacy universe. This is presently
a custodial deployment obligation: the control plane does not discover or
merge competing namespaces and does not automatically migrate their counters.
The intended product adapter will bind that identity to one persistent capsule
per logical snapshot, complete schema/workload contract and privacy epoch, so
downstream methods are post-processing of the capsule rather than new
per-method allocations. The allocator refuses to infer an identity from a
method name, method arguments or an incomplete coordinate pilot. That
full-capsule product adapter is not yet promoted.
Exactly two computation peers are named and pinned by distinct Ed25519 public
keys. The analyst/DSI process may reorder, replay, fork, delay or suppress
messages, but cannot forge either peer's receipt. Privacy assumes that at least
one pinned computation peer both does not collude and retains and uses its
complete authenticated monotonic history across a rollback event. Peer
unavailability may stop a
release; it must never make the protocol fail open.

MPC confidentiality does not make a malicious data custodian report truthful
input. A peer can always choose its own protected dataset. The protocol binds
that choice immutably to its signed, capsule-specific opaque snapshot binding;
it does not claim to validate another custodian's data semantics.

## Immutable bindings

The clean pre-release ABI fixes the control protocol at
`dsvert-joint-dp-control-v3` and capsule identity at
`dsvert-joint-dp-capsule-identity-v3`. Both bind the lifetime fields and
biomedical workload v7. V2 artifacts are legacy and fail closed; there is no
automatic migration or re-signing. Deployment requires empty DP capsule state
or a future audited offline migration.

The common canonical query commits to:

- protocol, release scope and capability identifier;
- domain, cohort, adjacency and contribution policy;
- the complete ordered K-peer pinset and its SHA-256 digest, plus exactly two
  canonical custodian-designated noise peers selected from that map;
- fixed per-capsule epsilon/delta parameters (never a request-count quota);
- logical snapshot identifier/version and alignment protocol version;
- the operation-independent capsule schema plus canonical admission, bounds
  and workload contracts;
- producer, purpose, source-context hash, shape, ring/scale, clipping hash,
  sensitivity norm/value, mechanism/version and sampler version within that
  workload contract; and
- privacy epoch.

The capsule identity also carries the full relevant policy-contract hash and
complete peer-pinset digest. `method`, `arguments` and `operation` fields are
rejected inside the identity preimage. On the provisional wire only,
`query_id` is retained as a compatibility alias and must equal `capsule_id`
byte for byte; it is not an operation counter or a privacy-budget key.

Each peer separately HMAC-binds its private snapshot fingerprint to that capsule.
The fingerprint itself is never placed in a receipt. Each peer also derives a
capsule/index/mechanism/allocation-specific 256-bit seed from its persistent DP
noise root and publishes only a domain-separated SHA-256 commitment. The two
noise-root key IDs may differ, but their privacy epoch and all common allocation
fields must agree.

## State machine and exact ordering

Only one proposal may occupy a ledger head. There is intentionally no remote
abort, refund, seed-read or generic state-write endpoint.

1. **Producer seal (future adapter prerequisite).** An internal-only helper now
   HMAC-authenticates the exact server-minted proposal before DSI prepare; no DS
   method can mint or alter it. A proposal is accepted only with an explicit
   capsule identity whose workload binds the exact full-capsule materialization
   mechanism. A future high-level method must first seal its complete vector of
   purpose-bound statistic shares and provenance. A method-specific Count or
   chi-square coordinate pilot is deliberately insufficient and must remain
   fail-closed; otherwise it could reserve a partial identity that later blocks
   the complete capsule.
2. **Leader prepare.** The lexicographically first member of the canonical
   custodian-designated pair is the sole allocator leader. It assigns the
   release ID to the current global index, epsilon, delta and previous chain
   head, derives its sticky private seed, stores a durable `prepared` row, and
   signs that assignment. A different proposal cannot replace the prepared
   head.
3. **Follower prepare and agreement.** The second designated peer cannot
   reserve any head without the leader's valid signed prepare receipt. It
   verifies that the release ID, epoch, mechanism, allocation and previous
   head exactly match its local proposal, fixed capsule parameters and retained head before it
   derives its own seed and persists the assignment. The ordered receipt set
   becomes `prepare_set_hash`. Thus opposite A/B delivery order at the two
   peers cannot create two independently prepared heads.
4. **Local allocation commit.** Each peer writes the complete ordered prepare
   set, `joint_record_hash`, next chain head, and fixed capsule epsilon/delta
   certificate with SQLite `synchronous=FULL` under an exclusive file lock. It then
   atomically creates the dense authenticated capsule-reservation journal row.
   This is the lifetime charge point: one unit is burned before protected data
   or sampling and is not refunded if later phases abort. It then advances its
   optional external linearizable CAS anchor. Only after both durable steps can
   its signed commit receipt become active.
5. **Cross-anchor.** Each peer verifies and durably stores both signed commit
   receipts before signing an authorization receipt with
   `peer_commit_stored=TRUE`. Thus the other peer holds a signed checkpoint for
   every opening that can progress. The reservation journal already exists from
   local commit; reconciliation appends or replays the bound registry row and
   seals its identical allocator/registry sequence, row MAC and chain hash as
   `registered`. Crashes between the two databases reconcile idempotently; an
   unbound registry row is rejected. Authorization adds no second charge.
6. **Bilateral authorization.** Each peer verifies and stores both
   authorization receipts before minting its signed `open_authorized` token.
   The authenticated allocator-registry binding is reconciled before this
   token is minted or consumed. This is the earliest state a sampler may
   consume. Today that token is deliberately non-capable.
7. **Exact-GC sampler (not implemented).** The GC must consume both ordered
   opening tokens, both seed commitments, and the exact public contract emitted
   by `.dsvert_joint_dp_sampler_contract()`. Inside the circuit it must verify
   both private seed preimages, derive
   `HKDF-SHA256(transcript_hash, seed_A || seed_B)` in pinned-peer order, feed a
   CSPRNG, and sample **one** globally calibrated discrete mechanism. It must
   output two additive ring shares of that one noise vector, not one complete
   draw per peer. At least one unpredictable seed makes the joint stream
   unpredictable before the commitments are fixed.
   A separately implemented provisional fallback lets each designated peer
   add one independently rooted, complete-global-budget raw draw to a uniform
   Ring128+ statistic share. It requires a joint signed-decode-and-single-clamp
   finalizer and has variance multiplier 2/RMSE multiplier sqrt(2). It is not
   the exact-GC sampler described here, is not advertised, and cannot change
   any capability flag; see
   `joint_dp_independent_full_draw_convolution.md`.
8. **Durable result mapping (implemented internally).** Each peer accepts only
   an exact raw byte payload plus a server-minted result-contract hash after it
   has both signed opening tokens. It writes the bytes and a domain-separated
   HMAC-SHA256 commitment under its persistent private ledger key to the
   authenticated SQLite result table before returning a v2 `result_prepared`
   receipt. The relay sees only this computationally hiding commitment; unlike
   the retired v1 `SHA256(public_context || payload)` field, it cannot test a
   dictionary of low-entropy candidate outputs without the local secret. Both
   peers then durably store
   the ordered result-receipt set and cross-sign `result_committed`; finally
   both store the ordered commit set and mint non-capable delivery tokens.
   Lost acknowledgements and restarts replay byte-identical receipts. A
   conflicting payload for the same query is rejected, including after a
   one-peer rollback when the other peer retains its commitment. There is no
   remote payload getter. The generic scalar DSI bridge and its seven
   unregistered frontdoors are hard-deleted. Legacy v1 result receipts and
   their enumerable public hashes are rejected. A future producer must still
   use uniformly masked additive result shares or the authenticated exact-GC
   peer channel: the HMAC closes the receipt oracle but does not make an exact
   unmasked statistic safe to deliver.
9. **Single payload delivery (not implemented).** A future product-bound
   adapter must
   prove that the persisted bytes are the purpose-bound, already-noised output
   of the attested sampler and must verify both delivery tokens before one
   payload is returned. It may never persist or pass an exact statistic as a
   result payload. Until that E2E provenance and delivery path exists,
   `payload_delivery_available=FALSE` and no bytes leave the result ledger.

The future sampler transcript, in order, is therefore:

```
protocol/version
consortium_id
ordered_peer_names + peer_pinset_sha256
capsule_id + query_id compatibility alias + privacy_epoch
allocation_index + previous_chain + new_chain
epsilon + delta
joint_record_hash
prepare_set_hash
commit_set_hash
authorization_set_hash
producer + purpose + source_context_hash
ring_bits + frac_bits + coordinate_count
mechanism_hash + mechanism/version + sensitivity/clipping
ordered(seed_commitment_A, seed_commitment_B)
ordered(opening_token_A, opening_token_B)
result_contract_hash
ordered(payload_commitment_A, payload_commitment_B)
result_set_hash
ordered(result_commit_A, result_commit_B)
delivery_commit_set_hash
```

Changing any field creates a different transcript and must fail before the GC
accepts a private seed or statistic share.

## Invariants

1. A committed index is unique and never reused or refunded.
2. Every new capsule receives the fixed configured `epsilon_capsule` and
   `delta_capsule`; K never divides either value. `allocation_index` orders the
   integrity/rollback chain and indexes one lifetime reservation. Exact decimal
   policy validation requires `N * epsilon_capsule <= 8` and
   `N * delta_capsule < 1`. The authenticated committed count is an admission
   control for a new capsule, but never a request count or accuracy schedule.
   The fixed `[dsvert_dp_lifetime_budget_exhausted:v1]` token is an opaque
   terminal union of global `N` exhaustion and a capsule whose irrevocable
   instance claim/publication binding prevents the requested instance from
   safely continuing or replaying. It does not imply
   `remaining_distinct_capsules == 0`; separate tokens would reveal state.
3. The same canonical capsule at any later head replays the same prepare receipt,
   seed commitment, allocation and all later receipts.
   The allocator imposes no limit on replay or downstream post-processing;
   product-level capsule identity determines when a genuinely new allocation
   is required.
4. No result can become eligible for delivery until both global allocation
   replicas, both opaque payload-commitment receipts and both result commits
   are durable and cross-signed.
5. Receipt substitution across peer, query, snapshot, epoch, mechanism, index,
   chain, shape or purpose fails signature or transcript equality checks.
6. A crash or lost acknowledgement after any durable phase resumes from that
   phase and cannot obtain a new seed, noise draw or payload mapping.
7. A pre-commit failure produces no sample. A post-commit failure consumes the
   allocation and can only retry the same deterministic sample. There is no
   abort-driven reroll or refund path.
8. The local legacy accountant and this consortium ledger use different files,
   schemas, chains and anchor IDs. No migration or double-accounting inference
   occurs implicitly.
9. With K greater than two, the transcript binds the complete pinset and one
   canonical, custodian-owned `designated_noise_peers` pair. Only those two
   pinned identities may run the allocator; the analyst/relay cannot select or
   substitute them. E2E ingestion of contributions from all K data holders is
   still required before promotion.
10. Registry composition counts every allocator-commit reservation, including
    one that never reaches authorization or publication. It may deny a new
    capsule at `N`, but cannot rate-limit replay or change fixed parameters.
    The configured bound makes cumulative delta strictly less than one.
    Registry-only suffix rollback is reconstructed from the authenticated
    allocator journal; an alternate branch or unbound row is an integrity
    error, distinct from genuine lifetime exhaustion.

## Rollback and deployment

Cross-signed anchoring is automatic and needs no new administrator secret or
coordinator. If one ledger is restored, the other peer's retained head will not
sign the old index/head, so no new opening can pass bilateral authorization.
An analyst can withhold messages and cause denial of service, but cannot make
the honest non-colluding peer that retains and uses its complete authenticated
monotonic history accept the fork.

The local allocator journal also anchors the separate capsule registry. A
registry restored to an authenticated prefix is rebuilt deterministically in
its original sequence; a same-length alternate head, unbound entry, changed
admission, or broken chain is rejected. Because allocator and registry are two
SQLite files rather than one distributed transaction, temporary filesystem or
locking failures can delay reconciliation, but retries never allocate a new
capsule and are not denied by request count. The authenticated reservation count
is consulted when admitting a previously unseen capsule and denies capsule
`N + 1`.
Both sides persist HMAC-authenticated count/head state. Exact COMMIT/RELEASE
replay and sticky replay within the same live session verify only a fixed
number of indexed rows (O(1) SQL calls and decoded rows; each SQLite B-tree
lookup remains O(log N)); a crash processes indexed pending rows and rollback
replays the missing suffix. End-to-end cold reconstruction after process
restart returns through AllocationProof and first audits the complete O(N)
allocator journal. That replay audit neither consumes a lifetime unit nor
draws noise or reads protected source. Old-schema migration and explicit audit
also require full-history work. The authenticated counts certify completeness and ordering and enforce
the configured lifetime maximum; status reports the remaining distinct-capsule
units separately from request limits.

The allocator itself follows the same rule. Its authenticated singleton binds
the immutable policy and peer, committed count, chain head, cumulative
epsilon/delta telemetry, committed-tail row MAC, optional prepared-head row
MAC, registry-eligible count, exact output count, and the query ID/row MAC of
the latest output mutation. Every state-machine write and the corresponding
singleton update occur in the same `BEGIN IMMEDIATE` transaction. Healthy
validation reads that singleton plus the expected allocation and output tails
through SQLite indexes; the operation then loads and authenticates its requested
`query_id` directly. It never scans all allocations or outputs.
If a legacy ledger has no singleton, one complete authenticated audit creates
it. Once its version marker exists, a missing or invalid singleton is an
integrity failure rather than an invitation to reconstruct state silently.

This constant-row check cannot discover arbitrary corruption of an unrelated
interior row in a flat SQLite history. Such a row cannot be consumed silently:
its keyed row MAC is checked when that capsule is addressed, and the explicit
forensic audit checks every row and chain edge. Immediate global detection of any
unaddressed historical bit change would require an authenticated tree and
O(log N) proofs. Whole-database replay likewise remains subject to the retained
peer/external-anchor assumptions below.

This does **not** solve simultaneous rollback of both peer ledgers to mutually
consistent old images. That is impossible to detect using only those restored
images. The existing custodian-provided durable linearizable CAS provider is
therefore supported as an optional per-peer strengthening and detects local
rollback before prepare. It is not an analyst option and is not a consensus
coordinator. Its current v2 state covers the allocation index and chain head,
not the separate `joint_outputs` delivery commitment. Production claims must
therefore retain the first assumption below for query-to-payload continuity;
the second currently strengthens allocation rollback only:

- at least one non-colluding designated peer retains and uses complete,
  independently durable authenticated monotonic history; or
- every peer also uses the external monotonic CAS anchor for the allocation
  chain (full result-spool rollback hardening additionally requires a future
  delivery-head anchor).

DSI itself offers neither fairness nor linearizable durable storage. The new
bridge treats it only as an untrusted transport for canonical, pinned-identity
signed receipts. A server-local HMAC prevents the analyst from fabricating a
proposal. Prepare uses two ordered DSI round trips—leader, then follower—while
the later symmetric phases retain one fan-out round trip each. Every phase has
a fixed byte bound, exact schema and generic public failure. Identical messages
are replay-idempotent after restart or a lost ACK; a conflicting fork fails
closed and may require availability recovery. The current control plane does
not advertise automatic liveness under adversarial scheduling.

The allocation ledger also pins one local noise-root key ID and privacy epoch. Rotation
is intentionally fail-closed until an explicit consortium epoch-transition
record is designed and tested; it never silently rebinds a prepared or
committed query to a new key. A conflicting prepared head is likewise a safe
availability failure, not an automatic refund/replacement. These are
pre-promotion limitations, not properties claimed for the final user-facing
package.

There is no query-count or rate limit in this allocator. Repeated methods and
arbitrarily many method arguments over an existing capsule are post-processing
and do not touch the allocation ledger. A new immutable snapshot/schema/epoch
creates a new capsule version, records another fixed per-capsule guarantee and
consumes one non-refundable lifetime unit. Once `N` units are committed, history
does make another capsule fail with the fixed typed exhaustion condition.

Only the internal adapter that constructs the complete vector capsule may mint
its identity and invoke this allocator. Adapters for models, tests and other
post-build operations must consume the already materialized capsule and must
not allocate again. This separation is a product-level invariant: the generic
allocator validates an explicit signed contract but cannot infer whether an
application-specific workload omitted a coordinate.

## Verification currently present

The focused suite covers canonical equivalence, fixed per-capsule allocation
versus `epsilon/K`, operation-independent replay across different methods and
arguments, exact lifetime boundaries, non-refunded aborted commits and typed
exhaustion, wrong peer/capsule-alias/snapshot/epoch/mechanism,
signature tampering, adversarial A/B ordering without a follower-side head,
every leader and follower durable prepare crash phase, every later allocation and
result durable crash phase, lost acknowledgements, one-peer allocation and
payload rollback, external-anchor rollback, concurrent identical
allocation/result prepares, and exhaustive enumeration of the former public
SHA commitment over a one-byte output domain. The product-bound vector
allocation tests additionally cover K=3 with a non-designated observer,
server-derived proposals, tampered signed allocation receipts, peer
substitution, exact replay and history gating. These are
in-process/mock-connector tests, not a claim of real Opal/Armadillo multi-host
E2E validation. No test opens protected data, a statistic share, a seed, noise,
or a persisted payload through a service API.
