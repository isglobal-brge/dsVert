# Formal GLM Phase 1.8 protected-row materializer

Phase 1.8 is an internal, non-production boundary. It has no exported R
function, DataSHIELD `AggregateMethod`, runtime command, advertised capability,
or opening route. Its purpose is to turn server-owned vertical rows into a
fixed-shape encrypted input for the exact-GC formal binomial/Poisson GLM without
placing plaintext rows or shares on the analyst relay.

## Pre-execution authorization

The materializer accepts only the durable server-built biomedical capsule
manifest, the canonical formal-GLM artifact, the canonical Phase-1.5 plan, and
exactly one valid pinned approval from every one of the `K >= 2` custodians.
It checks the capsule, workload, schema, snapshot, source context, artifact,
kernel, plan, pinset, designated compute peers, cryptographic role selection,
fixed capacity, block schedule, coordinate ownership, adjacency, family,
missingness, patient-collapse policy, lattice, ring and container.

This is a distinct pre-execution type. It contains neither a Phase-1.7 release
token nor a worker token. Phase 1.7 binds a fan-in/execution transcript that can
exist only after materialization and execution, so it cannot be used
circularly to authorize the source rows that must exist before execution.

Recipient transport tickets are signed by the recipient's pinned Ed25519
identity and are bound to the capsule, plan, kernel, run, source context,
snapshot, pinset, designated role, transport key, capacity, layout, ring and
the Phase-1.9-only purpose. Both recipients must be the two designated pinned
compute peers.

## Protected row semantics

Each server resolves only its own immutable protected snapshot and its
custodian-owned dataset mapping. Patient identifiers are canonicalized and
sorted into a fixed public capacity. Every physical block always contains the
same number of slots; unused slots are zero-padded. Exactly one local record is
admissible per patient. Missing rows, duplicate rows, missing values, invalid
binomial outcomes, non-integer Poisson outcomes and unregistered categorical
levels set a separate local validity bit to zero. Numeric predictors, weights,
counts and offsets follow the signed clamp-then-quantize contract. Dyadic
rounding is exact round-to-nearest/ties-to-even, and exposure logs use the same
bounded exact-rational interval construction as the Phase-0 reference oracle.

Coordinates use the Phase-1.5 `p + 3` layout
`[weight, design..., outcome, offset]`. Only the signed owner supplies a
coordinate; all other local contributions are zero. Invalid local tuples are
zeroed before sharing, but this alone is not the complete vertical
missingness rule. A separate XOR share of each local validity bit is sent for
every custodian and slot. Phase 1.9 must compute the exact AND of all `K`
validity bits and mask the complete reconstructed tuple before the GLM kernel.
Treating an invalid predictor as a baseline value is forbidden.

Every signed lattice integer is range-checked against the selected signed
`2^ring_bits` domain before conversion to a residue. Coordinates are split into
fresh additive shares modulo `2^ring_bits`; validity bits are split into fresh
XOR shares. The container is fixed-width little endian and masked to the
declared ring. Modular wrap is never silently accepted.

## Alignment and fixed shape

The private PSI alignment token derives a source-local consensus digest over
the capsule, plan and canonical patient slots. The source converts both the
accept/reject gate and the 256-bit digest into recipient-specific XOR shares.
The masks come from a server-local, domain-separated HMAC PRF bound to the
capsule, plan, pre-execution token, run, source, block, recipient role and
release state. The same semantic block therefore receives stable private lanes
on retry, while the two recipient lanes remain computationally independent.

Each compute peer receives from each source only one random-looking gate share
and one random-looking consensus share. Neither encrypted header contains the
complete status or digest; public envelopes, bundles and receipts contain
neither a status field, a patient-derived digest nor a seal from which the
status can be tested. Only the exact Phase 1.9 two-peer circuit
XOR-reconstructs the gate and digest, requires an accepted gate and a non-zero
equal digest across all `K` custodians, and masks every row otherwise. A
missing/local-only PSI consensus therefore cannot become an accepted execution,
and the fan-in reveals neither the aggregate failure nor which remote source
caused it. A custodian necessarily still knows its own local PSI state; this
protocol prevents it from learning another custodian's state.

Each source emits an atomically committed pair of encrypted envelopes. Public
commitments cover ciphertext hashes and fixed metadata, never plaintext rows,
patient hashes, low-entropy validity vectors or shares. A local receipt is
issued only after every fixed block appears exactly once and passes its
purpose, run, pin, signature, ciphertext, pair and block commitments. Missing,
duplicated, conflicting or cross-run blocks fail closed. Retries of an
identical ciphertext bundle are deterministic evidence; they never mint new
source values.

## Post-execution binding and current blocker

A second, distinct post-execution type requires:

- one valid signed local materialization receipt from every custodian;
- the canonical all-`K`-signed Phase-1.7 source-contribution attestation;
- the canonical all-`K`-signed Phase-1.7 admission preimage;
- equality of all plan, kernel, manifest, workload, source, snapshot, pinset,
  role, capacity, adjacency, transcript, receipt-pair, release-instance and
  release-contract bindings; and
- equality of the release contract and worker transcript.

All `K` custodians must sign the resulting Phase-1.8 post binding. The only
result is an internal sealed token with `opening_authorized = false`,
`protected_data_e2e_verified = false`, zero openings and
`production_ready = false`. Pre/post substitution, cross-capsule/run replay,
signature omission and field tampering are rejected.

The internal Phase 1.9 implementation now performs the exact all-`K` validity
AND, private gate/digest consensus, complete-tuple masking and materialization-
root transcript binding. Phase 1.8 also has an authenticated, bounded,
crash-safe local ciphertext inbox and Go finalizer. The remaining typed blocker
is `formal_glm_durable_inbox_not_wired_to_phase19_joint_dp_release`: there is
deliberately no R export, DSI method or Go command joining these internal types,
and the joint-DP release does not yet consume the hidden execution-validity
shares.

Promotion therefore still requires runtime wiring over the reviewed DSI relay,
binding the resulting Phase 1.9 evidence to this R post-execution type, and
end-to-end K=2, K=3 and K=5 tests on DSLite, Opal and Armadillo. Until then,
Phase 1.8 makes no claim of public release or production readiness and performs
no opening.

## Verification in this phase

The focused R suite covers K=2, K=3 and K=5 signature sets and sealed
post-bindings; exact binomial and Poisson quantization; categorical domains;
missing values; duplicate patients; numeric clipping; fixed padding; accepted
and rejected PSI states with identical ciphertext/public lengths and no public
status literal; HMAC-seal forgery, swap and cross-block binding; purpose-bound
tickets; ciphertext and metadata tampering; incomplete/duplicate/replayed
blocks; pre/post type confusion; ring no-wrap rejection; and the absence of any
registered or exported Phase-1.8 method. It also covers byte-identical durable
outbox replay without rematerialization/re-encryption, authenticated inbox
replay/conflict/tamper, owner-only key bootstrap/rotation epochs and a shared
R/Go binary framing golden vector.
