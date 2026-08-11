# Formal GLM Phase 1.9: protected K-to-two fan-in

Status: internal research implementation; no R export, DSI command, runtime
capability, result opening, or production claim.

The provisional R Phase-1.9 schedule adapter and its
`formal-glm-phase19-v1` private state/output store were hard-deleted. This note
describes retained Go component evidence only.

## Implemented boundary

Phase 1.9 starts from an internal `verified-source-block` type. A block can be
created only after the Phase 1.8 payload has been authenticated and decrypted
at its designated compute peer. Its private coordinate shares, validity lane,
alignment gate and consensus SHA are omitted from JSON and protected against
in-process mutation with a domain-separated HMAC seal.

This boundary and the durable local finalizer which turns the Phase 1.8
recipient ciphertext into this Go type are executable and tested. They are not
registered on the R/DSI or Go command surface. Consequently the actual runtime
path is not wired, and `protected_data_e2e_verified=false` and
`production_ready=false` remain mandatory.

## Exact computation

For each public fixed-shape block and each of the two designated compute peers:

1. The fan-in requires exactly one authenticated block from every one of K
   custodians. Missing, duplicate, misrouted, type-confused, modified and
   conflicting replay inputs are rejected. Identical retries are idempotent;
   this is not a request counter or query quota.
2. Coordinate shares are added modulo the selected `2^ring_bits` ring. The K
   XOR-shared validity lanes, K XOR-shared alignment gates and K XOR-shared
   consensus-digest lanes remain private backend inputs.
3. The two fan-in receipts are paired by their context, run, block, recipient,
   pair commitments and block commitments. The relay can transport these
   receipts but cannot forge a different pair without the backend key.
4. An exact Yao/OT circuit validates both shares of every bit, reconstructs
   each lane with XOR, computes the exact all-K AND, and compares all consensus
   SHA limbs across K custodians and both compute peers. A zero or unequal
   consensus fails the private gate.
5. The circuit reconstructs each complete `(weight, X[1:p], y, offset)` tuple,
   validates the signed public bounds, indicator/outcome domains and public
   padding, and sets **all p+3 coordinates** to zero if any row condition is
   false. It does not clamp an invalid value into the valid domain.
6. The output remains two fresh additive coordinate-share vectors. A block is
   considered active only when at least one valid row has positive weight. Its
   activity is emitted as two fresh XOR shares and is never opened.
7. A second exact circuit validates the block activity shares and ORs them over
   the complete public block schedule. This prevents an all-neutralized dataset
   from being silently treated as a successful execution while revealing no
   validity bit to either peer or the relay.

Ring addition is deliberately modular because the input representation is
additive sharing over `2^k`. A reconstructed tuple is accepted only if its
signed representative satisfies the unanimously approved scientific bounds.
Thus a residue outside the domain cannot be silently wrapped or clamped into a
reported row. The existing numeric plan remains responsible for proving
headroom for the downstream formal-GLM kernel.

## Evidence and disclosure surface

The typed post-execution token binds:

- capsule, Phase 1.5 plan, pre-execution token, run and pinset;
- the Phase 1.8 global materialization root;
- both fan-ins, pair/block commitments and every masked-block receipt;
- the hidden execution accumulator and its two receipts;
- the authenticated final Phase 1.5 receipt pair;
- the execution, checkpoint and worker transcripts.

Final receipts and checkpoint evidence may transitively depend on protected
shares, so the public token contains keyed HMAC seals rather than their raw
digests. Consensus SHA values, alignment status, validity values, coordinate
shares and the accumulated execution-valid value never appear in the token or
JSON receipts. The token always records zero openings, blocks authorization,
and lists the remaining integration blockers.

## Threat model

The implementation assumes pinned compute-peer identities, authenticated
peer-to-peer key establishment, two non-colluding semi-honest compute peers and
an analyst/relay which may omit, reorder, duplicate, replay or alter traffic.
Those relay actions are detected by fixed source slots, typed contexts, HMAC
seals, pair commitments and session-bound secure-record transcripts.

Both servers must deliberately participate in the exact-GC sharing protocol.
The analyst cannot manufacture a valid peer input or receipt solely by
manipulating the DSI pool. A malicious custodian can still lie about its own
source row or deliberately collude with another protected party; preventing
that requires attested source execution or malicious-secure input proofs and
is not claimed here.

## Tested cases

The focused Go suite covers K=2, K=3 and K=5 for exact valid reconstruction,
all-K masking, missing and duplicate custodians, public padding, out-of-domain
ring residues, unequal consensus, invalid bit shares, route swaps, private
tamper, conflicting replay and type confusion. It checks that every invalid row
reconstructs to a zero **complete tuple**, that valid rows are bit-exact, and
that the real Yao/KOS-OT network path plus the hidden accumulator execute
between both designated peers. The post token is checked for tamper/replay and
for absence of private consensus, checkpoint evidence, row status and values.

## Remaining blockers

The signed Phase19 post token retains two release blockers under the pinned,
semi-honest deployment model.  The internal Phase20a handoff now durably seals
each peer's Phase19 output under that peer's server-local key material and feeds
the existing Phase16 one-draw/full adapters.  Each deployed peer opens only its
own source share; access to both server-local secret roots is collusion or host
compromise outside this threat model, not a cryptographic impossibility inside
one compromised process.  This component evidence does not make a remotely
callable analysis:

1. `registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1`:
   register and orchestrate the complete source-specific R/DSI lifecycle,
   bind the K-of-K final release receipts, and validate it over real
   multiprocess Opal/DSLite/Armadillo deployments for K=2 through K=5.
2. `joint_dp_release_consuming_hidden_execution_validity_v1`: make the joint DP
   release circuit consume the two hidden execution-valid shares, return a
   typed non-identifiable/invalid execution outcome without exposing the bit,
   and permit only the single authorized noisy release.

Phase20a also has one durability promotion blocker which is deliberately not
folded into the already signed Phase19 token:

3. `checkpoint_root_rotation_recovery_without_tamper_downgrade_v1`: add a
   durable, authenticated key-epoch continuity record before treating an AEAD
   authentication failure as key rotation.  With the current record there is
   no safe way to distinguish a lost/regenerated checkpoint root from tamper,
   so an existing undecryptable handoff remains fail-closed rather than being
   silently quarantined and recomputed.

Until all three are complete, Phase 1.9/20a must remain absent from the registered
R/DSI surface and advertised runtime capabilities.  The existing
`formal-glm-phase19-*` binary worker entry points are local implementation
details invoked with private configuration paths; Phase20a adds no command
handler, and no registered method may expose either phase.
