# Internal staged durable executor

This is an implementation checkpoint, not a release admission. The production
R dispatcher and the six structured release readers remain closed. The retained
GEE v3 producer/certificate, GH5 factorial exclusion, Cox bridge, exact OT
products and independent oracles are unchanged.

`cross_grid_stage*.go` implements a two-authority durable stage graph.
`k2_exact_gc_lmm_staged.go` composes the retained LMM arithmetic from an
authenticated, routed Ring192 input to Ring128 candidate losses. Cycle7 joins
authenticated typed sources, private routing and exact conversion to that graph
through `k2_exact_gc_lmm_source_staged.go`. The typed background worker uses the
existing spool/heartbeat protocol. The public R release lifecycle remains closed.

## ABI and authentication

An internal family adapter supplies the authenticated signed schema digest,
semantic release key, durable session identifier, two pinned authorities and
ordered typed stages. The executor does not accept analyst-supplied kernels.
Each stage pins its ring (128 or 192), fixed-point scale, canonical coordinate
order, public bounds, source/profile digests and predecessor identifiers.
The graph is copied before execution. Stage records additionally bind the
predecessor receipts, joint attempt nonce, both masked-share commitments,
receipt, output mask domain, private masked share and authority-local share MAC.

Words are little-endian additive shares. Validity is one XOR-shared bit in one
byte per coordinate. Private kernels conjoin source, profile and product
correctness; local AND of shares is forbidden. Private presence/live bits are
data and are distinguished from arithmetic correctness by the source/router
adapter. The adapter privately verifies binary presence, normalized numeric
bounds, source/sidecar label equality and grouping capacity. Missing values
retain their original within-cluster slots. Numeric f50 and metadata q0 are
separate source stages; the routed result is homogeneous f50.

The reserved consecutive coordinate names `<coordinate>:limb:0` and
`<coordinate>:limb:1` describe one little-endian Ring384 additive share carried
in two Ring192 words. They retain the existing LMM f264 representation. The
output refresh carries across both limbs; independent Ring192 refreshes would
corrupt the value. Malformed or non-Ring192 limb pairs are rejected.

The content receipt binds the complete public plan, stage identifier,
predecessors, source/profile digests and both commitments in authority order.
Each local share MAC derives its key from the authority-local storage secret
and (durable session, stage, attempt nonce, authority). A separate record MAC
authenticates all state and metadata. Peer messages use the existing pinned
authenticated exact-GC session with a fresh bilateral nonce-derived encrypted
record context on every connection, including cold recovery. Private outputs
are never returned in metadata messages.

## Commit and recovery

The private authority directory is locked for the complete graph. Writes use
owner-only temporary files, atomic rename, file fsync and directory fsync.
Acknowledgements follow durable writes. Only the exact persisted PREPARE may
become COMMIT; committed records cannot be overwritten.

| Observed pair | Action |
|---|---|
| COMMIT / COMMIT | Authenticate, require identical attempt/receipt/commitments, reload shares |
| COMMIT / PREPARE | Require identical persisted attempt/receipt/commitments; promote that PREPARE without recomputation |
| Neither COMMIT | Both durably erase abandoned outputs, acknowledge ABORT, jointly generate a fresh attempt and recompute |
| COMMIT / missing or different peer record | Reject; never regenerate a complementary share |

RUNNING records reserve attempt context before a private kernel begins. PREPARE
persists the output before the receipt exchange. COMMIT follows matching durable
PREPARE receipts, and a final bilateral acknowledgement precedes downstream use.
Every fresh attempt has a new OT/session master-key domain and output-mask
domain. Kernel subcalls also require distinct purpose domains.

The final opened artifact is **f(true sufficient statistics, sticky semantic
seed)**. Attempts, receipts, share masks and transport sessions are absent from
the semantic seed. The executor draws no noise; a family adapter must hand the
committed terminal vector to the existing sticky DP lifecycle exactly once.
The synthetic protocol test uses that real joint-noise circuit with fixed
semantic seeds, kills OS authority processes during a private exchange and at
PREPARE/COMMIT boundaries, restarts from disk, and compares exact final bytes
with the independent integer/noise reference. Cold replay forbids kernel calls.
This test does not substitute for a DSLite family release.

## Approved Section C conversion

The reviewer approved the private carry correction in cycle7. The original
formula failed at M=2^128, x=1 and r=M-1. The canonical unsigned lift is

    z - lift(r) + [z < r] * M.

Signed extension also subtracts `[x >= M/2] * M`. The implementation in
`cross_grid_stage_conversion.go` privately creates the dual-ring mask from
independent uniform local contributions, opens only z through an attempt-scoped
encrypted channel, and computes the carry/sign correction inside GC. Neither
comparison bit is opened. The stage retains scale, coordinate order and sticky
validity, with its own durable MAC and receipt. Masks are never obtained by
locally widening Ring128 shares or deriving them from a shared transport key.
Both named acceptance tests and real signed/unsigned private-protocol,
bilateral/unilateral recovery and cold-replay tests pass on pod4.

## Source and worker handoff

`cross_grid_grouped_route.go` authenticates the owner-local routing sidecar,
re-derives stable Beneš controls, normalizes at most 16 rows per circuit and
uses fixed public checked-OT tiles of at most 4096 words. The grouping owner
must be the actual garbler in this adapter. Labels, controls, counts and raw
label digests never enter a public plan. LMM admission pins normalized values
to [0,2^50] and checks public beta endpoints with the retained encoding slack.

The R source loader verifies signed contract/layout/snapshot/peer bindings,
the existing successful alignment gate and actual private-store MACs and chunk
identities before repacking predictor, outcome and routing-label shares. It
carries the alignment circuit's XOR validity into every source coordinate.
The owner sidecar binds the source snapshot, value and private alignment MACs.

The server-local `grouped-lmm-staged-prepare-v1` command consumes exact decimal
parameters and returns opaque native worker material. No aggregate endpoint
exposes it. `grouped-lmm-staged-v1` returns local Ring128 shares, packed candidate
validity, terminal receipt and plan digest. A durable authority-keyed source
binding rejects replaced source material even when cold replay skips callbacks.
All configuration material stays outside public receipts; the durable directory
must survive disposal of an ephemeral transport spool. The worker draws no noise.

## Remaining integration

1. Connect the internal source loader, preparation and typed worker to the
   authenticated R lifecycle, its terminal validity gate and sticky DP handoff.
   The public catalogs and grouped release reader remain closed. The actual
   pinned-identity garbler must own routing; owner names alone do not set roles.
2. Reconcile the signed family scope with the requested ML/REML language. The
   retained LMM certificate is a fixed-variance quadratic objective; do not
   relabel it as a new ML/REML variance-grid implementation.
3. Prove LMM at n2000 with bilateral/unilateral recovery, cold replay, tamper
   rejection, paired tests and measured capacity under 256GB/6h before moving
   to the next family. C<=64 remains the signed production guard. A completed
   n2000/C500/B4/p3 router component measured 1,037,600,408 two-way bytes and
   193.021 seconds with exact oracle equality; it omits owner materialization,
   LMM arithmetic and DP and therefore does not admit full-family C500 capacity.

No family promotion or full paired-suite result is established here.
