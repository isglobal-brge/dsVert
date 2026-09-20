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
identities before repacking predictor, outcome and routing-label shares. The
alignment protocol already opens its global admission result; only a true
result reaches complete status. That public result is canonically XOR-shared
as owner 1 / peer 0 so reconnects preserve identical worker source bytes even
if the alignment circuit uses new output masks. Private row presence and all
downstream candidate validity remain private and are never replaced by true.
The owner sidecar binds the source snapshot, value and private alignment MACs.

The server-local `grouped-lmm-staged-prepare-v1` command consumes exact decimal
parameters and returns opaque native worker material. No aggregate endpoint
exposes it. `grouped-lmm-staged-v1` returns local Ring128 shares, packed candidate
validity, terminal receipt and plan digest. A durable authority-keyed source
binding rejects replaced source material even when cold replay skips callbacks.
All configuration material stays outside public receipts; the durable directory
must survive disposal of an ephemeral transport spool. The worker draws no noise.

## ML variance grid and terminal DP validity

The optional typed `Objective="ml"` and ordered `VarianceGrid` extend LMM with
`r'V^-1r + log|V| + n*log(4)`. Coefficient candidates remain unique; terminal
coordinates are variance-major then coefficient-major, with V*K signed caps.
The first variance matches the legacy Numeric fields. Empty optional fields
preserve the fixed-covariance graph and its serialization.

The ML graph computes exact moments once, then branches precision and loss
arithmetic per variance. A private live count selects an exact rational,
upward-rounded q64 log table. Its shifted determinant is added at f264 before
clamp/quantization. `NUMERIC_CERTIFICATE_LMM_ML.md` proves the log enclosure,
12B bound and retained 1e-8 error allowance. REML remains unadmitted.
Both R validators bind the ML objective, certificate bytes, canonical variance
order, expanded caps and candidate identities. Source preparation preserves
all variance bits as decimal strings. Public preparation now also returns the
expected `stage_plan_digest`, which R checks against the worker terminal.

The internal R lifecycle connects source preparation to the typed worker and
persists complete losses, private candidate validity and terminal receipt. A
separate MAC-protected public binding row is committed atomically; sampler
planning reads that row without loading private losses before its START claim.
Private injection follows the existing claimed source boundary. The client
compares both authorities' signed stage identities and persistence receipts.

The existing discrete-Laplace sampler optionally binds `source_stage_plan_digest`
and requires packed `source_validity` in its private worker config. The circuit
ANDs all incoming XOR bits with its range checks and gates the terminal result.
Neither bit shares nor attempt-varying stage receipts enter the noise identity.
The empty legacy path preserves circuit source and digests. Canonical lengths,
padding bits, missing validity and extra validity are checked before readiness.
Staged LMM rejects non-exact Synopsis samplers before START and rejects the
legacy capsule lifecycle, whose source encoding cannot retain this private
validity contract. Only the integrated Synopsis exact-GC route is supported.

## Remaining integration

The signed public workload catalogs and grouped release reader remain closed.
Connect their admission, client source-layout projection, artifact validation
and released-coordinate reader to the completed internal path. The actual
pinned-identity garbler must own routing; owner name order does not set roles.

A real internal n2000/C500/B4/p3/J2 fixed-covariance worker completed all 244
stages with an independent integer oracle, 6,222,758,629 computation bytes and
715.079 seconds. Cold replay, source/stage tamper rejection, and actual late
bilateral/unilateral stage recovery passed. This is authenticated synthetic
source/worker evidence, not production owner materialization, the new ML grid,
or a DP release. It does not raise the signed C<=64 production guard.

Prove the first complete signed LMM n2000 ML release, including actual owner
materialization, sticky DP, bilateral/unilateral recovery, cold replay and
source/stage tamper rejection. Measure complete-family C500/frontier capacity
under 256GB/6h and run the full paired suite before promotion and before moving
to GLMM binomial. No family promotion or full paired-suite result is established.
