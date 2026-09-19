# Internal staged durable executor

This is an implementation checkpoint, not a release admission. The production
R dispatcher and the six structured release readers remain closed. The retained
GEE v3 producer/certificate, GH5 factorial exclusion, Cox bridge, exact OT
products and independent oracles are unchanged.

`cross_grid_stage*.go` implements a two-authority durable stage graph.
`k2_exact_gc_lmm_staged.go` composes the retained LMM arithmetic from an already
authenticated, routed Ring192 input to Ring128 candidate losses. It does not
implement source routing, an ML/REML variance grid, or the R release handoff.

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
data and must be distinguished from arithmetic correctness by the source/router
adapter. That adapter is not yet implemented.

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

## Section C arithmetic correction still required

The literal masked-lift formula in EXECUTOR_SPEC.md C omits modular carry. For
M=2^128, x=1 and r=M-1, it opens z=(x+r) mod M=0 and computes z-r=1-M in
Ring192, not 1. In general the exact unsigned lift is

    z - lift(r) + [z < r] * M.

Signed fixed-point extension also subtracts `[x >= M/2] * M`. Both bits must
remain private. A private reconstruct/sign-extend/remask circuit is an available
implementation, but the literal three steps cannot satisfy exactness. Tests
retain the counterexample and the corrected integer identity. No incorrect
conversion or public carry has been implemented; correction was raised to the
reviewer during this cycle.

## Remaining integration

1. Authenticate the grouping owner's actual private routing controls against
   the source snapshot/PSI order; pack once using fixed public switch topology,
   preserving padding and original slot gaps.
2. Implement the corrected private Ring128-to-Ring192 conversion and connect
   signed materialization/routing to the new executor.
3. Complete the signed family adapter and R lifecycle/worker/DP handoff. The
   retained LMM certificate is a fixed-variance quadratic objective; do not
   relabel it as a new ML/REML variance-grid implementation.
4. Prove LMM at n2000 with bilateral/unilateral recovery, cold replay, tamper
   rejection, paired tests and measured capacity under 256GB/6h before moving
   to the next family. C<=64 remains the signed production guard; C500 in a
   graph-shape test is not measured admission.

No family promotion or full paired-suite result is established here.
