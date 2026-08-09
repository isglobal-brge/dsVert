# Private cross-owner alignment gate audit (2026-08-02)

## Release decision

The categorical and Gaussian cross-owner routes are eligible for the single
production profile only when the recipient-specific alignment gate completes.
Their bind endpoints consume the gate's masked Ring128 file and cannot fall
back to the pre-gate aggregate store.

The exact claim is conditional: two pinned, semi-honest, non-colluding
computation peers; authenticated source custodians; server-owned immutable
snapshot/workload/alignment descriptors; and an untrusted analyst relay.  A
malicious computation peer, peer collusion, host compromise, source lies about
its own input, availability, physical timing, DSI scheduling and denial of
service remain outside this claim.

## Data path

1. Every participating source computes its local SHA-256 alignment digest and
   splits the 32 bytes into two deterministic XOR shares derived from an
   independent per-source secret.  Each designated computation peer receives
   only its recipient-specific share inside source-to-recipient AEAD.
2. For each public coordinate chunk and all K source custodians, the two peers
   feed additive Ring128 value shares plus their two 128-bit digest limbs into
   `alignment-mask-ring128`.
3. The fixed-shape circuit reconstructs the K digests internally, checks
   non-zero equality, and returns fresh additive shares of the complete value
   chunk or zero.  Value output masks are uniform Ring128 values; the terminal
   validity output alone uses one XOR bit.
4. Every chunk runs regardless of the mismatch source.  After all chunks are
   durably stored, the peers exchange signed, recipient-bound validity shares
   and open exactly one terminal outcome: `complete` or
   `alignment_contract_invalid`.
5. Only a `complete` batch is readable by cross-owner bind code.  An invalid
   batch deletes its masked file and releases its reservation.

When one immutable capsule contains both categorical and Gaussian cross-owner
artifacts, the client reuses this single capsule/contract-bound session and
completed gate. Family computations remain separated by distinct producers,
purposes, analysis/stage identifiers, artifacts, transcripts and numeric
certificates; no cross-family exact operation is reused.

No source digest, digest limb, per-source predicate, mismatch index, validity
share, additive aggregate share, masked aggregate share or exact intermediate
is returned through DSI.  K, coordinate count, public chunk geometry,
operation identifiers, exact-GC context, success versus terminal integrity
failure, and the ordinary signed artifact metadata are public.

## Relay and retry behavior

The malicious relay can drop, delay, reorder, duplicate or modify traffic.
Pinned signatures, recipient AEAD, exact peer/session/application contexts,
absolute offsets and idempotent state make the result one of authentic
delivery, exact duplicate or abort.  Start, store, seal and receive are safe to
retry after a lost acknowledgement.  A changed operation, chunk geometry,
context or peer blob aborts.  This statement does not cover physical timing or
availability.

Content, shape, phase and source-location alignment failures execute the same
public number of chunks and have the same semantic terminal token.  The
implementation does not claim that network timing, process scheduling, disk
backpressure or host-level traces are indistinguishable.

## Protected header HMACs

`private_snapshot_binding_mac` and `private_value_commitment_mac` are
domain-separated HMAC-SHA256 values.  Their key is the independent persistent
secret of the source server; their message binds the capsule contract hash and
source name.  They remain within recipient AEAD, are deterministic only for an
identical source contract/retry, are not public or enumerable digests, and are
not comparable across source custodians because those custodians use different
keys.  Neither HMAC is an input to the alignment circuit or its terminal gate.

## Correctness and accuracy

For equal, non-zero digests, reconstruction of the two output shares is exactly
the original Ring128 aggregate, byte for byte.  For any tested mismatch or an
all-zero absent digest, reconstruction is exactly zero and the terminal bit is
invalid.  No floating-point approximation or DP noise is introduced by this
integrity gate.

## Validation evidence

- Go circuit/protocol tests cover K=2, K=3 and K=5, every mismatch position,
  an all-zero digest set, fixed circuit/context shape, invalid K/ring/fraction
  contracts and full-width Ring128 output masks.
- The real two-worker authenticated spool integration covers valid K=2/3/5
  and a K=5 mismatch through worker launch, opaque byte pumping, canonical
  output validation and reconstruction.  The same integration completes the
  signed, recipient-encrypted terminal exchange for every valid K and the K=5
  invalid case, including exact retry and cross-peer replay rejection.
- Server R tests cover K-aware geometry, recipient-only digest-share records,
  uniform public failure, and the no-read-before-success invariant.
- Client R tests cover K=2/3/5, multi-chunk orchestration, deterministic
  operation binding, no share/hash fields, peer consensus and one terminal
  mismatch outcome.
- Adversarial relay tests cover dropped, duplicated, reordered, modified and
  replayed frames for K=2/3/5 under the stated malicious-relay boundary.

The suite proves implementation behavior under its stated model; it is not an
unconditional guarantee against colluding peers or compromised custodians.
