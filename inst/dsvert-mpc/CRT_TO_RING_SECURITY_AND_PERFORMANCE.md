# Exact private CRT-to-Ring boundary

Status: implemented and tested as an internal, unexposed MPC core. It is not a
client-callable endpoint and must not be promoted until the signed HE workload
adapter supplies its arithmetic certificate and the durable worker finalizer
consumes the resulting shares.

## Purpose

The linear HE accelerator evaluates independent odd-prime CRT lanes. The
nonlinear dsVert backend evaluates additive shares in `Z/2^kZ`. Reconstructing
the CRT result at a server and splitting it again would reveal the protected
aggregate to that server. Reinterpreting the CRT shares as Ring shares would
be numerically wrong.

`k2_exact_gc_crt_to_ring.go` converts without either operation:

1. The garbler derives a release- and coordinate-bound uniform pad `r` in
   `[0,P)`, where `P` is the CRT product.
2. It sends its CRT input share minus `r`, lane by lane, over the existing
   authenticated and encrypted exact-GC record channel.
3. The evaluator combines this with its share and reconstructs only
   `t=(x-r) mod P`. Given an unknown uniform `r`, `t` is uniform and independent
   of `x`.
4. A small Yao circuit with KOS-checked OT reconstructs `x=(t+r) mod P`, applies
   the signed CRT map, checks `|x|<=M`, and returns fresh additive Ring shares.
5. The validity result is itself XOR-shared. Any invalid coordinate neutralises
   the complete circuit tuple; no coordinate-specific public failure is
   emitted.

The masked-residue phase and the GC use one secure-record instance, so record
nonces and sequence numbers are never reset on the same transport. Its bundle
has a fixed schema, exact length, canonical residues, contract digest and an
acknowledgement over the authenticated bytes.

## Bound contract

The circuit can prove that the decoded modular value is within `M`; it cannot
infer whether an upstream computation had already wrapped before producing
its CRT residues. Therefore every accepted specification binds all of:

- the exact odd, pairwise-coprime plaintext primes and target Ring width;
- `P>2M` and a non-zero server-derived arithmetic-certificate hash;
- the logical release, an opaque HMAC snapshot handle and the pinned peer set;
- the number of upstream custodians (`K>=2`);
- the total coordinate count and authenticated chunk interval.

The production adapter must recompute the magnitude certificate from
server-side input/contribution bounds and the signed HE workload. Analyst
claims are not sufficient. Under that condition, the boundary never presents
a CRT wrap as a valid Ring result.

## Retry and chunking

Pads and output masks use HMAC domain separation and a custodian-only 256-bit
root. The release digest and global coordinate, rather than transport session
or local chunk offset, determine them. Therefore retry, restart and transparent
rechunking reproduce identical shares. Different snapshots, releases, roots or
coordinates receive independent PRF streams. Chunk validity masks are bound to
the exact chunk, avoiding mask reuse between different validity predicates.

The maximum circuit shape is a per-circuit resource envelope, not a query,
privacy or history quota. The production adapter must transparently split
larger vectors into authenticated chunks and combine every chunk-validity
share in the later protected finalizer; that adapter is still promotion work,
so the current internal core does not claim an exposed large-vector path.

## Threat boundary

The security claim is computational and uses the package's pinned,
semi-honest, non-colluding two-compute-peer model. The client/relay can drop,
reorder, replay or alter bytes, but authenticated records, sequence numbers,
contract binding and acknowledgements prevent an altered value from being
accepted. Such interference can cause denial of service, not a forged result
or plaintext opening.

Either compute peer alone sees only one Ring share and, for the evaluator, a
pseudorandom masked CRT opening. If both compute peers collude, they can combine
their inputs and outputs; this is an explicit exclusion, not something DP or
pinning can repair. A malicious custodian lying about its own data or violating
the signed bound is also outside the current semi-honest protocol and requires
malicious-secure proofs.

## Measured circuit cost

Apple M2 focal tests, one converted coordinate:

| Target | CRT lanes | Gates | Non-XOR gates | Typed input bits |
|---|---:|---:|---:|---:|
| Ring63 | 3 | 7,859 | 2,302 | 512 |
| Ring127 | 5 | 15,731 | 4,606 | 1,024 |
| Ring257 | 9 | 31,473 | 9,214 | 2,048 |

The initial direct-in-circuit CRT reconstruction used 1,158,560 gates for one
Ring63 coordinate. The masked-opening construction reduces that circuit by
about 147 times. The Ring63 real Yao/KOS-OT focal protocol completes in roughly
0.09 seconds on the same host; this is a development measurement, not a WAN
DSI service-level claim.

## Validation

`k2_exact_gc_crt_to_ring_test.go` covers:

- independent `big.Int` oracle checks for Ring63, Ring127 and Ring257;
- signed extrema, negative values, exact CRT carries and bound rejection;
- K=2, K=3 and K=5 workload binding;
- tuple-wide private neutralisation and shared validity;
- real Yao plus KOS-checked OT over the encrypted record layer;
- sticky retry/restart/rechunk behaviour and root-rotation epochs;
- release, source, pinset and arithmetic-certificate binding;
- malformed, non-canonical, truncated and tampered masked bundles;
- an exhaustive small-domain proof that the masked opening is a permutation;
- focal `go test`, `go test -race`, `go vet` and explicit gate accounting.

Remaining promotion work is intentionally explicit: production HE parameter
review, server-authoritative adapter, multi-chunk durable finalisation, DSI
process-separation tests and packaged-binary rebuild/checksums.
