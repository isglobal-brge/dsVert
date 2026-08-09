# Biomedical Gaussian independent-full backend (internal boundary)

This checkpoint connects the machine-derived biomedical contribution layout to
the scalable fixed-work Gaussian worker without adding an R function, DSI
endpoint, command, runtime capability, `main` dispatch, `NAMESPACE` export or
packaged binary.

The exact selected backend is
`independent_full_global_dyadic_discrete_gaussian_tv_bounded_ring128_v2`.
It is a K-of-K, server-authoritative field in a separately domain-separated
signed contract. The builder has no backend argument and no sensitivity
argument. Consequently neither the relay nor a caller can request the sealed
one-draw implementation, substitute another sampler, or supply a smaller
sensitivity. The one-draw exact-GC code remains a sealed numerical reference;
there is no automatic fallback in either direction.

## Privacy and numerical certificate

Each of the two designated peers uses the complete capsule epsilon and delta
and independently samples a full, finite-support, TV-accounted discrete
Gaussian vector. The public release law is their convolution. Conditional on
the view of the analyst plus either one designated peer, the other peer's full
calibrated draw remains; under the authenticated semi-honest fan-in
precondition this gives the stated per-release `(epsilon, delta)` guarantee.
Delta is therefore `max(per-peer delta)`, not their sum. This route assumes at
least one of the two designated peers is honest and non-colluding; collusion of
both designated peers is outside the model.

The utility cost is explicit: nominal variance is twice the variance of one
full draw and nominal standard deviation is multiplied by `sqrt(2)`. The
certificate includes the exact rational epsilon/delta fields, the backend,
sampler, adversary view, machine-derived L2 sensitivity, finite-support/TV
plan and the Ring128 no-wrap proof. For every coordinate, the exact shifted
source upper bound plus the maximum magnitude of both peer draws must remain
inside signed Ring128. Otherwise admission fails; modular wrap is never
reported as a numerical answer.

## Sticky identity and rotations

The deterministic HKDF-SHA256 seed domain binds the logical release, release
instance, privacy epoch, manifest, workload, pinset, both opaque noise-root
epochs, logical snapshot handle, source-contract handle, materialization root,
append-before-release reservation and all typed reservation receipts. The
coordinate sampler additionally uses the absolute coordinate. Retry,
rechunking and local admission reconstruction therefore reproduce identical
draws and bytes.

The two roots must be independently generated and held by their respective
peers; sharing the same root across peers would invalidate the one-honest-peer
argument and is not claimed to be safe. Admission compares peer-independent
HMAC root-epoch fingerprints and rejects an accidentally cloned root. This
detects equality without revealing a root, but cannot prove that two distinct
roots were never copied between deliberately colluding custodians; that case
remains outside the stated threat model.

Noise roots never enter the signed contract. Each peer publishes only an
HMAC-derived opaque root-epoch handle and a seed commitment, then verifies its
own root against the K-signed commitment locally. Loss/rotation of a root may
change a candidate release instance only before the first valid START claims
the capsule at that peer. Attempting to use a sibling candidate after the claim
fails before another sampler runs. A pinset change belongs to a different
capsule identity rather than rebinding the existing capsule. Once claimed, the
capsule must continue or restore that exact instance or fail closed; after
publication it may only replay/restore it and can never silently reroll or
publish a second instance.

Relay-visible digests are explicitly declared as data-independent public
projections or release-stable server-HMAC handles. An unkeyed hash of patient
identifiers, alignment membership, row order or protected values is not a
valid implementation of these fields.

## Durable handoff and remaining blockers

The worker does not accept a loose `SourceShare`. The authoritative local
materializer first creates a non-serializable binding over the exact share,
chunk, local snapshot/source contracts and the K-signed release handles. The
worker verifies that binding, its local noise root and its pinned Ed25519
identity. It then signs the digest of its exact-backend noised share and source
binding. This prevents an analyst/relay from replacing either an input share
or a noised peer payload before finalization.

A typed finalizer handoff verifies both pinned peer signatures and binds the
privacy-ledger reservation and the exactly-once finalizer reservation. Its
private finalizer input, source bindings, noised shares, output digests and
signatures are omitted from routing JSON, and the handoff authorizes zero
openings.

Promotion remains blocked until the concurrent Phase 1.8 recipient-specific
alignment handoff, the R/DSI verification of the durable append-before-release
receipt, and the exactly-once memoized release finalizer are linked end to end.
This checkpoint deliberately does not bypass those dependencies or advertise
the route as production-ready.

The pre-existing generic Gaussian planner/share/finalizer commands and R
vector lifecycle are not implicitly upgraded by the presence of this file.
They become part of this biomedical route only after they consume the K-signed
selection, local source binding, signed peer-share envelope and durable receipt
handoff defined here. Until then, this admission remains internal and sealed.

## Validation recorded

- K=2, K=3 and K=5 admission and execution.
- Exact K-of-K signature cardinality.
- Re-signed backend, release, snapshot, source, materialization, reservation,
  plan and history-denial substitutions rejected.
- Retry, alternate chunking and reconstructed admission produce identical
  noised bytes.
- Pre-START root rotation changes only the candidate release instance; after
  the claim, sibling progression/resampling is rejected. Pinset rotation creates
  a different capsule identity rather than rebinding this capsule.
- An identical noise root provisioned at both designated peers is rejected.
- No caller-controlled sensitivity field and no serialized private noised
  shares.
- Loose/substituted source shares, wrong local signers and relay-substituted
  peer outputs rejected.
- Ring128 global headroom checked with exact integers.
- On Apple M2, cached per-chunk admission validation for an 8192-coordinate
  manifest measured about 37 microseconds, versus about 52 milliseconds for a
  complete K-signature/layout revalidation; the complete 8192-coordinate peer
  worker (sampling, bindings and signature) measured about 43 milliseconds in
  the same three-run benchmark. The complete admission validation is done once
  when reconstructing the internal admission; each chunk verifies the compact
  admission seal and current local pinset.
