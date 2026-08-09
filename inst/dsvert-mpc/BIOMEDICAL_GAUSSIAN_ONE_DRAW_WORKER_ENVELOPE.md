# Biomedical one-draw Gaussian worker envelope (sealed v1)

## Status

This is a production-shaped admission contract, not a production release.
`ProductionReady` is always `false`, `OpeningsAuthorized` is always zero, and
this phase adds no command, runtime capability, R/DSI decoder, or opening.

The generic one-draw contract remains an internal numerical/GC harness. Its
legacy `machine_proven` certificate cannot authorize this route. Biomedical
policies carry the distinct status
`biomedical_machine_derived_typed_layout_pending_materializer_e2e_v1` and require the
typed K-of-K envelope before a worker may accept protected input.

## Worker admission contract

The worker verifier checks, in order:

1. A local trust root containing the reviewed worker-artifact digest and the
   complete sorted Ed25519 pinset. Public keys are never accepted from the
   envelope.
2. Exactly one valid signature from every one of K pinned custodians. K=2,
   K=3, and K=5 are covered by adversarial tests.
3. Canonical, domain-separated envelope bytes binding capsule, manifest,
   schema, workload, an opaque logical-snapshot handle, privacy epoch, release
   instance, release contract, worker transcript and run nonce.
4. Exact mechanism, allocation, plan, worker-policy, worker-contract, circuit
   and implementation digests.
5. Adjacency and the machine-derived typed-domain sensitivity certificate.
   The manifest no longer accepts free-form squared-sensitivity components.
   It declares an ordered partition of patient-contribution blocks: dense
   boxes, one-hot families, constant vectors, finite allowed profiles or
   non-negative integer monomial grids. Go derives the add/remove norm or
   replace-one diameter in exact integer arithmetic. Constant, profile and
   monomial types preserve count/moment/pair/survival coupling instead of
   silently treating coupled coordinates as an independent box.
6. Canonical epsilon/delta decimals plus their unique reduced rational
   numerator/denominator. Equivalent spellings such as `1.0`, `1e0`, `1/1`
   and non-reduced `2/2` are rejected.
7. A single pre-materialized integer lattice. Every productive scale shift is
   zero, every upper bound is a canonical integer, and the full coordinate
   order and bounds are bound in every chunk. Alternative raw/shift
   factorizations are rejected.
8. Release-stable, server-HMAC-derived snapshot and materialization handles,
   an HMAC-derived or public-data-independent source-contract handle, and
   idempotent typed reservation references. Every relay-visible handle and
   reservation digest carries an explicit contract forbidding patient-, row-,
   membership-, alignment- or value-derived unkeyed hashes.
9. A local materializer binding for the exact role-specific `SourceShare`.
   The binding includes the public snapshot/source handles and the private
   snapshot/source-contract digests, epoch, release, materialization root,
   receipt, run nonce and envelope digest. A changed share is rejected before
   it can be passed to the GC runner.
10. The run nonce equals the exact-GC session identifier and the private seed
    matches the commitment for the locally pinned role.

The complete worker policy (including the legacy release-binding JSON) is
`json:"-"` local handoff state. Neither its unkeyed digest, the full circuit
digest, the full circuit purpose, nor either release-binding digest is
relay-visible. The K-signed token contains an explicit allow-list projection
of public policy fields and a data-independent circuit-shape digest. The real
snapshot/source digests therefore do not appear directly or as public
dictionary-testable commitments in serialized tokens. The verifier still
validates the full local policy, release binding and circuit digest before
execution.

Chunk geometry and the retry/session nonce are signed but excluded from the
productive sticky-noise stream. Absolute-coordinate derivation therefore
remains invariant under rechunking/retry. Release instance, privacy epoch,
opaque snapshot handle, opaque source-contract handle, materialization root and
release-stable reservation references are included in a second
domain-separated stream binding. Snapshot/materialization handles and
reservation digests are deterministically regenerated or durably memoized for
the same release+logical snapshot+workload, including after crash, restart or
rematerialization, so that reconstruction does not reroll noise. Before a
capsule's first valid START claim, a lost or rotated root changes the candidate
`release_instance_id`; it must never silently assign a new root to the old
candidate. Once claimed, the exact instance must continue or be restored, or
fail closed; a replacement root cannot create a sibling release for that
capsule.
`WorkerTranscriptSHA256` is explicitly a release-stable DP transcript, never a
transport session, reconnect or ACK transcript. Transport/ACK receipts are not
accepted receipt types and cannot enter the DP stream.

The sealed execution wrappers pass this productive stream into both peers'
private noise derivation and the garbler's per-absolute-coordinate output-mask
derivation. The generic runner is not used by the biomedical wrappers.
Rechunking/retry produces identical words, signs, coordinate masks and validity
mask; changing release/epoch/source handles changes the productive streams and
masks. The wrappers return shares only and still expose no command/opening.

## Trust boundary

The trust root and local materializer binding must be supplied by server-local
configuration/handoff code. Their authority does not come from the analyst,
relay, envelope, or the unkeyed integrity digest on the local binding. Replacing
the local trust root is an administrative trust-root rotation, not a token
operation. A token signed by foreign keys or carrying a substituted pinset is
rejected against the existing local root.

The threat model still assumes the pinned custodians follow the admission
protocol and at least one of the two designated noise peers is honest and
non-colluding. K-of-K authentication proves agreement and origin; it cannot
make a unanimously false custodian assertion true.

## Explicit blockers before production/opening

- Make the server-authoritative materializer enforce the exact typed
  contribution layout against collapse, clipping, missingness, coordinate
  transform and adjacency before it writes shares. The Go certificate is now
  machine-derived and exact for its declared typed domain, but K-of-K agreement
  about a descriptor does not by itself prove that protected rows followed it.
  `UnitCapacity` fixes padded aggregate shape and no-wrap bounds; it is not a
  patient-sensitivity multiplier because one adjacency changes one collapsed
  contribution (or replaces one contribution).
- Wire the local materializer and trust root into the durable worker process,
  and then through durable DSI dispatch, with the same ownership, mode, symlink
  and atomic-handoff checks as the sensitive worker config. Persist an
  idempotent mapping from release+logical snapshot+workload to its HMAC handles
  and reservation digests. Reissuing or reconstructing the same release must
  return the same mapping; root loss/rotation may change a candidate only before
  the first valid START claim, while a claimed capsule must continue or restore
  its exact instance or fail closed. The pure verifier exists now; durable
  dispatch and registry are intentionally not simulated by this phase.
- Verify a durable append-before-release privacy-ledger receipt. Accounting is
  telemetry/composition state and must not impose request-count, operation-count
  or history-based denial.
- Implement exactly-once release memoization and a durable finalizer so the
  same release cannot be evaluated against a second source while reusing its
  sticky noise.
- Keep the exact-CDF one-draw GC sealed until a reviewed compact oblivious
  lookup exists. Benchmarks show linear `M-1` circuit work despite logarithmic
  logical depth; Phase-1.6 p=2 used 6.58 GB of compiler allocation. The 6-GiB
  per-circuit projection guard now forces one-coordinate chunks for that shape
  without limiting request history. The scalable two-independent-full-draw
  Gaussian route is an explicit alternative with the same conditional
  `(epsilon,delta)` guarantee under the one-honest-peer model and a signed
  variance-x2 / standard-deviation-x-sqrt(2) utility certificate. It must be
  selected and bound into a biomedical release explicitly, never substituted
  automatically.
- Add the server-authoritative R/DSI projection and permit exactly one common
  DP-vector opening only after all preceding checks succeed.

Until every blocker is closed, receipt hashes in the envelope are signed typed
references/reservations, not proof that the durable ledger/finalizer
implementation exists or has committed.
`release_finalizer_reservation` is a pre-worker authorization/precommit; it is
not a receipt for a result that has not yet been computed.
