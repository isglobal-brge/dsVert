# dsVert (development version)

### Security hardening

* `dsvertTransportProbeDS()` retains its exact three-argument v1 request
  acknowledgement and adds an optional, stateless response-padding probe. The
  extension returns only bounded public `R` padding and its digest, has an
  independent 8 MiB server hard cap, and never opens protected data, MPC state
  or a privacy ledger. Capsule-source scalar bundle/envelope limits remain
  768 KiB/1 MiB for byte-identical compatibility, while attested outer source
  and recipient windows are separately bounded at 8 MiB; every inner envelope
  and acknowledgement retains its existing signature and hash. The existing
  `byte-window-v1` negotiation now continues to enforce exactly 768 KiB/1 MiB;
  only the new, fully attested `adaptive-window-v2` contract selects 8 MiB.
  Within one synchronously deployed DSV1 client/server generation, omitted
  adaptive framing arguments retain v1, so adaptive v1 and v2 peers can
  coexist. DSV1 itself is a deliberate lockstep wire change: client and server
  packages must be upgraded together, and a mixed package generation fails at
  the first framed, data-free manifest phase before protected data access. A
  safe staged rollout is server-first with release traffic paused: deploy,
  reconcile and attest every server, verify the data-free framing boundary,
  and only then deploy the paired client. The intermediate mixed state is
  deliberate fail-closed downtime, not backward compatibility.

* `dsvertSecurityProfileDS()` now reports deployment-surface readiness only
  when the connector-neutral, custodian-owned attestation matches the
  deterministic alias-free contract computed from the installed
  `DESCRIPTION`. Opal may persist the token in its dedicated server profile;
  Armadillo/Rock may provision the same token only in the server/container
  environment after native admin tooling verifies the effective inventory.
  Missing, malformed, conflicting or mismatched attestations make
  `formal_dp_claim_eligible` false. The response explicitly records that this
  is an administrative assertion which becomes stale after any later surface
  mutation; it is not presented as live connector introspection and is never
  generated automatically or supplied by the client. Schema v4 adds a
  typed route map: the compatibility field is scoped only to biomedical
  joint-DP profile/surface eligibility, runtime consortium readiness requires
  the client handshake, and formal GLM/Cox remain explicitly not ready.

* Exact-GC setup now derives its two accepted computation peers exclusively
  from the server's joint-DP policy, including for K=3--5 consortia. Its
  canonical session binding commits the complete pinset hash, designated pair,
  signed identities, ephemeral transport keys, capability and session; relay
  omission, injection, relabelling, key swaps and payload tampering fail closed.
  All authenticated full-peer, typed-blob, exact-GC and padded-PSI binds now
  require a persistent server-authoritative `dsvert.peer_name`. Public identity
  discovery and transport bootstrap remain available for provisioning, but a
  relay-supplied connection name is never trusted as the local role.

* Replaced the selectable `strict_dp` / `legacy_exact_mpc` profiles with one
  immutable `disclosure_safe` profile. No environment variable, R option or
  installed test-mode switch can enable retained exact/adaptive endpoints.
  The central deny gate remains in place while each public family is migrated
  to a purpose-bound DP/MPC contract.

* Removed the production DP enable switch and the legacy decay/partition
  selectors. The v9 server policy always uses fixed per-capsule epsilon/delta
  and adds the custodian-owned
  `dsvert.dp.lifetime_max_distinct_capsules` bound (default `1`). Exact-decimal
  policy validation requires `N * epsilon <= 8` and `N * delta < 1`. A local
  allocator commit consumes one durable unit before protected-source access or
  sampling, including when the later protocol is abandoned; it is never
  refunded. The fixed, detail-free
  `[dsvert_dp_lifetime_budget_exhausted:v1]` condition is an opaque terminal
  union: either global `N` is exhausted, or the requested capsule is already
  irrevocably bound to its claimed/published release instance and that exact
  instance cannot safely continue or replay. It therefore does not imply
  `remaining_distinct_capsules == 0`; separate tokens would expose state.
  This is a privacy-loss/publication-safety gate, not a request counter:
  byte-identical replay of the same
  capsule/release instance and all of its post-processing remain unlimited and
  do not reduce accuracy. The geometric allocator remains reachable only
  through a non-exported unit-test constructor. Joint-DP capsule status v5
  scopes the bound to
  `at_most_N_immutable_snapshot_workload_capsules_per_stable_privacy_accountant_namespace`.
  It binds both the requirement that at least one non-colluding designated peer
  `retains_and_uses_complete_authenticated_monotonic_history` and one stable,
  unique privacy accountant namespace across domain, cohort, policy, pinset and ledger
  reconfiguration for each protected privacy universe. Namespace continuity is
  currently a custodial deployment assumption, not package enforcement or
  automatic counter migration. Status explicitly declines protection against
  simultaneous rollback of both designated histories without an external
  linearizable CAS.

* Added a server-authoritative primitive workload scope for the reusable DP
  capsule. The compatibility default `all_schema` preserves every bounded
  univariate and same-owner pair. The recommended `catalog_v1` includes only
  custodian-declared primitives plus deduplicated describe, Gaussian, survival,
  and vertical-cross dependencies, eliminating implicit quadratic pair cost
  for large schemas. The manifest certifies the normalized scope, projected
  coordinates and sensitivity; it is bound into capsule identity, source
  context, authenticated cache and signed peer builds, and cannot be expanded
  by an analyst query. Scope mismatch fails before protected snapshot access.

* Froze the pre-release biomedical vector ABI at PREPARE v6;
  START/RESULT/RELEASE/ACK v5; STORE v6; claim row
  `dsvert-joint-dp-vector-instance-claim-v1`; authenticated claim-set state
  `dsvert-joint-dp-vector-instance-claim-state-v1`; and replay v4.
  Every public phase receipt
  is signed, and every signed receipt plus replay attests exactly
  `history_gate=TRUE`, `request_limit=FALSE`, and `operation_limit=TRUE`.
  STORE v6 makes both HMAC-authenticated per-capsule claim artifacts required
  durable invariants. There is no automatic
  migration or re-signing of earlier v4/v5 stores: rollout requires empty DP
  capsule state or a future audited offline migration, and legacy state fails
  closed. Earlier Opal deployments had `POLICY_READY=FALSE` and published no DP
  capsules; their local K-site state was ephemeral.
  Exact COMMIT/RELEASE replay and sticky replay within a live session are O(1).
  End-to-end cold reconstruction after restart instead returns through
  AllocationProof, which audits the complete O(N) allocator journal before
  returning the proof; it still burns no unit, draws no noise and reads no
  protected source.
  The same clean baseline fixes the control protocol at
  `dsvert-joint-dp-control-v3` and canonical capsule identity at
  `dsvert-joint-dp-capsule-identity-v3`; both bind the lifetime fields and
  biomedical workload v7. Their v2 artifacts are legacy and fail closed. They
  are neither migrated nor re-signed automatically, so rollout likewise
  requires empty DP capsule state or a future audited offline migration.

* Versioned the biomedical workload as v7 and replaced its obsolete
  `local_materializer_only_not_end_to_end` assertion with an exact registered
  release-lifecycle contract. Every declared coordinate is now bound to the
  materializer, encrypted two-recipient source, joint sampler, confidential
  finalizer and durable replay path; raw source intermediates remain
  non-releasable. Package integration is distinguished from live connector
  execution, which still requires the runtime preflight. The manifest cache
  and public authority are versioned so earlier releases remain immutable
  replay records while a v7 capsule must first reserve one authenticated
  lifetime unit. Manifest/plan/source phase-local responses retain
  `request_limit = FALSE` and their non-admission flags; the allocator commit is
  the single lifetime boundary.

* Joint-DP vector releases now bind both designated peers' sticky noise-root
  descriptors to independent, automatically generated public release domains.
  PREPARE persists a candidate but does not claim the capsule, so sibling
  candidates can coexist until the first valid START at a designated peer
  atomically and irrevocably claims one release instance before local staged
  source access or sampling. Source material may already have been staged by
  the preceding encrypted source phase, but no noised share or public output
  exists at this boundary. Split sibling claims cannot form the matching
  bilateral receipts required for finalization. Ordinary retries and restarts
  continue the claimed instance. If an
  authenticated publication survives but its vector state is irrecoverably
  missing, the server restores and replays that exact release or fails closed;
  it cannot rotate the domain and resample the published capsule. Domain
  rotation can select another candidate only before the first valid START
  claims the capsule.
  Missing/corrupt domain metadata is restored from authenticated release
  evidence when possible; contradictory or insufficient post-publication
  evidence fails before replacement. Every capsule has at most one public
  `release_instance` for its lifetime.

* Vector-release composition now uses authenticated state v2 with exact
  canonical-decimal `contract x release-count` totals and an outward-rounded
  numeric display. Existing v1 state is migrated atomically only after a full
  authenticated legacy audit; read-only recovery computes the exact total in
  memory. The reservation registry counts every allocator-commit burn, while
  the release ledger separately counts publications and rejects more than one
  public instance per capsule. A process-local cross-audit cache is reused only
  while every ledger and capsule row is unchanged, and is not an external
  monotonic rollback anchor. The authenticated history can deny a new capsule,
  but `request_limit` remains false and exact replay is free.

* Added an internal, unregistered Phase20a handoff from the protected formal
  GLM Phase19 worker to the existing one-draw and full-release backends. Each
  peer durably seals only its own Ring128 share with authenticated encryption,
  CAS/restart checks and bounded stale-temporary cleanup; no command, R export,
  DataSHIELD method or advertised capability was added. At this stage the
  source-bound hidden-validity release, registered R/DSI lifecycle and
  checkpoint-root rotation continuity still required completion; Phase21
  below closes only the first of those internal component gaps.

* Added internal, unregistered Phase21 runners for both the one-draw and
  independently sampled full backends. Neither accepts a caller-provided
  source share or local source binding: each derives them from the
  authenticated Phase20 slot immediately before exact-GC execution. The full
  path binds its exact pre-noise range gate and signed noised peer share to
  that same source. Both paths durably memoize a false hidden all-K predicate
  as a no-release and permit source cleanup only after validating the
  two-peer signed certified release. Binomial and Poisson tests cover K=2,
  K=3 and K=5, exact restart replay, a genuinely signed lower-layer source
  substitution, certificate tamper, authenticated cleanup and hidden-invalid
  terminal replay. No command, capability, R export or DataSHIELD method was
  added; formal GLM remains unavailable before DSI while the registered
  lifecycle, checkpoint-root rotation continuity and deployment
  scalability/timing evidence remain incomplete.

* The local capsule materializer now discards redundant finite-value,
  presence and bounds views after producing each column's moments and all
  declared histograms. Same-owner pairs and Gaussian designs retain only the
  per-unit bounded values and validity mask. Regression tests prove the full
  coordinates and commitments are byte-identical; the change reduces live
  heap pressure without changing the `all_schema` quadratic pair workload.

* Gaussian sufficient-statistic assembly now preallocates its canonical
  lower-triangular coordinate vector instead of repeatedly appending to it.
  The serialized coordinates remain byte-identical, while cumulative copying
  falls from quartic to linear in the number of emitted coordinates; the
  underlying Gram computation remains quadratic in predictor count.

* Capsule-source transport now supports an authenticated, byte-bounded
  consecutive window through the existing ticket, chunk and acceptance
  methods. The outer chunk and acknowledgement framing is not independently
  signed; every inner ticket/summary wrapper, ciphertext envelope and
  acknowledgement retains its existing signature and complete binding. The
  scalar ticket, bundle, ciphertext envelopes and acknowledgements remain
  byte-identical. Both designated recipients and every declared source owner
  attest the versioned capability before a window is used; unsupported peers
  retain the scalar path. The per-message byte/window caps provide
  backpressure only and are not request or history quotas.

* Capsule-source durable inbound accounting now reserves receipt storage for
  every declared source-by-chunk pair, rather than a source-independent
  estimate. Recipient tickets also reserve their authenticated key row before
  insertion; replay is idempotent, historical v3 rows migrate under lock, and
  compaction releases the reservation. K=2 through K=5 and large synthetic
  source sets exercise exact byte-bound admission, restart reconciliation and
  release; this is storage backpressure, not a limit on queries, sessions or
  release history.

* Cross-owner fixed-domain categorical tables now stay private through one
  capacity-padded Ring128 exact-GC multiplication and enter only the sticky
  joint-DP capsule vector. A cross-signed two-peer allocation is verified
  before source keys, raw source materialization, or private categorical
  input binding; no exact cell, marginal, alignment hash, or share is returned
  to the analyst relay. The allocator commit is the durable lifetime
  reservation and is never refunded; it is operation accounting, not a request
  quota.

* A valid surviving DP noise-root receipt no longer blocks startup when the
  root, recovery envelope and epoch journal were lost before any release
  ledger or rollback anchor existed. dsVert preserves that receipt as an
  unreleased first epoch and performs one identity-authenticated, restart-safe
  rotation automatically. Malformed receipts, surviving ledger/anchor state,
  authenticated-history contradictions and rollback still fail closed.

* Completed automatic recovery from simultaneous loss of both reciprocal
  cryptographic roots. Identity-HMAC local/joint ledgers and capsule stores are
  locked, preserved byte-for-byte in an owner-only retired-state archive, and
  removed from the active paths before a replacement identity and independent
  DP root are minted. The fresh ledger no longer fails on the old `secret_id`;
  peer rotation still requires out-of-band verification and produces the typed
  `peer_not_recognized` instructions, with no autoaccept or rotation quota.
  Surviving external anchors are not modified, and the retired archive is
  explicitly labelled unauthenticated after total reciprocal-root loss.

* Replaced exact-GC's cumulative `inbound.bin` / `outbound.bin` transcripts
  with v3 immutable, hash-addressed ciphertext segments and durable absolute
  byte bases. Consumed inbound and acknowledged outbound prefixes are reclaimed
  without renaming a file open in the other process. Exact retries remain
  byte-identical, conflicting overlaps and offset rollback fail closed, and the
  byte ceiling now applies backpressure until an ACK releases capacity instead
  of acting as a cumulative-operation limit or request quota. Cursor reads and
  segment hashing are bound to coherent open-file snapshots, closing rename /
  immediate-reclamation races under high-throughput Ring512+ transcripts.

* Multipart legacy compatibility blobs now keep purpose-bound chunks and their
  hashes in an environment with an incremental byte/count accumulator. Exact
  retries are O(1), a generic/PSI purpose switch fails closed, and finalization
  performs one ordered assembly instead of rescanning and rehashing every prior
  frame after each append. The path remains legacy and O(payload); active typed
  transport continues to use private disk spooling and signed receipts.

* Corrected approximate-Gaussian privacy accounting: the implementation now
  reserves `(1 + exp(epsilon)) * d * 2^-40` delta for transferring the ideal
  Gaussian guarantee across the published vector total-variation bound. The
  mechanism and selector contracts are versioned to v3 so releases produced
  under the former, insufficient reserve cannot be mistaken for corrected
  certificates.
* Added a provisional purpose-bound DSI bridge for the cross-signed global-DP
  control plane. Seven narrowly typed phases relay only canonical signed
  receipts between two custodian-designated peers from the complete K-peer
  pinset. Proposals require a server-local HMAC; no endpoint accepts or returns
  a statistic, seed, noise sample, share, or result payload. Exact retries are
  durable, while capability and payload delivery remain disabled.
* Replaced the relay-visible unkeyed result-payload hash with a v2,
  domain-separated HMAC-SHA256 commitment under the persistent private ledger
  key. This removes the offline dictionary oracle for low-entropy result
  domains; legacy v1 result receipts are rejected, and result/delivery
  capability remains disabled pending E2E provenance and delivery tests.
* Versioned DP contingency aggregation as
  `consistent_cell_else_exclude_v1`: duplicate valid cells count once,
  conflicting valid cells contribute zero without a data-dependent error, and
  missing/out-of-domain rows do not create conflicts. The public rule is bound
  into policy and query hashes and returned without an exclusion count.
* Replaced the experimental R inverse-CDF DP sampler with Google Differential
  Privacy Go v4.1.0's `noise.Laplace().AddNoiseInt64` secure granular sampler.
  The server has no production fallback, enforces exact integer/granularity
  bounds before sampling, clips without wrap, and reports upstream marginal
  and union-bound simultaneous confidence radii.
* Raw-share release is bound to the aggregating producer by a content-digest
  provenance stamp; a per-observation share can no longer be laundered into the
  allowlisted release slot (`k2GetStoredShareDS` / `k2StoreSumShareDS`).
* Every transport-sealed share is pinned to an identity-verified peer, and the
  stored peer set contains only Ed25519 + trusted-list verified keys.
* Chi-square DCF comparison keys are generated on the non-computing
  coordinator; a data-owning server can never act as the comparison dealer.
* Cox discrete-time and event-time risk sets below the disclosure floor are
  grouped so no released time bin isolates a single subject.
* Single-observation isolation floor on the share-sum slicing primitives.
* Disclosure controls (small-cell suppression, exact extrema, histogram /
  contingency floors) are server-authoritative and fail closed by default.
* Pinned peers are mandatory and logical-name-bound. The former disable and
  unnamed-pin compatibility selectors are ignored; no option or environment
  variable can reopen a key-only transport handshake.
* Added `k2SeedSingleClusterDS`, seeding a constant cluster so the LMM Gram
  driver serves the gaussian GLM one-shot fast path.
* Retired and removed the obsolete remote primitives
  `dsvertClusterBinomialMomentsDS`, `dsvertLMMExactClusterR2DS`,
  `dsvertLMMXCovarianceWithinDS`, and `dsvertLMMGLSAggregatesDS`; active
  share-domain or stored-session replacements avoid granular/adaptive
  cluster-statistic oracles and client-supplied row membership.

### Beaver preprocessing

* Added `dsvertBeaverPolicyDS()` so DataSHIELD administrators can inspect the
  server-side Beaver preprocessing policy.
* Added relayable semi-honest IKNP OT-extension commands as the strengthened
  Beaver preprocessing backend, with rebuilt `dsvert-mpc` binaries for all
  packaged platforms.
* Domain-separated IKNP extension seeds so client-side orchestrators can reuse
  a base-OT transcript safely across multiple multiplication batches without
  reusing PRG pads.
* Dealer preprocessing has been removed: a participating-party dealer can
  reconstruct peer operands, so IKNP OT-extension is now the sole, dealer-free
  backend. The historical direct-OT helpers are also out of the registered
  `AggregateMethods` surface.

### Cleanup

* Removed archived `inst/k2-mpc-tool` research sources and generated package
  tarballs from version control. The maintained Go runtime is
  `inst/dsvert-mpc`; shipped binaries remain under `inst/bin/`.
* Documented the production DataSHIELD surface as the `AggregateMethods` /
  `AssignMethods` list in `DESCRIPTION`. Disclosive or suboptimal historical
  helpers are removed from the invocable server surface.
* Strengthened the product-surface disclosure test so debug reveal helpers,
  patient-level ordinal/NB legacy helpers, plaintext weight helpers, and Cox
  rank primitives remain out of `AggregateMethods`, out of `NAMESPACE`
  exports, and absent from the package namespace.
* Removed archived server code for debug share reveal, Cox rank/Newton/Path-B,
  plaintext DCF weights, disclosive NB eta transport, and ordinal
  patient-level reconstruction.

## dsVert 1.1.0

Server-side primitives for the v2.0 federated method stack. Companion
release to dsVertClient 1.1.0.

### New aggregate methods

* **Cox K=2** discrete-time non-disclosive primitives — `dsvertCoxDiscreteShareMaskDS`,
  `dsvertCoxDiscreteReceiveSharesDS`, and assign-time
  `dsvertCoxDiscreteExpandXDS` for the Allison 1982 / Andreux 2020
  pooled-logistic equivalence with K=2-safe share-mask gating
  (Aliasgari-Blanton 2013 NDSS).
* **NB regression** — full profile-MLE digamma chain
  (`dsvertNBProfileSumsDS`, `dsvertNBMomentSumsDS`,
  `dsvertNBEtaShareDS`, `dsvertNBEtaTotalReceiveDS`,
  `dsvertNBSumShareDS`, `dsvertNBPsiAggregateDS`) supporting iid-mu,
  Method-of-Moments, and non-disclosive full-regression theta estimators with
  the Ring127 NR-LOG
  share-domain primitive (Goldschmidt 1964 + Pugh 2004).
* **Multinomial joint Newton** — `dsvertPrepareMultinomGradDS`,
  `dsvertSoftmaxDenominatorDS`, `dsvertOneHotDS`,
  `dsvertComputeResidualShareDS` for the K-1 stacked Bohning-bounded
  Newton path (paper §V.A row).
* **Ordinal joint PO Newton** — `dsvertOrdinalShareClassMasksDS`,
  `dsvertOrdinalReceiveClassMaskDS`, and `dsvertOrdinalExtractXColumnDS`
  for strict class-mask/share-domain orchestration without the historical
  patient-level reconstruction path.
* **LMM (random intercept + slopes)** —
  `dsvertCluster{Sizes,Residuals}DS`, `dsvertExpandClusterWeightsDS`,
  `dsvertClusterZtZDS`, `dsvertLMMPeerFittedShareDS`,
  `dsvertLMMCoordResidualShareDS`, `dsvertLMMPeerResidualFinaliseDS`,
  `dsvertLMM{Broadcast,Receive}ClusterIDsDS`,
  `dsvertLMM{Per,Global}SumDS`, `dsvertLMMGLSTransformDS`,
  `dsvertLMMLocalGramDS`, `dsvertLMMReceiveGramSharesDS`,
  `dsvertLMM{R1,R2}DS` for the Laird-Ware GLS closed form with
  Pinheiro-Bates §2.4.2 within-between ANOVA variance components.
* **LMM K=3** — `dsvertLMMVarianceComponentsDS` +
  `dsvertLMMXCovarianceWithinStoredDS` for the K=3 sigma^2 / sigma_b^2
  recovery with Var_within(X β) correction.
* **Beaver vecmul Ring63 / Ring127 stack** —
  `k2BeaverVecmul{GenTriples,ConsumeTriple,R1,R2}DS`,
  `k2Beaver{ShareVector,ReceiveVector,ExtractColumn,SumShare}DS`,
  `k2Ring127{AffineCombine,LocalScale}DS`. Underpins the joint Newton,
  Cox Path B, LMM Gram, and chi-square primitives.
* **Histogram + descriptive aggregates** — `dsvertHistogramDS`,
  `dsvertLocalMomentsDS`, `dsvertContingencyDS` for the v2 descriptive /
  contingency table API.
* **PSI / IPW / chi-sq** — `psi*DS` family extended;
  `dsvertOneHotDS`, `dsvertImputeColumnDS`, `dsvertPearsonR2ColDS`,
  `k2CrossOneHotCountsDS` for two-way contingency Beaver dot products.

### Changes

* Cox now defaults to `ring = 127L` (5/5 STRICT on Pima synthetic at
  ~2× speedup vs Ring63).
* `glmStandardizeDS` gains a `mode = "x_only" | "full"` switch.
* `glmRing63ReorderXFullDS` reorders the fusion party's X to the
  canonical `(coord | fusion | extras)` ordering.
* `mpcStoreTransportKeysDS` and `psiStoreTransportKeysDS` gain
  base64url JSON variants for chunked-blob relay through DataSHIELD.

### Documentation / quality

* Rd warnings cleared: bracket-link traps, loose LaTeX-macro escapes,
  `Lost braces`, `Missing link` cross-refs all eliminated.
* Auto-generated @param entries replaced with descriptive prose
  for 102+ previously-undocumented arguments.
* Non-ASCII characters in R sources replaced with ASCII equivalents
  (R CMD check `code files for non-ASCII characters` clean).
* LICENSE switched to DCF stub; full MIT text retained in `LICENSE.md`.
* `.Rbuildignore` excludes Go-source dirs and vignette caches; the
  per-platform compiled binaries under `inst/bin/{darwin,linux,windows}-*`
  ship intentionally.

### Testing

* 88 server-side `testthat` checks (K-arity guards, contingency,
  histogram, LMM K=2 enforce). All PASS.
* Go tests (`dsvert-mpc`) — full suite passes in ~2 s.

## dsVert 1.0.0

Initial public release: K=2 GLM (Gaussian / Binomial / Poisson),
correlation, and PCA via Ring63 Beaver MPC + DCF wide-spline link
functions, with ECDH-PSI record alignment.
