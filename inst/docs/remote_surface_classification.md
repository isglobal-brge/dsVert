# dsVert remote surface audit

Audit date: 2026-08-11. The machine-readable source of truth is
[`remote_surface_classification.json`](remote_surface_classification.json).

## Result

The current client/server registration contract is internally complete:

| Check | Result |
|---|---:|
| Registered `*DS` endpoints | 86 |
| Direct `call(name = "...")` endpoints | 179 |
| `as.call()` / `as.name()` exact-GC endpoints | 13 |
| Dynamically named endpoints behind one closed runtime allowlist | 1 |
| Unregistered endpoint names retained below guarded/test-only client code | 107 |
| Production-reachable client expressions naming an unregistered endpoint | 0 |
| Registered endpoints with no repository consumer | 0 |
| Unregistered, unexported internal `*DS` functions | 154 |

This audit keeps 105 formerly registered endpoints out of `AggregateMethods`
and `NAMESPACE`: three diagnostic/migration helpers and 102 legacy exact,
generic MPC, score, cluster-model, mutating-analysis and lifetime-gated vector
primitives. `dsvertImputeColumnDS` has no executable client construction; the
remaining 104 retired endpoints plus three locally quarantined unregistered
constructions are covered by the client AST audit. Six obsolete
per-query DP wrappers, their bare SQLite release engine and the nine superseded
scalar Count capsule/ledger phases are now hard-deleted. The seven generic
scalar control-plane frontdoors and their endpoint-only DSI adapters are also
hard-deleted; the remaining R closures stay internal solely for source
compatibility and focused regression tests. None is exported or remotely
invocable. All 86
endpoints that remain registered belong to the promoted purpose-bound
allowlist and have a product call builder after resolving literal calls, seven
`as.call()` / `as.name()` constructions and the closed dynamic branch. The
dynamic branch still names
`mpcStoreBlobDS`, but only below quarantined legacy frontdoors; it cannot be
reached by an installed public route. Any other dynamic name fails before a
DSI expression is constructed.

These counts classify source constructions and the installed registration
contract; they are connector-neutral and do not by themselves establish a
live Opal, Armadillo or Rock deployment. Connector-specific administration
must still reconcile the effective callable inventory before installing the
custodian attestation, and release evidence must name a current live harness
artifact rather than infer one from this AST audit.

This audit also hard-deleted `localCorDS`, all fifteen legacy variable-shape
PSI closures (including the patient-index helper), and the now-redundant
`psiPaddedExactTransportDS`. Exact-GC transport binding is idempotently folded
into `psiPaddedANDStartDS`. The public patient-alignment route therefore
consists of exactly sixteen purpose-bound `psiPadded*DS` methods: fifteen
aggregate phases and one assign phase. Cross-owner statistical inputs use a
separate four-endpoint private integrity gate: recipient-specific digest XOR
shares are compared only inside fixed-shape GC and only one terminal
`complete`/`alignment_contract_invalid` outcome is opened.

The retired `dsvertDPStatusDS`, `dsvertDPCountDS`,
`dsvertDPContingencyDS`, `dsvertDPMeanVarDS`, `dsvertDPDescribeDS`, and
`dsvertDPSurvivalDS` closures are also hard-deleted. Their unregistered bare
SQLite engine had no production consumer; `dsvert.dp.ledger_path` remains only
as the namespace prefix for promoted stores.

`mpcTypedSourceProbeDS` remains an unregistered internal diagnostic helper.
`mpcTypedBlobReadDS` is registered only as a ticket-bound authenticated
transport primitive; neither is a statistical producer or an opening.

The retired scalar Count capsule/ledger adapter and generic scalar
control-plane frontdoor are hard-deleted. The shared receipt codec and the
older allocation phases remain namespace-internal for regression only; neither
is a remotely invocable product route.
Count is served by a five-phase stateless route: signed compilation,
two-authority public
authorization, exact-GC Start, recipient-encrypted final-share transfer and one
signed Release. Compilation binds the full K-peer pinset, padded-PSI snapshot,
public bounds and mechanism; only the two identity-selected authorities enter
exact GC. Sticky noise is derived from each authority's persistent identity
seed and the semantic analysis contract. Session identifiers, attempts and
signatures do not reroll the semantic release, and no Count lifetime ledger,
request quota or durable cache exists. Fixed-cohort Count is represented by the
signed zero-sensitivity Compile variant and does not enter exact GC.

Fixed-domain Frequency uses a separate seven-endpoint stateless lifecycle.
Claim is issued only by the explicitly configured source owner; every pinned
peer contributes one signed, snapshot-bound Compile receipt, while only the
source owner and the contract-selected secondary noise authority create
authorization, typed-transfer, execution or resource state. Source and
Finalize process fixed 65,536-coordinate Ring128 windows sequentially and open
one signed terminal vector release; Replay returns committed chunks without a
new draw. Cleanup is authenticated, idempotent and invoked only on those two
authorities. The K-2 witnesses retain no session state for this lifecycle.

The former biomedical vector allocation and release lifecycle is retained only
as an unregistered internal regression path. Its authenticated ledger imposed
a maximum-distinct-capsule boundary, so it is not an admissible public route.
The registered Synopsis lifecycle instead binds one canonical signed artifact
to sticky deterministic replay and explicitly has no request, rate or catalog
admission gate. Distinct artifacts are separate analyses; this does not claim
finite global DP composition.

The exact-GC/typed-store route is production-classified only for its fixed
capabilities and consumers. For categorical and Gaussian cross-owner products,
the promoted checked-vector-multiplication subgraph consists solely of
producer-manifest-bound claim, start, validity exchange and commit phases.
The generic bind endpoint and the GLM softplus producer are unregistered,
unexported and locally guarded before DSI construction. Cleanup
uses a peer-signed, purpose-bound capability that can delete all and only the
ephemeral state of the exact session to which it was issued; the historical
generic cleanup endpoint is unregistered, and promoted PSI/vector/cross routes
no longer issue it even as a best-effort fallback. The two-worker transport suite covers spool
retries, tamper, lost acknowledgement, restart and deterministic post-clamp
shares.

The four biomedical capsule-source endpoints add persistent recipient tickets,
owner-local Ring128 splitting, a single canonical two-recipient ciphertext
bundle per source/chunk, and recipient-local aggregation. Their relay-visible
schemas contain only ciphertext and public contract/progress metadata; patient
IDs, exact values, masks, seeds, private snapshot/value commitments and
plaintext shares are forbidden. This raw-source stage deliberately remains
`ready_for_sampling = FALSE`: it is a confidential input boundary and never an
  independent DP release. The v7 manifest authorizes its output only as input to
an internal regression sampler and never creates a public release by itself.

The four private-alignment gate endpoints and six categorical/Gaussian
cross-owner endpoints are production-classified as one indivisible route.
Cross bind reads only the gate's fresh Ring128-masked file; it has no fallback
to the pre-gate aggregate store. The relay and each individual computation peer
receive no alignment digest or mismatch location. This claim assumes two
pinned, semi-honest, non-colluding computation peers and excludes physical
timing, availability, malicious peers, peer collusion and host compromise; see
`private_alignment_exact_gc_audit_20260802.md`.

The three capsule-manifest endpoints expose only signed custodian policy
metadata, unanimously sign the derived global schema/workload binding, and
durably replay one byte-identical server-authoritative manifest. They do not
resolve protected objects, expose snapshot/alignment hashes or accept
analyst-selected bounds, domains, owners, versions or workload specifications.

The registered Synopsis release lifecycle exposes signed commitments and
replayable final DP chunks only. Private source shares, sticky seeds,
noise-root/private-key material, sampled noise and pre-clamp values remain
internal; repeat requests for the same canonical artifact replay durable state
and are never denied by a history or request counter.

No non-DS alias is registered. In particular, `c`, `list`, `numeric`, and
`character` must remain ordinary client-side constructors: registering their
`base` implementations as aggregate methods would bypass the namespace guard
and is rejected during service bootstrap and Opal allowlist reconciliation.

## Primary classification

| Class | Count | Meaning |
|---|---:|---|
| Production-safe / purpose-bound | 86 | Fixed status/schema, padded PSI, complete stateless Count, Frequency and Synopsis execution, typed-store, transport, capsule manifest/source, and cross-owner checked-vector-multiplication routes admitted by the default guard |
| Retired diagnostic/migration internals | 3 | A data-free source probe plus generic exact-GC bind and GLM softplus helpers; unregistered, unexported and test-only or locally guarded |
| Retired quarantined compatibility internals | 102 | Legacy exact/MPC endpoints, including the lifetime-gated vector lifecycle, below stable local frontdoor errors; unregistered, unexported and carrying no DP or non-reconstruction claim |
| Registered orphan/dangerous candidates | 0 | Every registered endpoint is promoted and consumed |
| Internal-unregistered total | 153 | The 105 above plus 48 previously retired compatibility/test closures |

“Production-safe” is not an unconditional theorem. A DP claim still depends on
the advertised adjacency and contribution bounds, immutable snapshot,
pinned-peer assumptions and the documented transcript boundary. Capsule routes
add their own sticky-root and accountant assumptions; Count does not use that
lifetime state. `dsvertColNamesDS` returns only the custodian-approved policy
schema and never resolves the protected object. `dsvertDPCountCompileDS` emits
one of two closed signed variants: an add/remove analysis configuration and
receipt for an already attested padded-PSI object, or a fixed-cohort
zero-sensitivity public declaration. The four execution endpoints accept only
the add/remove variant, keep seeds and intermediate shares private, and return
one signed clamped Count.
The remaining status endpoints must stay data-independent and may reveal
operational policy progress but no protected statistic.

## Risks isolated below the public remote boundary

The following closures remain only to keep historical implementations
regression-testable while safe replacements are developed. Their public names
fail locally with `dsvert_route_unavailable:v1`, before connection discovery or
DSI submission; their server names are unregistered and unexported.

### Exact adaptive summaries

`getObsCountDS`, `glmStandardizeDS`, moment/NB
aggregates, ordinary contingency, one-hot margins, deviance sums, outcome
levels and the cluster summary endpoints release exact or reconstructible
statistics. A minimum-cell threshold is useful suppression, but it is not a
composition theorem: repeated and differenced queries remain unsafe. Each
high-level consumer needs one accountant-bound DP release or one purpose-bound
joint MPC/DP opening before its old primitive can disappear.

### Pinned padded PSI threat boundary

The promoted PSI route has a fixed schedule determined only by K and the
server-owned public power-of-two capacity bucket. Every peer signs the complete
name-pinned contract and phase receipts; peer-to-peer payloads are encrypted,
signed, purpose/sequence/snapshot bound and durably replayed with absolute
offset acknowledgements. The relay never receives identifiers, row maps,
membership vectors, input counts, pairwise counts or intersection cardinality.
It can delay, drop or replay traffic only to cause an explicit failure, not a
silent substitution. The public bucket remains an upper bound on input shape,
and K plus availability/timing are observable. Collusion of both designated
exact-GC compute peers is outside the membership-confidentiality claim. When a
cohort size is scientifically required, it must come from a separate authorized
DP artifact.

### Cluster-granular workflows

The GEE/LMM/GLMM compatibility paths expose or reconstruct exact per-cluster
sizes, levels, ordering metadata or share vectors. `dsvertClusterZtZDS` is
especially broad because its reply includes the cluster-level labels alongside
per-cluster matrices. Minimum cluster size does not close adaptive differencing.
Cluster membership should remain inside authenticated peers and only a
contribution-bounded model-level DP result should open.

### Aggregate methods that mutate analysis data

`glmStandardizeDS`, `dsvertImputeColumnDS`, `dsvertPearsonR2ColDS`,
`dsvertExpandClusterWeightsDS` and `dsvertCoxDiscreteExpandXDS` create or
modify server-side objects despite being AggregateMethods. They are blocked by
default, but their replacement should use immutable, purpose-bound derived
objects with producer-minted names/tickets and fixed acknowledgements.

### Generic transport and reducers

`mpcStoreBlobDS` accepts a caller-selected session key. Producer-minted typed
store/receipt tickets are live for the vector capsule route; generic typed reads
remain provisional and cannot be used as an analyst-selected opening.
Generic column extraction, sum/strided-sum, affine-combine and LMM-global-sum
endpoints likewise make protocol confusion or unintended exact openings easier
to compose. Their replacements must bind producer, source slot, shape,
destination, operation and one permitted opening.

## Already outside the remote surface

The 153 internal `*DS` functions are both unregistered and unexported. This set
includes:

- the retired exact adaptive `dsvertHistogramDS` helper, now replaced in
  `ds.vertDesc` by the sticky fixed-grid DP capsule;
- the orphaned exact `dsvertContingencyDS` table, replaced by the signed DP
  contingency artifact used by chi-square and Fisher post-processing;
- the legacy chi-square guard/product lifecycle, exact one-hot helper and
  generic Beaver vector-share pair, all superseded by purpose-bound categorical
  and typed-vector capsule paths;
- legacy DCF/comparison phases (`k2Cmp*`, persistent DCF keys and old wide
  spline phases);
- raw/generic stored-share access, clear/reset and obsolete triple helpers;
- test-only data mutation helpers for injected NAs, synthetic survival,
  quartiles, factors and clusters.

The executable tests assert this exact set, the exact 86-endpoint registration
allowlist and all guarded public frontdoors. Merely leaving one of these
functions defined in package source does not make it a DataSHIELD endpoint.
The removed legacy PSI functions, `psiGetMatchedIndicesDS`,
`psiPaddedExactTransportDS` and `localCorDS` are stricter still: their closures
no longer exist in the installed namespace.

## Removal rule

An active endpoint is removable only after all of the following are true:

1. its disclosure-safe replacement is live and tested;
2. AST resolution finds no client expression, including `as.call()` and bounded
   dynamic construction;
3. retry, typed-transport and protocol inventories contain no reference;
4. the endpoint is absent from `AggregateMethods` / `AssignMethods` and from
   namespace exports; and
5. focused, full compatibility and source/installed-package checks pass.

Until that gate is met, deregistration plus the client-local guard and internal
server deny gate form the defence-in-depth boundary. There is no environment
variable, option or request that enables compatibility methods. Retained
implementations remain executable only inside package regression tests through
a test-only namespace replacement that is not installed. A public method is
admitted remotely only after its migrated purpose-bound contract passes the
removal rule above.
