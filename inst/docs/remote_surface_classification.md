# dsVert remote surface audit

Audit date: 2026-08-09. The machine-readable source of truth is
[`remote_surface_classification.json`](remote_surface_classification.json).

## Result

The current client/server registration contract is internally complete:

| Check | Result |
|---|---:|
| Registered `*DS` endpoints | 65 |
| Direct `call(name = "...")` endpoints | 150 |
| `as.call()` / `as.name()` exact-GC endpoints | 7 |
| Dynamically named endpoints behind one closed runtime allowlist | 1 |
| Unregistered endpoint names retained below guarded/test-only client code | 94 |
| Production-reachable client expressions naming an unregistered endpoint | 0 |
| Registered endpoints with no repository consumer | 0 |
| Unregistered, unexported internal `*DS` functions | 158 |

This audit removed a further 94 endpoints from `AggregateMethods` and
`NAMESPACE`: four diagnostic/migration helpers and 90 legacy exact, generic
MPC, score, cluster-model and mutating-analysis primitives. Six obsolete
per-query DP wrappers and their bare SQLite release engine are now hard-deleted;
the remaining R closures stay internal solely for source compatibility and
focused regression tests. None is exported or remotely invocable. All 65 endpoints that remain
registered belong to the promoted purpose-bound allowlist. Sixty-four have a
product call builder after resolving literal calls, seven `as.call()` / `as.name()`
constructions and the closed dynamic branch; `dsvertDPCountCompileDS` is the
server-side compiler milestone and is covered by focused server tests while its
client orchestration lands separately. The dynamic branch still names
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

`mpcTypedSourceProbeDS` and `mpcTypedBlobReadDS` retain concrete internal
diagnostic call builders, but both are now unregistered and unexported. They
are test-plane tools, not statistical producers.

The retired generic and scalar Count control planes have been superseded by the
manifest-bound biomedical vector capsule. Five product-bound allocation
endpoints first derive, cross-sign, register and durably replay the immutable
capsule authorization without accepting analyst-selected proposal fields. Its
seven registered release endpoints then prepare and commit the fixed vector
mechanism,
draws, exchange only typed encrypted already-noised Ring128 shares, apply one
fixed public coordinate clamp, and release a signed root plus Merkle-proved DP
chunks. The analyst receives no private source share, sticky seed, sampled
noise, noised share or pre-clamp value. Completed state is durably replayed
without another lifetime charge or a request-quota gate. A new capsule is
separately subject to the authenticated lifetime reservation boundary.

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
the registered joint sampler and confidential finalizer.

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

The seven vector-release endpoints are the fixed sampler/finalizer lifecycle
for that server-authoritative manifest. They expose signed commitments,
encrypted typed noised shares, one final Merkle root and replayable final DP
chunks only. Private source shares, sticky seeds, noise-root/private-key
material, sampled noise and pre-clamp values remain internal; repeat requests
for the same capsule/release instance replay durable state and are never denied
by a history or request counter. A previously unseen capsule may be denied only
by the earlier authenticated lifetime gate.

No non-DS alias is registered. In particular, `c`, `list`, `numeric`, and
`character` must remain ordinary client-side constructors: registering their
`base` implementations as aggregate methods would bypass the namespace guard
and is rejected during service bootstrap and Opal allowlist reconciliation.

## Primary classification

| Class | Count | Meaning |
|---|---:|---|
| Production-safe / purpose-bound | 65 | Fixed status/schema, padded PSI, Count compilation, typed-store, transport, capsule manifest/source, cross-signed allocation, cross-owner checked-vector-multiplication and joint vector-release routes admitted by the default guard |
| Retired diagnostic/migration internals | 4 | Generic typed read/source diagnostics plus generic exact-GC bind and GLM softplus helpers; unregistered, unexported and test-only or locally guarded |
| Retired quarantined compatibility internals | 90 | Legacy exact/MPC endpoints below stable local frontdoor errors; unregistered, unexported and carrying no DP or non-reconstruction claim |
| Registered orphan/dangerous candidates | 0 | Every registered endpoint is promoted and consumed |
| Internal-unregistered total | 158 | The 94 above plus 64 previously retired compatibility/test closures |

“Production-safe” is not an unconditional theorem. A DP claim still depends on
the advertised adjacency and contribution bounds, immutable snapshot, sticky
root secrecy, healthy global accountant/ledger, pinned-peer assumptions and the
documented transcript boundary. `dsvertColNamesDS` returns only the
custodian-approved policy schema and never resolves the protected object;
`dsvertPublicFixedCohortCountDS` likewise returns only the published fixed
cohort constant. `dsvertDPCountCompileDS(data_name)` resolves only an already
attested padded-PSI object and returns the closed `{config, receipt}` envelope:
privacy parameters, stable count bound, source semantics, complete pinset and
runtime protocol digest are all server-authoritative, and the local receipt
signs the canonical configuration hash. The remaining status endpoints must
stay data-independent and may reveal operational policy progress but no
protected statistic.

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

The 158 internal `*DS` functions are both unregistered and unexported. This set
includes:

- the 16 retired generic scalar control-plane and Count lifecycle functions;
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

The executable tests assert this exact set, the exact 64-endpoint registration
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
