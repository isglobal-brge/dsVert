# dsVert - DataSHIELD Server Package for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](NEWS.md)

## Overview

**dsVert** is the server-side DataSHIELD package for privacy-aware
analysis on vertically partitioned federated data. Each server holds different
columns for the same aligned records; no server receives another server's raw
features or outcome column.

The analyst-facing API lives in
[**dsVertClient**](https://github.com/isglobal-brge/dsVertClient). This package
ships the server functions registered in Opal/DataSHIELD plus the Go MPC
runtime used by those functions.

## Product Surface

The remotely invocable DataSHIELD surface is the `AggregateMethods` and
`AssignMethods` list in `DESCRIPTION`. An exact allowlist test prevents stale
or unused primitives from silently re-entering registration. Patient-index
diagnostics, generic reductions and several cluster-granular legacy helpers are
retained internally only where source compatibility requires it; they are not
registered or namespace-exported.

Registration is not by itself a declaration that arbitrary direct calls to a
low-level primitive are disclosure-safe. Some primitives remain necessary for
provisional iterative methods and still require stronger protocol state
machines before those estimators can be promoted.

The installed server exposes one immutable profile, `disclosure_safe`.
Historical exact/adaptive methods cannot be enabled with an environment
variable, R option or request. A retained method stays behind the central deny
gate until its purpose-bound DP/MPC migration is complete; package tests use a
test-only namespace replacement that is never installed.

## Methods (v1.1.0)

| Family | Product route |
|---|---|
| PSI / alignment | ECDH-PSI common-record alignment with Ed25519 peer identity pinning |
| GLM | Signed bounded Gaussian capsule route; formal binomial/Poisson capsule implementation remains internal until its production gate is satisfied |
| Cox PH | Formal bounded Cox capsule implementation remains internal until compiler, optimizer, DP finalization and independent-host validation are complete |
| Negative binomial | Historical implementations are retained internally but quarantined pending a bounded NB2 capsule and joint inference |
| Multinomial / ordinal | Historical Newton implementations are retained internally but quarantined pending formal bounded capsules |
| Mixed models | Historical LMM/GEE/GLMM research routes; currently provisional or quarantined in the client maturity registry |
| Penalised / causal / MI | LASSO research routes, known-weight outcome modelling and server-local MI; contracts differ by method |
| Descriptive / second-order | Descriptives, contingency/chi-square, Fisher helper, correlation, and PCA |
| Differential privacy | Sticky signed Ring128 biomedical capsule for Count, tables, bounded moments/Gaussian artifacts, fixed histograms and fixed-grid survival, with purpose-bound cross-owner categorical/Gaussian transport |

## Architecture

```
Client (analyst)                    Servers (data holders)
┌──────────────┐                   ┌──────────────────────┐
│ ds.psiAlign()│──── DataSHIELD ──→│ Pinned PSI/MPC       │
│ ds.vertDP*() │    (HTTPS/DSI)    │ Bounded materializer │
│ DP Gaussian  │                   │ Exact-GC joint noise │
│ DP survival  │←─ signed release ─│ Sticky durable replay │
│ DP epidemiol.│    + certificates │ Ed25519 verification │
│ postprocess  │    (no new DSI)   │ X25519 + AES-256-GCM │
└──────────────┘                   └──────────────────────┘
```

**What the client sees on the active capsule surface**: signed public metadata,
one sticky noisy release and its numerical/privacy certificates. Supported
follow-up analyses are local post-processing and make no new DSI call. Several
historical routes would expose aggregates that are too granular for this
contract and are therefore quarantined rather than described as
production-safe.

**What each server sees**: its own data plus protocol messages and additive
Ring shares. The intended model requires non-collusion and at least one honest
designated share holder; malicious-peer security and host compromise are out of
scope.

## Security

| Property | Current contract |
|---|---|
| Observation-level disclosure | Plain patient rows/PSI indices are not registered outputs; exact aggregate outputs can still compose across unlimited adaptive analyses |
| Beaver triples | Dealer-free IKNP OT-extension is the sole preprocessing backend; server policy refuses any trusted-dealer mode, so no participating server ever receives the unsplit `(a, b, c)` triple |
| IKNP consistency | The KOS consistency opener is mandatory in both R and Go; the former unchecked downgrade option has been removed |
| Transport encryption | X25519 + AES-256-GCM (transport-encrypt) |
| Identity verification | Mandatory Ed25519 signed, logical-name-bound peer transport keys; only keys that match the configured exact peer pin are installed |
| Recipient pinning | Every transport-sealed share is pinned to an identity-verified peer (or this server's own key), never an analyst-supplied key |
| Raw-share release | Default-deny allowlist and producer/content binding protect the intended aggregate slot; this is not a proof for arbitrary registered primitive sequences |
| Disclosure floors | Small-cell and dimension guards reject direct small releases; they do not solve adaptive differencing/composition |
| Collusion threshold | Additive-sharing paths are outsourced 2-of-2 to a fusion + coordinator pair: inputs stay private while at least one of those two designated servers is honest (semi-honest, non-colluding) |
| Ring | Checked Ring63/Ring127 fast paths plus exact multi-limb rings through 4096 bits; promoted truncation and comparison use purpose-bound exact GC and reject any unsupported bound before execution |

Pinned identities prevent the analyst/relay from substituting a recipient key
and opening shares. They do not make arbitrary exact outputs
non-reconstructive. The promoted Synopsis surface materialises one bounded,
signed DP artifact per canonical immutable snapshot/workload, with sticky
memoisation and durable replay. Supported methods are unlimited
post-processing of that artifact: there is no request counter, catalog limit,
geometric accuracy decay or charge for exact replay. A distinct artifact is a
separate DP release under its own declared scope; no finite global composition
claim is made. Historical exact implementations are not retroactively DP and
remain unavailable behind the single profile; no absolute non-reconstruction
claim is made. See the client security contract and
`ds.vertMethodStatus()`.

`dsvertDPCountCompileDS(data_name)` is the server-side Count compiler
frontdoor. It accepts only the name of an already attested padded-PSI result
and returns `{config, receipt}`. The canonical configuration is derived from
the custodian's authorized source mapping, privacy options, stable capacity,
complete name-bound pinset and validated exact-GC runtime protocol; the local
Ed25519 receipt signs its hash. The object name contributes no dataset
semantics, and this compile step does not open a statistic.

The currently promoted capsule Count release uses one jointly sampled,
finite-support discrete Laplace mechanism inside exact GC and still obtains
its sticky seeds from the legacy independent noise root. The new compiler
above does not yet replace that product route or publish a Count; its executor
will instead derive each private Count seed from the persistent Ed25519
`identity.seed` by domain-separated HMAC-SHA256. The first protected service
operation bootstraps exactly 32 identity bytes from the OS CSPRNG into
persistent owner-only service state; there is no statistical RNG fallback and
production rejects a literal seed in a package image or service profile.
`DSVERT_STATE_DIR` selects
the state volume explicitly; in Rock, `ROCK_HOME/.dsvert` is used before the
ephemeral container `HOME` fallback. `configure`, package installation and
`.onLoad()` never generate a key, including when an image build loads the
package for a smoke test. A legacy DP route invokes its complete policy, which
performs the ledger/anchor guard before lazily minting its independent noise
root; identity-only routes and `dsvertDPCountCompileDS` do not initialize that
root.
Production fails closed if secure persistence or the compiled runtime is
unavailable. The independent Ed25519 `identity.seed` is created at the first
protected service boundary, not at package load. Once a legacy DP policy has
created both roots, dsVert durably stores two authenticated,
encrypted recovery envelopes: the identity is wrapped under keys derived by
the non-extractable noise-root HMAC interface, and a file-backed noise root is
wrapped under the identity. Losing either primary file therefore restores the
exact original secret automatically, preserving client pins, sticky noise and
ledger authentication across restart and reinstall. Receipts distinguish a
lost secret from a fresh deployment. If both independent primary roots are
lost simultaneously, dsVert preserves the old continuity evidence and creates
a new identity and an independent noise root from the OS CSPRNG. Identity-HMAC
ledgers and capsule stores that can no longer be authenticated are moved,
without rewriting, into a private retired-state archive beside the configured
ledger (and therefore on the same filesystem); the original paths then start
a fresh cryptographic continuity epoch and do not fail on the old
`secret_id`. This archive is forensic/audit evidence only: after both roots are
lost, dsVert does not claim that the replacement identity authenticates its
contents. Any external rollback anchor remains untouched under its old anchor
id. Existing servers do not accept the new identity automatically: they return
a typed `peer_not_recognized` error with both public fingerprints and
instructions for an administrator to verify the key out of band, persist the
new pin on every other participating server, restart or reconnect the affected
services, and retry. A server never pins itself and the analyst/relay can never
approve a replacement. If a separately configured identity exactly matches
the surviving receipt, it is restored instead, so the reciprocal noise-root
envelope can recover the original root without an unnecessary rotation.
When upgrading a pre-receipt deployment, the candidate seed must first
authenticate every surviving local or joint v1/v2 DP ledger; a mismatched seed
is never sealed as the deployment identity.
Inputs and outputs stay inside an exactly representable integer envelope, and
the returned 95% error radii come from the upstream confidence-interval
implementation. Epsilon is restricted to the explicitly tested numerical
domain `[2^-50, 2^40]` and every computed granularity is checked.

## Go Runtime (`dsvert-mpc`)

`inst/dsvert-mpc` contains the current Go source for the Ring63/Ring127 MPC
kernels, purpose-bound exact-GC operations, dealer-free IKNP OT-extension
Beaver preprocessing, transport encryption and identity verification. Legacy
local-share truncation and DCF/wide-spline code remains internal and
quarantined; no promoted path uses it. Every promoted path that needs secret
truncation or comparison uses exact GC and fails closed when its canonical
encoding, public bound, shape or certified adapter is unavailable. This is an
exact integer/ring operation claim, not a proof of exact real arithmetic, a
whole-estimator error bound, or a constant-time claim for the R/DSI host.
The generic `compare-signed` circuit core is property-tested but is not exposed
as an all-purpose promoted comparison capability. Generic checked
multiply/truncate and whole-workload dynamic-ring GLM remain unavailable; only
the purpose-bound adapters listed in `inst/docs/exact_gc_residual_inventory.md`
carry end-to-end promotion evidence.
Per-platform runtime binaries ship under
`inst/bin/{darwin-amd64,darwin-arm64,linux-amd64,windows-amd64}/`.
Packaged artifacts are checked against `inst/bin/SHA256SUMS` before execution,
and the runtime must publish the exact API/capability manifest expected by the
R package. This detects stale builds and accidental artifact corruption; it is
not remote attestation and does not protect against a compromised host or an
administrator able to replace both the binary and its checksum manifest.

The Go binary intentionally exposes only low-level kernel commands. Product
analysis routes are orchestrated by R DataSHIELD methods, and the safe product
surface is still the `AggregateMethods` list. Commands that would directly
reveal session state, legacy Cox ranks, patient-level working vectors, or
debug snapshots are not part of the Go command surface. A test guards this.

The old experimental `inst/k2-mpc-tool` tree is no longer part of the package;
the maintained implementation is `inst/dsvert-mpc`.

## Installation

```bash
# 1. Rebuild all four release runtimes and their SHA-256 manifest.
# Release artifacts require Go 1.25.7.
cd inst/dsvert-mpc
go version
make all

cd ../..

# 2. Build + install the R package
R CMD build --no-build-vignettes .
R CMD INSTALL "$(ls -t dsVert_*.tar.gz | head -1)"
```

## DataSHIELD method registration

Production Opal deployments use a restricted, dedicated non-default profile
named `dsvert`; sharing the default profile is not supported. Run the
`provision_opal.R` script shipped by `dsVertClient`: it disables the profile,
installs private copies of the selected tarballs, removes the complete previous
aggregate/assign inventory, registers exactly the alias-free allowlist from the
staged `dsVert/DESCRIPTION`, verifies the resulting total inventory, stores the
deterministic `dsvert.remote_surface_attestation`, and only then re-enables the
profile. Direct ad-hoc `dsadmin.set_method()` registration does not establish
this contract.

The attestation token is connector-neutral and is a custodian-owned
administrative assertion rather than live connector introspection. An
administrator who later changes the effective callable surface makes it stale
and must rerun connector-specific reconciliation before
`ds.vertSecurityStatus()` reports the deployment ready. Opal persists the token
in its server profile; an isolated Armadillo/Rock deployment may set the same
token through the server/container `DSVERT_REMOTE_SURFACE_ATTESTATION`
environment only after its native administrative inventory check. dsVert never
auto-attests an installed package and the client never supplies this value. The
validation runner receives only profile `use` and Opal's table `view`
permission (dictionary and summaries for DataSHIELD, without individual-value
queries); `view-values`, edit and administrative access are never granted.

Security-profile schema v4 defines the server compatibility field
`formal_dp_claim_eligible` only as eligibility of the biomedical joint-DP
capsule surface for the separate live consortium handshake. Its route map
explicitly keeps formal GLM and formal Cox not ready. A top-level client
`ready` value, this compatibility alias or a valid surface token never
promotes either sealed model route.

## Custodian-owned PSI source authorization

`ds.psiAlign()` accepts an object and identifier name from the analyst, but the
server never treats those names as authorization. Before alignment, every
custodian binds its local object to the agreed logical dataset, version,
identifier column, purpose and a private full-snapshot digest. The local helper
below is not a registered DataSHIELD method and its digest must not be returned
to the analyst:

```r
options(dsvert.psi.authorized_sources = list(
  D = dsvertPSISourceDescriptor(
    D, id_col = "patient_id",
    id = "cohort-2026-07-main", version = "v1",
    purpose = "patient-record-alignment-v1")
))

# Declare the aligned symbol's stable identity before PSI. This is a template,
# not a digest and contains no analyst-chosen secret.
options(
  dsvert.dp.patient_column = "patient_id",
  dsvert.dp.datasets = list(
    DA = list(id = "cohort-2026-07-main", version = "v1")))
```

After `ds.psiAlign()` assigns `DA`, its live non-empty-session attestation
validates the complete padded-PSI v2 contract and atomically records the local
snapshot binding in an owner-only, authenticated server registry. Policy
construction resolves the template from that registry. Repeating PSI for the
same logical version and local snapshot is idempotent even though the protocol
session, nonce and alignment token change; a different snapshot under the same
pinset/id/version is rejected, while a new version or verified peer-pin epoch
gets a separate record. The analyst never transports or sees either digest.

`dsvertDPDatasetDescriptor()` is retained only for a custodian that already
has the padded-PSI object in the same trusted R process and deliberately uses
an explicit descriptor instead of the automatic registry:

```r
private_descriptor <- dsvertDPDatasetDescriptor(
  DA, id = "cohort-2026-07-main", version = "v1")
```

Do not copy these private snapshot or alignment commitments into client code,
logs, manifests, or DataSHIELD arguments.

The logical `id`, `version`, `id_col` and `purpose` must agree at every
vertical peer. Each site has its own private `snapshot_sha256`, because its
columns differ; the stable alignment binding is derived only from authenticated
common semantics. The signed PSI v4 contract never publishes either local
digest, identifiers, row order or intersection size. Raw-source authorization
remains distinct from the DP template: it binds the pre-alignment local
snapshot, whereas the registry binds the resulting aligned snapshot.
Missing/mismatched authorization fails before transport keys or protocol state
are created. This is deliberate custodian policy, not extra client-side DSI
configuration: the analyst's call remains unchanged.

## Differential-privacy policy

DP policy is deployment configuration, never an analyst argument. A typical
patient-level consortium configuration is:

Every site must persist one unique `dsvert.peer_name` in its DataSHIELD server
package profile before any authenticated peer bind. The deliberately blank
package default permits `ds.getIdentityPks()` and ephemeral transport bootstrap
for initial provisioning only; it is never inferred from a connection alias or
accepted from the analyst/relay. After verifying all identity fingerprints out
of band, each administrator persists the other sites' name-bound pins and
restarts the service. For K > 2, every server also persists the same designated
two-peer DP/GC pair; the client may relay that pair's signed messages but cannot
select or rename its members.

```r
options(
  # One independently sticky, canonical Synopsis artifact at a time.
  # These are not a global privacy budget or a caller admission limit.
  dsvert.dp.total_epsilon = 1,
  dsvert.dp.total_delta = 1e-6,
  dsvert.dp.domain = "cohort-release-v1",
  dsvert.dp.cohort_id = "cohort-2026-07",
  # Parent directory must already be persistent, owner-only Rock storage.
  dsvert.dp.synopsis_state_path = "/var/lib/dsvert/rock/dp-synopsis",
  dsvert.peer_name = "site_a",
  dsvert.trusted_peers = c(site_b = "<Ed25519-PK>",
                           site_c = "<Ed25519-PK>"),
  # Required only when the complete pinset has K > 2. Every custodian must
  # publish the same canonical two-peer subset; the analyst never selects it.
  dsvert.dp.designated_noise_peers = c("site_a", "site_b"),
  dsvert.dp.adjacency = "add_remove_patient",
  dsvert.dp.patient_column = "patient_id",
  dsvert.dp.unit_capacity = 100000L,
  dsvert.dp.max_records_per_unit = 20L,
  dsvert.dp.fixed_cohort_size = NULL,
  dsvert.dp.overflow_policy = "reject_snapshot",
  dsvert.dp.contingency_unit_aggregation_policy =
    "consistent_cell_else_exclude_v1",
  dsvert.dp.numeric_grid_bits = 16L, # integer lattice for bounded moments
  dsvert.dp.datasets = list(DA = list(
    # Stable ex-ante identity: use the same values at every vertical peer.
    # The live padded-PSI attestation fills the private bindings locally.
    id = "cohort-2026-07-main", version = "v1")),
  dsvert.dp.categorical_levels = list(
    exposure = c("no", "yes"), outcome = c("no", "yes")),
  dsvert.dp.numeric_bounds = list(age = c(0, 120), bmi = c(10, 80)),
  # Recommended for large schemas. This is identical server configuration at
  # every pinned peer, never an analyst request argument.
  dsvert.dp.workload_scope = list(
    mode = "catalog_v1",
    selection = list(explicit_catalog = list(
      numeric_moments = c("age", "bmi"),
      categorical_marginals = c("exposure", "outcome"),
      categorical_pairs = list(c("exposure", "outcome")),
      correlations = list(c("age", "bmi")))))
)
```

DP is the sole production release mode and cannot be disabled by an analyst.
Each canonical, signed Synopsis artifact has one deterministic sticky release:
the same artifact replays byte-for-byte after restart without reading protected
source or drawing new noise. There is deliberately no request counter, rate
limit, catalog limit, lifetime admission limit, or global finite-composition
claim. A distinct artifact is a distinct DP release and must be interpreted
with its own declared `(epsilon, delta)` scope; dsVert does not pretend that an
unlimited collection of distinct analyses has one finite global privacy bound.

Physical safety bounds are separate from privacy admission. The signed capacity,
per-unit contribution bound, lattice width, fixed work geometry and bounded
spool sizes may reject an unsafe *declared computation* before source access;
they never consume an entitlement or block a later canonical artifact. A
durable conflict or corrupted state fails closed rather than producing a second
sample or a silently different release.

Without `dsvert.dp.workload_scope`, the compatibility default is exactly
`list(mode = "all_schema")`: count, every bounded numeric moment,
every categorical marginal, and all same-owner/same-dataset categorical and
correlation pairs are included. This preserves schema-wide results but its
pair coordinates and sensitivity grow quadratically. `catalog_v1` always
retains count and automatically adds/deduplicates primitives required
by custodian-owned describe, Gaussian, survival, and signed vertical-cross
specifications; undeclared primitives add neither coordinates nor sensitivity.
The canonical selection and projected cost are signed into the manifest and
source authorization, so a client cannot enlarge it. See
`inst/docs/biomedical_capsule_local_materializer.md` for the complete contract.

For contingency tables, repeated copies of one valid cell contribute once;
units containing distinct valid cells contribute zero. Missing and
out-of-domain rows are ignored for this consistency check. This sole accepted
policy is public and query-bound, and releases never expose the exact number of
conflicting or excluded units.

The dataset `id` and `version` are stable custodian declarations and must agree
across all vertical peers; they must not be derived from patient data. Exact
snapshot and ordered-ID commitments remain private server configuration and
are validated locally. DP status and PSI responses expose only the stable
cohort/dataset attestation, never those commitments or a row count.

Synopsis manifests, execution records, encrypted transient sessions and public
replay records live under the owner-only Rock state root. The service verifies
the configured `synopsis_state_path` and its parent before creating state;
temporary, shared-memory and installed-library paths are rejected in
production. Ring128 values remain canonical integer strings until all signed
bounds, hashes and reconstruction checks have passed.

### Archived capsule-control record

The remaining capsule-control discussion is retained only as an audit record
for unregistered compatibility code. It is not deployment configuration,
does not describe the promoted Synopsis paths, and must not be used to infer a
lifetime admission, ledger setting, request limit or catalog limit.

The ledger directory must already exist on persistent private storage, be
owned by the service account and have mode `0700`. dsVert canonicalises the
parent path, rejects symbolic-link/non-regular database and sidecar targets,
and creates the database, lock, WAL and SHM under `umask 077` with mode `0600`.
These checks prevent substitution by an unprivileged local user; control of
the service account/root or replacement of the directory is a compromised-host
case and is outside the threat model. Policy, cohort, complete
logical-name-to-Ed25519 pinset, PSI alignment manifest, identity key and ledger
are immutable as a unit. The configured composition partition count must equal
the complete pinset size if that obsolete compatibility option is retained;
otherwise K is derived directly from the complete pinset.

The target single safe publication ledger is automatic: the current control
plane uses exactly two custodian-designated Ed25519 computation peers from the
complete K-peer pinset to replicate one capsule chain and cross-sign prepare,
commit, authorization, opaque result-commitment and delivery receipts. It
therefore needs no administrator-written `dsvert.dp.anchor_provider`, does not
partition epsilon as `epsilon/K`, and does not allocate privacy per method.
Each capsule uses fixed policy-owned epsilon/delta. Its allocator index both
orders the rollback chain and records one non-refundable lifetime reservation;
the authenticated registry counts reservations, while the publication ledger
separately counts public releases. The lifetime claim additionally assumes one
stable, unique privacy accountant namespace for each protected privacy
universe across deployment reconfiguration; this continuity is custodian
managed rather than automatically enforced or migrated. Its rollback claim
assumes that at least one designated non-colluding peer retains and uses its
complete durable authenticated ledger history. The
analyst/DSI relay may replay, reorder, suppress or fork messages but cannot
forge that peer's signatures. Simultaneous rollback of every peer to mutually
consistent old images remains outside this assumption.

The durable control plane and private capsule-to-payload spool are implemented:
a capsule creation is recorded once globally; exact payload bytes are persisted
before a domain-separated HMAC-SHA256 commitment is signed; both peers store
the ordered result receipts and
commit set; retries after crashes or lost acknowledgements are byte-sticky;
and a conflicting payload cannot obtain both delivery signatures while one
peer retains its state. Unlike the retired public payload hash, the v2
commitment does not give the analyst/relay an offline dictionary predicate for
a low-entropy output; legacy v1 result receipts fail closed. No seed, payload
or generic state mutation is remotely callable. See
`inst/docs/joint_dp_result_confidentiality.md` for the exact threat boundary.

The biomedical vector wire/storage ABI is frozen as a pre-release baseline:
signed PREPARE receipts use v6; signed START, RESULT, RELEASE and ACK receipts
use v5; the authenticated STORE schema uses v6; its per-capsule claim row and
authenticated claim-set state use
`dsvert-joint-dp-vector-instance-claim-v1` and
`dsvert-joint-dp-vector-instance-claim-state-v1`; replay uses v4. Every signed
phase receipt and replay response must carry exactly `history_gate=TRUE`,
`request_limit=FALSE`, and `operation_limit=TRUE`. No legacy v4/v5 store is
automatically migrated or re-signed. Deployment therefore requires empty DP
capsule state or a future audited offline migration; a legacy store fails
closed. Previous Opal environments had `POLICY_READY=FALSE`, published no DP
capsules and used only ephemeral local K-site state.

Exact COMMIT/RELEASE endpoint replay and sticky replay within the same live
session are O(1). A cold end-to-end reconstruction after process restart is not:
it re-enters through AllocationProof and performs a complete O(N) audit of the
allocator journal before returning the proof. That validation still consumes no
lifetime unit, draws no noise and reads no protected source.

That pre-release baseline also requires `dsvert-joint-dp-control-v3` and
`dsvert-joint-dp-capsule-identity-v3`, which bind the lifetime contract and
biomedical workload v7. A v2 control or capsule-identity artifact is legacy and
fails closed; it is not automatically migrated or re-signed. Deployment must
therefore use empty DP capsule state or a future audited offline migration.
The registered biomedical-vector DSI path now carries this contract end to
end: signed allocation, bounded source materialization, joint sampler shares,
one final opening, durable release/replay, and bilateral finalization. Scalar
Laplace vectors use the exact-GC one-draw backend; wider vectors use the
scalable two-independent-complete-draw convolution. The fixed-work dyadic
discrete-Gaussian backend is selected only when its signed exact plan is
eligible and improves the certified simultaneous radius. The retired bare
per-query SQLite release engine is absent; `dsvert.dp.ledger_path` remains only
the namespace prefix for the promoted stores.

For K greater than two, the control-plane transcript binds the complete pinset,
its derived `peer_count`, and the canonical `designated_noise_peers` pair. Only
that pair can sign allocator receipts. Integrating shares from every one of the
K data holders is bound to the signed capsule/source manifest before the two
designated peers jointly noise and open the vector. Custodians may configure
that pair server-side; otherwise the policy deterministically chooses the first
two logical names in the sorted complete pinset. This is a selection of compute
peers, not a selection of data contributions: all K holders remain bound, and
the analyst cannot redefine either the pair or the workload.

`dsvert.dp.anchor_provider` remains optional for additional
rollback defence. Its `capabilities` action returns `schema_version`, a public
`provider_id`, and true `external`, `durable` and `linearizable_cas`
attestations. `read` returns `NULL` or the exact v2
`schema_version`/`policy_hash`/`next_index`/`chain_head` receipt;
`compare_and_swap` receives `expected` and `replacement` and returns `swapped`
plus current state. The provider must persist outside the protected host and
must not be mutable by the analyst. These are operational attestations, not
properties dsVert can prove remotely. With or without this callback, every
future capsule publication must consume the same cross-signed global index and
result-commit protocol. The callback may additionally anchor each peer's
capsule chain; it never enables a separate local
`epsilon/K` route. The current CAS schema does not anchor `joint_outputs`, so
simultaneous rollback of every result spool still requires the stated retained
honest-peer assumption. Promotion must either keep that scope explicit or
extend the external receipt to the delivery-commit head.

If a restored snapshot leaves the external anchor ahead of the local mapping,
dsVert fails closed until custodians restore that mapping. It never fabricates
a replacement or silently changes sticky noise. There is no production
`custom`/unsafe policy branch: immutable snapshot binding, ordered PSI
attestation, owner-only ledger storage and an authenticated retained anchor
(pinned peer, optionally strengthened by external CAS) are invariant. Use
`ds.vertDPCalibrate()` before selecting fixed per-capsule privacy parameters
and record the scientific rationale for clipping bounds, capacity and epsilon.
Repeated or distinct supported operations over the exact claimed capsule
release are free post-processing. New capsules for overlapping snapshots
compose and are admitted only while a lifetime unit remains. At most one public
`release_instance` may ever be published for a capsule. PREPARE stores only an
authenticated candidate, so sibling candidates may coexist before a claim. The
first valid START at each designated peer atomically and irrevocably claims one
`release_instance` before that peer reads its staged source or samples; it does
not spend another lifetime unit. Encrypted protected material may already have
been staged by source transport before START, but no noised share or public
output exists at the claim boundary. A release-domain rotation may select a
different candidate only before that claim. Afterwards only the claimed
instance may progress: retry and restart continue it exactly, and missing state
must be restored or fail closed. After publication only exact replay/restore is
allowed, never resampling or a second instance.

The noise-root provider contract exposes only public provider/key identifiers
and HMAC-SHA256. Package installation, `configure` and identity-only service
operations make no changes to noise-root state; the first legacy DP policy
invocation atomically creates or validates `~/.dsvert/privacy/noise_root` (or
`$DSVERT_STATE_DIR/privacy/noise_root`; Rock falls back to
`$ROCK_HOME/.dsvert/privacy/noise_root`) under an interprocess lock. The key is
32 bytes encoded as lowercase hex in a `0600` single-link regular file below a
`0700` owner-only directory. Temporary, shared-memory and installed-library
paths are rejected again after resolving ancestor symlinks. Before first
creation, dsVert rejects any configured prior local or joint ledger; when a
complete DP policy is already active it also checks the
bound external rollback anchor. Durable key and directory sync is required,
and a key-id deployment receipt prevents later key loss from being mistaken
for a fresh deployment. Each file root also has an append-only epoch journal:
every pending/active transition and its composition snapshot is chain-HMACed
under a domain-separated key derived from the persistent Ed25519 identity.
A pre-receipt upgrade authenticates any surviving local or joint release
history with the candidate root before writing that receipt; orphan non-empty
SQLite WAL/SHM state also fails closed.

If the root file disappears, the identity-wrapped recovery envelope is always
tried first and restores the exact same sticky randomness. If both root and
recovery are irrecoverably absent, but the epoch journal and surviving release
history authenticate under the persistent identity, dsVert automatically
draws a new 256-bit CSPRNG root as the next privacy epoch. A durable `pending`
record makes this rotation restart-safe; the previous key id and cumulative
composition remain audit history, while queries are sticky within the new
epoch. If only a valid receipt survives and there is no journal, release
ledger, rollback anchor or authenticated release history, dsVert records the
unreleased receipt as epoch 1 and performs the same authenticated rotation;
malformed or contradictory evidence is never downgraded to first-install
state. Root rotation itself is not a request counter, but every new capsule in
the new epoch remains subject to the authenticated lifetime bound and the
surviving reservation history. Rotation does not rebind an already claimed
capsule: that capsule must continue or replay its exact claimed instance, or
fail closed. Corrupt/unverifiable state is not treated as
loss, and an explicitly configured HSM/KMS provider never falls back to a local
file key.
Reinstall and restart reuse the same key; container replacement requires that
state directory to be a persistent volume. The built-in file store is
POSIX-server-only. A Windows dsVert server must configure
an external HSM/KMS provider; dsVertClient remains Windows-compatible. Rotation must advance
through authenticated consecutive public privacy epochs, bind every previous
key identifier and retain the existing cumulative composition audit—it never
erases earlier capsules. That continuity statement applies when the persistent
identity can still authenticate the journal/history. After simultaneous,
irrecoverable loss of both reciprocal roots, the old state is preserved but
cannot honestly be authenticated by the replacement epoch; composition across
that boundary cannot be used to claim a fresh lifetime allowance. Simultaneous
loss or rollback of every retained peer store is outside the package model
unless an external monotonic authority anchors the history. Within the stated
threat model, the formal claim is computational output differential privacy,
conditional on successful validation of this fixed setup, secrecy and correct
operation of the noise root/provider, and authenticated ledger integrity. A
root compromise can make past noise reproducible and is therefore outside the
claim; provider identifiers are attestations, not remote proof of key custody.
Admission, sampler, cache-hit and transport timing, availability, and detailed
setup or integrity errors are not currently data-independent transcripts. A
deployment requiring traffic-flow privacy must add a separately
validated fixed-time/asynchronous or padded serving layer. For the pending
joint path, divergent rollback is detected when at least one honest peer
retains and uses its complete authenticated ledger history. Simultaneous
rollback of every peer's result spool is
outside the current claim even when the optional v2 CAS protects the allocation
head; extending that receipt to delivery commitments is a remaining hardening
gate.

Consortia with two through five vertical sites use one custodian-declared,
transcript-bound pair of computation/noise peers inside the complete pinned
K-peer consortium. Every site's bounded source is split to both designated
peers, while every custodian signs and attests the immutable manifest and
snapshot contract. Connection order and the analyst/relay cannot select or
substitute that pair. Confidentiality still requires the two designated peers
not to collude; malicious-peer correctness is outside the claim.

## Validation

The server test suite verifies the exact registration allowlist, retired
namespace exports, PSI state/manifest behaviour, path and identity boundaries,
the persistent DP accountant (including concurrent memoisation and tamper
detection), and Go numeric/parser guards. Full method claims additionally require fresh
distributed-vs-centralized validation on independent server hosts.

The executable method evidence is maintained in the client package because the
client vignettes drive the full DSLite workflow. See the
[dsVertClient validation summary](https://isglobal-brge.github.io/dsVertClient/articles/validation_summary.html)
for the current K=2/K>=3 distributed-vs-centralized validation matrix.

## License

MIT - see [LICENSE](LICENSE.md).
