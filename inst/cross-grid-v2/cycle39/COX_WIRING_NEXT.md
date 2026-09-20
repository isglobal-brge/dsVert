# Cox after cycle39

Claim and source-sharing materializer now dispatch through a common selector.
Cox selects the existing exact binary64-rational producer after signed-schema
lookup and full private source-context validation. Claim uses the base source
contract; sharing supplies the artifact namespace. Existing producer semantics
keep commitments tied to the original manifest capsule. The private route is
not returned to the generic transport; the existing owner bind reconstructs it
from authenticated snapshots after checking the durable source commitment.

New tests exercise all source owners at K2/K3/K5 and compare complete private
source bytes/value commitments with the original producer and namespace. They
mock catalog/source-contract construction, schema lookup and transport context;
this is not a complete signed Claim/sharing transaction. Public admission stays
closed. Existing signed schema, native worker and persistence regressions remain.

Next: signed workload catalog validation (dpCapsuleWorkload.R and
 dpCapsuleManifestDS.R), client discovery/owner-first bind and routing receipt
handoff, compilation/certificate dispatch, then complete small authenticated DP
release/recovery/cold/tamper proof. Retain N<=400 and private presence composition.
Do not enable Cox fleet readiness until that proof passes. Detailed call sites:
../cycle38-20260920/COX_WIRING_NEXT.md. LMM batching boundary:
../cycle35-20260920/LMM_BATCHING_NEXT.md. GEE remains separately owned.

Additional catalog call sites checked this cycle (read-only):
- dpCapsuleWorkload.R:2842 must resolve time AND event plus predictors by
  owner/column/dataset and skip unrelated public moment expansion. Cox cannot
  use the current outcome/grouping assumption.
- dpCapsuleManifestDS.R:412 normalizes the advertised contract on the outcome
  owner for existing families. Cox needs an explicit event/time descriptor
  branch with its owner authorization, without inventing an outcome field.
- dpCapsuleManifestDS.R:887 must preserve the signed Cox contract during raw
  normalization, as existing cross-grid families do.
- dpGLMGridCrossMaterializer.R:195 already recognizes cox_grid_cross_v1 for
  snapshot-identity canonicalization. It strips self-referential hashes and
  signatures; no additional Cox change is needed there for this version.

Additional diagnostic `signed-claim.R` loads the same immutable source snapshot
and real fixture signing keys. K2 real Ed25519 Claims validate and match the
source-sharing commitment validator; changed source bytes and changed signed
commitments reject (8 assertions). Catalog projection is a validated fixture
projection, not real Cox admission; schema lookup and transport context remain
mocked. This proves signed commitment equality, not complete durable sharing.
