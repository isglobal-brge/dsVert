# Cox lifecycle after cycle38

Shared capsule/Synopsis source-contract construction now dispatches the exact
Cox-only private transport projection. It preserves the fixture's complete
contract hash and namespace at K2/K3/K5, without adding Cox to generic GLM
materialization. The exported evidence action recognizes the exact Cox version,
checks publication/compilation equality, reconstructs the namespaced source
contract, loads the signed schema and calls the authenticated Cox evidence
reader. It uses no live session and no private candidate rows.

These boundaries have upstream materializer/catalog and publication lookup test
doubles in the new tests. Catalog admission is still closed; this does not prove
a full real DP release. No Cox fleet readiness or capacity claim. N<=400 remains.

Next: signed Cox workload catalog validation, Claim/transport selection of the
existing exact binary64-rational Cox producer, client owner-first bind/routing
handoff, and trusted compilation/certificate dispatch. Then prove the complete
small DP lifecycle/recovery/cold/tamper before enabling fleet jobs. Do not pass
Cox source blocks to generic GLM floating-point materialization.

The shared source constructor now produces the required layout/hash; remaining
catalog and producer call sites from cycle37 are below. The old statement that
exported evidence does not dispatch Cox is superseded by this checkpoint.

---

# Cox lifecycle after cycle37

The exported `dsvertDPSynopsisGLMGridCrossDS` stage endpoint now accepts
`routing_receipt_json` for Cox bind. Omitted/empty on the owner's first bind;
the evaluator must supply the owner's signed public receipt. Supplied values
use the existing DSI framing and bounded canonical JSON decoder. The exact Cox
artifact version selects the existing authenticated adapter; other families
reject nonempty routing receipts, as do non-bind actions. Batch must be zero.
The adapter validates the sole Cox projection, signed schema, source, authority
and immutable request; shared stage dispatch handles subsequent actions.
Client DSI framing knows the new argument. This does NOT add client discovery,
owner-first orchestration or public source admission. The Cox bind response
contains `bound` (the existing signed receipt JSON) and `routing_receipt` (the
signed public object). The client must verify both, then canonicalize/frame only
the latter for the evaluator; do not feed this envelope to the flat grouped
bind receipt reader. Evidence action still
uses the old supported-grid gate and does not dispatch Cox.

Remaining:
1. Connect Cox explicit artifact discovery and signed workload validation in
   server/client catalogs. Use the existing distinct Cox source projection,
   producer and N<=400 private-v2 contract, never the grouped-source projection.
2. Extend the shared Synopsis source producer/claim/transport gate to select the
   Cox producer using the authenticated cached schema and namespaced source
   contract. Test signed Claim equality and complete persisted sharing, including
   source owners beyond the two computation authorities.
3. Wire the client runner to the new endpoint branch, with owner-first bind and
   forwarding only the signed public routing receipt to the evaluator. Retain
   immutable compilation/claim request checks, zero batch, and reject changes.
   Do not encode private routing or opaque worker input in an RPC receipt.
4. Connect explicit Cox publication evidence and certificate/compilation reader
   dispatch. Existing internal reader checks authenticated RELEASE/REPLAY,
   Merkle and signed terminal provenance; it still needs a trusted compilation.
5. Prove a fresh small complete authenticated DP lifecycle before fleet-ready:
   source sharing -> private worker -> durable terminal -> DP -> cold public
   reader, bilateral/unilateral recovery and source/stage tamper rejection.

Cox kernel-only capacity and these fixture-backed adapter tests are not a full
DP release, capacity measurement or promotion. LMM batching requirements remain
in ../cycle35-20260920/LMM_BATCHING_NEXT.md; frozen runs remain untouched.

Concrete registration call sites from the final read-only map:
- `dpCapsuleWorkload.R`: `.dsvert_dp_capsule_gaussian_spec` (1324) and
  `gaussian_artifacts` assembly (3422); add a distinct Cox kind and validator,
  with event/time descriptors, rather than fabricating an outcome/grouping.
- `dpCapsuleManifestDS.R` (886): signed contract admission/discovery.
- `dpGLMGridCrossMaterializer.R`: artifact discovery and explicit Cox source
  block dispatch; `dpGaussianCrossDS.R` (213) and the ordinary capsule source
  contract constructor must produce the same layout/hash as the Cox context.
- `dpSynopsisAnalysisDS.R` (446) constructs the Claim producer;
  `dpSynopsisSourceTransportDS.R` (138) constructs the sharing producer. Both
  must select the same Cox materializer, authenticated schema and manifest.
  Preserve exact Cox binary64-rational q50 normalization; do not silently route
  Cox values through the generic floating-point GLM source-value function.
- `dsVertClient/R/dp_synopsis_vector_runner.R` (254,367,455) currently discovers
  simple/grouped grids and drives their stages; add Cox explicitly, including
  all K source owners and the two computation authorities separately.
- `dsVertClient/R/dp_gaussian_certificate.R` has separate descriptor validators,
  model discovery and public result dispatch; old same-owner Cox descriptors
  are not the staged cross-owner contract.

These are next-step locations, not edits or proof that public dispatch works.

Cycle38 follow-up detail: Claim generation in dpSynopsisAnalysisDS.R still
calls the generic Gaussian producer without a source contract, while the
transport gate in dpSynopsisSourceTransportDS.R closes over the artifact-bound
source contract. Both must choose the Cox producer after signed-schema and
manifest validation. Preserve the original manifest identity for source
commitments and use the artifact namespace only for durable transport (the
cycle22 Cox adapter already implements that distinction). Do not assume the
new layout registration alone makes either generic producer safe for Cox.
