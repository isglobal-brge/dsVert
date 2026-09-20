# Cox lifecycle after cycle36

New `.dsvert_dp_cox_cross_remote_bind` in `dpCoxGridCrossPrepare.R` is an internal
adapter, not an exported endpoint or fleet-readiness claim. It validates the
Synopsis source transport context against the supplied source, checks the
manifest hash and cached signed schema, restricts computation to the two signed
authorities and retains immutable request admission for the shared dispatcher.
Only the time owner resolves snapshots. Existing Cox bind authenticates live
alignment/identity, regenerates and compares its durable source commitment,
authenticates the owner's routing receipt and prepares the native worker.
The evaluator receives that signed public receipt and resolves no snapshots.
The return value contains the signed bound receipt and signed routing receipt.

Remaining:
1. Connect Cox explicit artifact discovery and signed workload validation in
   server/client catalogs. Use the existing distinct Cox source projection,
   producer and N<=400 private-v2 contract, never the grouped-source projection.
2. Extend the shared Synopsis source producer/claim/transport gate to select the
   Cox producer using the authenticated cached schema and namespaced source
   contract. Test signed Claim equality and complete persisted sharing, including
   source owners beyond the two computation authorities.
3. Wire the exported stage endpoint and client runner to the new adapter, with
   owner-first bind and forwarding only the signed public routing receipt to
   the evaluator. The current endpoint has no routing-receipt argument. Retain
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
