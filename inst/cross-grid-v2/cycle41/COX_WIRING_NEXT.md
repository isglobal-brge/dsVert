# Cox after cycle41

Client catalog fragments now recognize cox_grid_cross_v1 without an outcome
field. Raw-wrapper version/dataset and analysis identity are bound; time/event
must have consistent dataset, qualified reference, distinct columns and common
owner. Both authenticated capsule draft and signed Synopsis bootstrap draft
parsers pass the advertising peer into this preflight. K2/K3/K5 signed draft
fixtures pass; another advertising owner and modified signed bytes reject.
Preflight is structural, not a substitute for the full contract/schema validator.
The latter validates the retained contract in the focused tests. No test doubles
are used in the new draft/fragment tests. Existing wider suites retain theirs.

Still required before enabling public admission/fleet readiness:
- Server dpCapsuleWorkload.R artifact loop (currently line 3439) explicitly
  rejects Cox. Validate the contract against the actual signed schema and
  project .dsvert_dp_cox_cross_workload_artifact with its sensitivity accounting.
- Client artifact discovery, source layout, compilation and certificate dispatch
  need Cox branches; reuse the authenticated Cox public reader.
- Owner-first bind must call the time owner, validate its signed public routing
  receipt and pass it to the evaluator. No private routes cross the client.
- Prove complete signed source-sharing/persistence, native-to-DP, bilateral and
  unilateral recovery, cold replay and tamper rejection on a small fixture.
- Only then publish Cox fleet-ready rows, preserving N<=400 scope.

LMM batching remains at cycle40/LMM_BATCHING_BOUNDARY.md. Compile reuse already
exists. Old-pair K5 fails 6h capacity; do not promote or reattribute its metrics.
Shared optional-Gaussian fallback remains owned here and tested; GEE must not
fork a sampler patch. No GEE-owned files changed.

Concrete next client dispatch sites inspected in cycle41:
- dp_glm_grid_cross_materializer.R:2 discovery currently omits bounded Cox;
  :49 source-block builder assumes an outcome except for grouped artifacts.
- dp_capsule_source_transport.R:594, dp_gaussian_cross_transport.R:80 and
  dp_synopsis_lifecycle.R:1367 all consume that discovery helper.
- dp_synopsis_vector_runner.R:254/:455 consumes the same artifact set.
  Adding discovery alone would route Cox through outcome/grouped assumptions;
  implement and test layout/materialization and orchestration together first.
- dp_cox_grid_cross_release.R already projects the exact Cox workload artifact
  and has the authenticated cold reader. Reuse those functions.
