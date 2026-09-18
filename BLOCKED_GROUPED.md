# Grouped release status after Addendum 3 — 2026-09-18

The former arithmetic-ownership and composed-GC traffic blockers are resolved
or withdrawn. Dealer-free checked-OT Ring192 products now exist in 80aee12.
No dealer/approximate truncation route was adopted. Measured component results:

| Component | Measured two-direction bytes | Elapsed pod seconds |
|---|---:|---:|
| 1024 exact Beaver products | 37,912,128 | 7.903936 |
| 32 wide-output exp profiles | 5,252,563 | 0.901655 |
| one signed Ring192-to-two-limb lift | 89,936 | 0.110025 |
| one LMM final clamp/rescale | 277,399 | 0.261466 |

These are component runs, not full releases. No member of the requested 3x3
matrix is admitted, and no new full-release traffic failure is asserted.
Evidence: inst/grouped-validation/dealer-free-product.json and
addendum3-validation.json. Existing signed capacities are unchanged.

The external release integration remains unavailable: Step 2, fetched through
2f36f79, provides an internal fused GLM kernel and joint-noise tests but explicitly
leaves authenticated R source/admission/lifecycle/client wiring unfinished.
A local MAC, raw component output, or synthetic DSLite evaluation cannot replace
that authorization/evidence boundary. Protected materializers/readers stay closed.

This is NOT a claim that all remaining lane work is externally blocked.
Private GEE whitening and its full certificate/oracle, complete grouped source
and primitive scheduling, all nine full-release measurements, protected DSLite
lifecycle tests, and completed current-snapshot package checks are still open.
Exact integration steps are in INTEGRATION_GROUPED/LMM/GLMM/GEE.md.
