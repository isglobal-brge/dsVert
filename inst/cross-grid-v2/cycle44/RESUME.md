# Cycle44 checkpoint — 2026-09-20

Cox internal client orchestration now uses the existing authenticated durable
executor: setup/alignment, owner-first signed routing receipt, prepare/start,
private native execution, store and finalize. Its exact native operation is
`cox-loss-staged-v1`. The shared receipt verifier now admits that operation for
Cox only, preserving grouped LMM/GLMM domains. Source layout and its commitment
match the server at K2/K3/K5, including padded private presence lanes. N<=400.
The shared executor retains the existing LMM control flow; no relay batching,
integer arithmetic, native code or packaged runtime changed.

Focused proof: **10 tests / 630 assertions PASS**, zero failures/errors/warnings/
skips. Actual Ed25519 signatures authenticate Cox route/stage/public receipts.
Transport, alignment and native invocation are test doubles in the new test:
all four bilateral persisted-state combinations verify whether computation is
required; invalid operations/purposes/plans/terminal receipts and source layouts
reject; cleanup runs on success and failure. This is NOT a real Cox DP release,
native recovery experiment, paired suite or capacity measurement.

**4/10 promoted**, unchanged at f3795a2/e748f05. NB remains resolved.
Envelope remains **256 GB serialized aggregate RPC / 8 h (28,800s)**.
The fleet still has **10 running / 2 terminal** jobs at this observation. Its
original-pair results remain 1 PASS (LMM epsilon8 K5) / 1 FAIL (old Gaussian
optional preflight). No new family has complete promotion evidence. Do not
restart the wave or relabel its source identity. Existing cycle43 measured
capacity table and simple confirmatory paired evidence remain authoritative.

The deferred-batching n4 smoke remains PASS; its separate paired suite still
has no exit marker, with all3025 frozen files matching. It does not establish
capacity or validation of this client's new Cox orchestration. No frozen run
was modified or restarted. Shared optional Gaussian handling stays owned by
this integration lane; no new sampler fix or GEE fork is needed here.

Remaining Cox work before FIRST release/fleet readiness:
1. Coordinate signed workload admission (server artifact-loop rejection and
   contract runtime states), client discovery and exact artifact reconstruction.
2. Wire the internal Cox orchestrator into public dispatch, source transport
   and certificate/runner reconstruction. Use the existing authenticated Cox
   cold reader; do not pass Cox through outcome/grouped assumptions.
3. Run a signed small source-to-native-to-DP lifecycle with independent oracle,
   actual bilateral/unilateral recovery, cold and source/stage tamper checks.
4. Emit four ready Cox jobs with the actual <=400 observation scope, then run
   its first fleet wave. Current Cox placeholders are not ready releases.

No new math blocker, GEE-owned edits, simple releases, speedup restoration,
thesis edits, tags or pushes. The ready LMM/GLMM manifest definitions remain
available, with the explicit instruction to harvest/re-score the existing wave
rather than launch duplicates. Oracle dependency equivalence preserves original
commitment-computation provenance when rebinding definitions to final commits.

Evidence: integrator-evidence/cycle44-20260920/PROOF.json, client-tests.log,
FLEET_LIVE_STATUS.json, FLEET_RESCORED.jsonl, PAIRED_CURRENT.json,
MANIFEST_VALIDATION.json and ORACLE_DEPENDENCY_EQUIVALENCE.json.
