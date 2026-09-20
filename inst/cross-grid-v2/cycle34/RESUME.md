# Cycle34 — authenticated Cox vector-reader boundary

Client code **5b6458f** adds `.dsvert_dp_cox_cross_read_vector`: it combines
existing Synopsis RELEASE signature verification, bilateral REPLAY chunk/Merkle
validation, and both signed Cox publication receipts. It re-derives the signed
layout/lattice and checks that the selected Cox block has zero additional shift.
The output is the exact candidate integer vector consumed by existing Cox result
processing. N<=400 staged scope is retained; no public dispatch is opened.

**Important prerequisite/scope:** `trusted` and `compiled` are internal inputs
that must come from authenticated bundle/compilation validation, exactly as in
the shared Synopsis helpers. Tests supply a synthetic compilation/DP-vector
fixture and real Ed25519 signatures. This closes the internal vector-reader
boundary, not public Cox compilation/admission, orchestration, portable
certificate integration, an actual DP release, recovery, capacity or promotion.

Final fresh snapshot: **16 tests / 496 assertions PASS**, zero failures/errors/
warnings/skips. K2/K3/K5 exact integers, first tied minimum, cold JSON round trip,
actual Cox result processing, signed cap boundaries, and changed/missing/forged
RELEASE, REPLAY and publication evidence are covered, plus existing Cox and LMM
regressions. The first narrower iteration also passed. Both 2646-file snapshots
are unchanged. Executable R/tests and runtimes match final committed bytes;
only client STATUS_COX.md changed after the final snapshot. See R_PROOF.json.

Priority F: server/native/sampler unchanged. Fresh real-native Gaussian fallback
regression passes all 10 assertions. Cycle28's signed n2000 base/recovery
diagnosis remains applicable: the optional Gaussian coverage gap is live, both
select certified Laplace, with no wrong sigma or replay-only derivation mismatch.
Pod16's terminal alignment-mask worker-readiness cause is still unresolved.
Shared DP remains owned here; GEE must not fork a sampler change for the caught
Gaussian diagnostic. No privacy/support/sampler change or new math blocker.

**4/10 promoted**, exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial,
ordinal. NB's math gate remains closed per cycle32. Confirmatory simple-client
paired was still active at 12:36 UTC; all 2504 frozen hashes unchanged. Server
paired remains 1164 tests/21062 assertions PASS. No new simple release.

Frozen cycle16 LMM remains incomplete at 12:32 UTC; all 2553 hashes unchanged.
Read-only process metadata confirms the intentionally stopped queue controller
and its live child release. Two later descendant samples 44.5s apart show CPU
increments in both native workers and all three R processes. The main R process
was once sampled in `request_wait_answer` on a FUSE-backed /workspace mount;
that does NOT establish a stall or its cause. Native workers have different cwd
and were absent from the first cwd-only filter; descendant traversal includes
them. Kernel stacks/syscalls were unavailable (permission denied), recorded as
such. No attach, signal, private-state read, restart or frozen modification.
Do not resume the obsolete queued sequence. LMM_HEALTH_SUMMARY.json records the
observations without extrapolating capacity or speedup.

Reviewer baseline jobs on pods12/14/15 were observed only and retain their
502b005/4c6c562 pins. Updated manifests do not authorize duplicate jobs.
The minimal manifest remains 24 real epsilon8 definitions, four per family:
K2/K3/K5 baseline plus K2 recovery with cold/tamper, one capacity marker/family;
1080 separate oracle-only definitions. Twelve LMM/GLMM jobs are ready; Cox/GEE
remain unready. MANIFEST_VALIDATION.json records the new exact pair and all nine
regenerated exact oracle commitments. Promotion rows keep their original pins.

Next work: connect Cox signed source registration/routing, pre-START sampler
binding/post-START injection and authenticated compile/portable certificate
reader dispatch; LMM authenticated relay batching with fresh baseline and
bilateral/unilateral recovery equality and capacity; complete heavy release
gates; harvest confirmatory client paired and preserve any defect; retain
native-startup logs on a fresh reviewer-owned pod16 retry. No GEE-owned edit,
tag, push, thesis edit, model escalation or new real release this cycle.
