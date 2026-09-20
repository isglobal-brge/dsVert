# Cycle18 second continuation — Cox time-sidecar adapter; release gates pending

Code `cc862ea5da622b284fe5d06b70cd465b803aa78c` / `4c6c5622fbdc2ae97de315f18c18901d452f3c09`. Native runtimes remain b59d34c.
LMM Promoted=No; no completed n2000 result or capacity measurement harvested.

## Release evidence

Source-verifying harvest at 06:48 UTC: LMM cycle16 r2 remains n2000/K2,
2553 source hashes match; controller identity/cwd/stdin remain correct.
GLMM cycle17 binomial remains queued behind its shared lock,2556 hashes match;
Poisson follows its successful sequence. No frozen snapshot/controller was
changed or duplicated. Both retain24h total/15min inactivity leases; the release
capacity gate remains256,000,000,000 serialized aggregate-RPC bytes/21,600s.
At06:47 UTC LMM had205 COMMIT stages per authority, product000012 active.
That is unauthenticated progress, not completion, oracle equality or capacity.
The reviewer n2000 milestone is still uncorroborated by the retained machine
evidence; the existing n4 oracle marker must not be relabelled n2000.

K3/K5/recovery/full paired remain subsequent stages in the existing LMM driver.
Each release's harness retains sticky/source+stage tamper/direct+exported cold
proofs. Do not mark promotion before every actual complete gate is reviewed.
Cycle18 cap-source paired snapshot e4df243/4c6c562 remains active;2563 hashes
match, no completed package pair. It excludes later Cox changes and is not
current-source/full-grid capacity evidence. Existing local collectors49135,
69790,78671 retain their recorded command/start identities (collectors.txt).

## Cox change and verification

Added the internal owner-local time-routing sidecar and handoff adapter in
`R/dpCoxGridCrossSource.R`, reusing the LMM source-commitment/MAC pattern.
It requires the time owner to be the pinned-identity garbler, binds the signed
spec/source/layout, producer snapshot/value commitments and private alignment,
and checks time-validity lanes against the committed producer's read_range.
Bounded observed times retain exact binary64 bytes with canonical positive
zero; invalid slots use zero plus false validity. A domain-separated private
MAC covers those bytes. Stable descending-time/tie-end routing remains private.
Handoff revalidates the MAC and reconstructs the binding from fresh owner-local
inputs, rejecting stale sources, altered ordering, validity or precise times.
Cold JSON serialization returns the same canonical routing shape.

This adapter accepts trusted owner-local inputs from the same resolved
snapshot/PSI slots as its producer; it is NOT a new remote input endpoint or
a completed producer. Wiring actual snapshot resolution/normalization and
sidecar persistence, private complete-case composition, durable DP handoff
and the public signed lifecycle remains. No Cox release or capacity is claimed.

Focused local R PASS:16 tests/914 assertions, zero failures/errors/warnings/skips.
K2/K3/K5 cases cover source-commitment/alignment changes, time/route tampering,
precise binary64 changes preserving the same permutation, validity mismatch,
role restrictions, invalid/padded slots, tied events/censor slots and cold JSON.
Existing actual SQLite MAC/completeness/live-key tests still pass.
The first run exposed list-order instability after cold JSON; handoff now returns
its freshly validated canonical routing. The next run passed914 assertions but
the CSV exporter failed on a list column. Both failed logs are retained; run3
fixes the runner, saves raw RDS, emits scalar CSV and exits0. Native code/runtime
unchanged; this is not a full paired-suite or signed lifecycle proof.

GEE estimated-alpha estimator/privacy/global-sensitivity contract remains the
unanswered scope in cycle17/GEE_ALPHA_SCOPE.md. No new math wall, BLOCKED file,
ULTRA escalation, tags, pushes, thesis edits or simple-family release jobs.

## Resume

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle17-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle18-20260920/paired/harvest.py --allow-partial
```

After paired exit harvest without --allow-partial and review all RDS/CSV
nonpasses. Never relabel older-snapshot or n4 metrics as current n2000 capacity.
LMM admission/public reader/provenance/fixture provisioning and the256-candidate
(257-total-coordinate) sampler repair remain implemented from earlier cycles.
Their completion does not substitute for the pending release proof.
