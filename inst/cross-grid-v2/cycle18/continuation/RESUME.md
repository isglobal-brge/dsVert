# Cycle18 continuation — authenticated source role check and release harvest

Code `fe4c953/4c6c562`; native runtimes unchanged `b59d34c`. LMM Promoted=No.
No completed n2000 proof or capacity result was available in this continuation.

At 06:28 UTC, the existing cycle16 LMM r2 controller still reported n2000/K2
release_start. All 2553 frozen source hashes match; controller start, cwd and
stdin /dev/null match. The signed n4 marker is not an n2000 marker. No frozen
source, runtime, driver or release log was changed or relaunched. K3/K5,
recovery and full paired remain automatic subsequent stages under the existing
24h total / 15min inactivity lease configuration and 256GB/6h capacity ceiling.

At 06:31:28 UTC, both authorities had 196 COMMIT records and
lmm.products.000003 RUNNING. This read-only observation is unauthenticated
stage progress only, not oracle equality, release timing or traffic evidence.

Cycle17 GLMM binomial remains behind the shared lock; Poisson follows only
its successful sequence. All 2556 source hashes and controller identity match.
Original local collectors 49135 (LMM), 69790 (GLMM), and 78671 (cycle18 paired)
remain active with matching process start/command identities. No duplicate
collector or release was created.

Current cap-source paired: cycle18 e4df243/4c6c562, all 2563 hashes match at
06:28 UTC; full server suite active, no complete paired result. This excludes
the subsequent Cox patches. Historical cycle12 ba436a1/496c053: all 2526 hashes
match at 06:32 UTC, server PASS 1170 tests/21264 assertions with no nonpasses;
client still active. Neither result is relabelled as the current code pair.

## Cox change and verification

The authenticated loader now requires the signed time owner to hold the
identity selected as garbler by the actual pinned pair. Native private risk-set
routing requires that role; matching names and live keys alone did not ensure
it. Fixtures provision that identity assignment BEFORE building pins or signing.
The new test verifies both live roles with valid signed contracts: correct
assignment passes, reversed assignment rejects with matching live keys.

Local focused Cox suite: 15 tests / 848 assertions PASS, zero failures,
errors, warnings or skips. Existing real SQLite source-MAC/completeness and
live-key replacement tests still pass. This is not a signed Cox lifecycle or
native full-suite proof. The first test attempt incorrectly expected canonical
validator output to retain input list order; corrected to assert successful
signature validation. That failed log is retained. No production regression
was hidden. Remaining Cox work is owner-local producer/time-sidecar binding,
private complete-case composition, durable native/DP handoff and public reader.

GEE alpha scope remains the explicit unresolved estimator, coefficient privacy,
and global-sensitivity contract in
`integrator-evidence/cycle17-20260920/GEE_ALPHA_SCOPE.md`. No fixed-rho proof is
transferred to estimated alpha, no new math wall or BLOCKED file is asserted.

## Resume

Keep the existing sequential release controllers; do not duplicate or alter
frozen snapshots. Harvest with:

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle17-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle18-20260920/paired/harvest.py --allow-partial
```

After the paired driver exits, harvest without --allow-partial and review all
RDS/CSV nonpasses. Require complete actual n2000 K2/K3/K5, bilateral/unilateral
recovery, cold/sticky/source+stage tamper, full paired and measured capacity
before setting LMM Promoted=Yes. Expanded 256-candidate admission remains
component coverage, not full-grid capacity. No tags, pushes, simple-family
releases, thesis edits, or escalation.
