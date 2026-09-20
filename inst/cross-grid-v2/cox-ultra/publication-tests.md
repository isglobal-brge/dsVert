# Cox publication boundary checks

Executed against the shared worktrees on 2026-09-20 with `Rscript --vanilla`
and stdin redirected from `/dev/null`. Both packages were loaded with
`pkgload::load_all`; client helpers were sourced into a namespace-backed test
environment before `testthat::test_file`.

| Suite | Expectations | Passed | Failed | Errors | Warnings | Skips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| test-dp-cox-cross-public-evidence.R | 249 | 249 | 0 | 0 | 0 | 0 |
| test-dp-cox-staged-orchestration.R | 249 | 249 | 0 | 0 | 0 | 0 |
| test-dp-lmm-cross-public-release.R | 177 | 177 | 0 | 0 | 0 | 0 |

The Cox evidence suite checks K2/K3/K5 signed publication evidence, cold
compilation-only reconstruction, forbidden source/sampler re-entry, offline
certificate verification and tamper rejection. The staged suite now invokes
the real private alignment projection in its transport seam, covering the
missing `enabled` flag that previously stopped fresh execution before native
recovery. The LMM suite verifies the adjacent staged cold publication behavior.

`git diff --check` passed for the publication runner, result context,
dedicated Cox release helper and staged regression file. These unit checks do
not substitute for the separate fresh signed native/joint-DP proof.
