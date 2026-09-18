# Cox cross-owner grid status

## 2026-09-18 resumed
The quota interruption left no Cox status/decision files. Inspected both repositories before changes; base server 38146c0 (approved primitive), client cb26ecd. Preserved the untracked Cox files and one additive client NAMESPACE export. No half-written files were discarded.

Recovered: pinned interval-generated exp/log profile; public caps; chunk planner/emitter; server/client signed contract validators; test-tagged Go plaintext command; client API/docs and four tests. Production registration/release deliberately disabled pending authenticated fusion.

Verified on resume: `go test -run '^TestCoxGridCrossProfile' -count=1 -timeout=5m .` passed (4 selected top-level tests; 0.770 s). `devtools::test("dsVertClient", filter="dp-cox-grid-cross", reporter="summary")` passed (4 tests, 36 expectations). Dense exp/log tests are separate names and not included in that initial filter.

Pod readiness checked: /workspace/logs/install_r.log ends R_STACK_DONE. Work uses /workspace/dsvert/cox/.

Remaining: compiled chunk equality/costs, pure R integer oracle, sensitivity neighbours, server contract parity, two-peer synthetic DSLite/coxph comparison, package checks, integration gate report.
