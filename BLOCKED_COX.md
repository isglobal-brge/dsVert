# Cox production promotion blocked — 2026-09-18

The family implementation is committed and its targeted tests pass. It is NOT
a completed source-to-joint-DP release and has NO supported production capacity.

1. **Whole-envelope resource gate fails.** Both scalar profiles meet the 2000
   non-XOR gate target, and all chunks fit the unchanged runner limits. However,
   the measured-component model for N=10000,J=50 gives about 722.3 GB of tables
   plus 373.0 GB of gate framing, before other traffic. This misses the binding
   approximately 30 GB envelope. `inst/cross-cox-v1/costs_pod.json` records the
   inputs, measurements, source hashes and modelling limits. No full-size secure
   run was attempted. The current permutation tiles reconstruct/remask full
   Ring64 triples, and the bounded reference scan kernels still perform exact
   prefix/loss additions in GC. Scalable integration must move these linear
   operations onto shares and use a substantially cheaper authenticated
   permutation/state composition. The present compiler/profile optimization
   alone does not meet that requirement. Do not raise runner caps or silently
   shrink a signed workload to advertise success.
2. **Authenticated fusion is unavailable in this family branch.** The separate
   integration must supply signed source materialization, private PSI gating,
   chunk receipts/state recovery, one-time authenticated result injection,
   joint DP noise and sticky cross-signed publication. Neither registration nor
   a synthetic DSLite reference test provides this evidence. The server producer
   and client release intentionally fail closed. See INTEGRATION_COX.md for the
   exact interfaces and remaining wiring/deployment gates.
3. **Public client admission is pending.** `dp_cox_grid` exists as the internal
   entry returned by the single client registration function. Its premature
   export was removed after the full check caught the public inventory mismatch.
   Public export requires coordinated inventory/maturity registration and
   corresponding surface tests; no existing registry/test was weakened.
4. **Whole-package verification is incomplete.** The targeted Cox Go suite
   passed 16 top-level tests + 7 subtests; R server 626 expectations, client
   contract/parity 39, synthetic DSLite 23, and the existing inventory suite
   passed. Both R CMD checks reached their test phases but did not finish.
   The broader Go run completed 18 top-level tests + 25 subtests without an
   observed failure before interruption in an unchanged formal-Cox test. Once
   these production blockers were established, only Cox-owned long-running
   validation jobs were stopped, as requested for a blocked handoff. They are
   NOT claimed as clean full-suite passes. Partial check logs and hashes are
   retained under inst/cross-cox-v1/ and /workspace/dsvert/cox/interrupted-checks/.

The static checks also expose pre-existing warnings (not merely NOTEs): server
undocumented exports and codoc mismatches, plus a normalize/global-reference
NOTE; client non-ASCII MI code, two codoc mismatches and duplicate ordinal
argument documentation. All implicated pre-existing files are unchanged from
server 38146c0 / client cb26ecd. The initial client inventory error was ours and
was fixed with a passing focused regression. Full checks must be repeated after
integration; no clean baseline or final full check is claimed.

No pushes, thesis edits, epsilon/delta reductions, cap relaxation, changes to
same-owner/sealed routes, or modified pre-existing files remain in the final
branch diffs. Work stops here pending resource/fusion integration.
