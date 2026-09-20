# Cox next release boundary after cycle43

Current client R/dp_cox_grid_cross_release.R now contains:
- `.dsvert_dp_cox_cross_source_blocks`: exact server-compatible padded source
  lanes, without time values or permutation controls.
- `.dsvert_dp_cox_cross_bind`: time-owner-first endpoint call, signed public
  route verification before evaluator forwarding, and bilateral bound receipts.
  Takes already authenticated manifest/context/artifact/source receipt. Transport
  test double used in proof; actual signatures and server semantic key are used.

These are internal integration steps, not an enabled public release path.
Reuse them when wiring the existing staged orchestrator; do not duplicate them.

Remaining coordinated changes before FIRST signed smoke/fleet run:
1. Workload artifact admission in server dpCapsuleWorkload.R and corresponding
   client reconstruction: validate the actual signed schema and Cox contract,
   use the existing exact sensitivity accounting and N<=400 guard. Current Cox
   contract/artifact still describes `contract_only` / `pending` states; align
   these with admitted runtime state only when the complete path is enabled.
2. Client discovery/layout/source transport and certificate reconstruction must
   dispatch Cox's exact projection, not the outcome/grouped fallback.
3. Staged orchestration must call the new owner-first helper for bind, then the
   existing prepare/start/store/finalize sequence. Cox's native operation is
   `cox-loss-staged-v1`, not `grouped-cox-staged-v1`; adapt prepared-receipt
   operation validation explicitly. Keep the existing Ring64->128 bridge.
4. Publication/evidence and exported reader must consume the already implemented
   authenticated Cox cold reader, including source namespace and typed validity.
5. Signed small smoke: complete Claims/sharing/persistence -> native -> joint DP,
   oracle equality, bilateral/unilateral recovery, cold, swapped-source/stage
   tamper. Then actual Cox release manifest rows (four) and fleet first run. Match
   the admitted <=400 observation scope in the Cox harness/manifest; the
   generic n2000 placeholder is not an admitted Cox release definition.

No new arithmetic blocker. N<=400 remains. Do not enable discovery alone: it
would enter generic assumptions and expose a partially wired release path.
Shared capacity policy is 256GB/8h; old signed kernel-only certificate fields
are historical kernel evidence, separate from complete release accounting.
No GEE-owned code changes. Batching is deferred on its preserved branch.
