# Grouped lane status

## Resumed 2026-09-18

Recovered this lane after quota interruption on `feature/groupedimpl`.
Server base `38146c0`; client base `cb26ecd`. No prior grouped status,
decisions or blocked document existed. Primitive status is in STATUS_P.md.
All recovered implementation files were untracked except the additive client
NAMESPACE export. They are under audit, not a completed milestone.

Recovered: seven q16 linear profiles and coefficient JSON; single-cluster LMM,
GH5 GLMM and GEE emitters; server/client signed contracts; fail-closed release
entry points; partial integer oracles and tests. No production dispatch enabled.

Initial resumed checks:
- Pod install log contains R_STACK_DONE; /workspace/dsvert/grouped exists.
- `go test -run '^TestGrouped' -count=1 -timeout=10m .`: FAILED;
  unequal-width wideMul profile arguments and LMM compilation rejection.
- Focused R contract checks started; results pending.

Outstanding gates: compile/equality for all kernels, integer/certificate and
sensitivity audit, R parity, test-tag reference bridge, two-peer DSLite and
pooled-fit comparison, resource measurements, package checks, integration notes.
No completed production release or full-size performance claim.

### Recovered contract milestone

Focused server contract test file: 120 expectations, no failures.
Focused client contract test file: 151 expectations, no failures (before the
subsequent quarter-step score-clip parity restriction; rerun required).
LMM: all 3 tests pass, including real encrypted two-authority transport;
two-slot circuit 271075 gates / 2487376 table bytes; one-slot garbler direction
2843195 encrypted bytes. Fixed compiler constant-folding/cast hazards and
widened quantization from uint72 to uint88 for admitted cluster magnitudes.
GLMM compiled binomial/Poisson equality: both pass. GEE valid cases pass;
invalid-row reference returned a partial sum, now corrected to all-zero output.
Profile equality and exhaustive q16-lattice error checks pass, but measured AND
cost exceeds the mandatory target; this remains a failed promotion gate.
