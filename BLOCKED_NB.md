# NB production cost gate blocked — 2026-09-18

The family implementation is retargeted to the binding certified piecewise
profile and its arithmetic verification passes. Production promotion is blocked
by the measured cost target, independently of the parallel release wiring.

`TestCrossGridNBV1SoftplusCircuitCostAndEquality` compiles the exact q16, K=64
quadratic profile using the existing Boolean engine:

- 5,720 AND gates and 17,989 total gates per softplus evaluation.
- 183,056 garbled bytes per evaluation under the engine's actual format.
- 91.528 GB at 10,000 rows times 50 candidates, excluding source transport,
  linear assembly, noise, and any other protocol traffic.
- Binding target: at most 2,000 AND gates (or a measured arithmetic-share
  equivalent) and approximately 30 GB for this envelope.

Narrow unsigned operands reduced the initial 9,135 AND gates without changing
profile semantics. A tested bitwise table tree was larger and was discarded.
The final profile remains above target. Buying a larger machine does not change
these circuit counts. The complete row Boolean adapter is also an exact
integration reference, not a scalable production implementation.

The next primitive/Step 2 implementation must supply either a lower-cost exact
evaluator of this pinned profile or a newly signed and certified profile/engine
meeting the cost and utility bounds. Reusing arithmetic-share machinery requires
an exact rounding/security proof and measured cost; the retired spline runtime
is not an authorized fallback. Preserve all source/result evidence and joint DP
gates while doing so. The R and Go family registration functions and integration
instructions are ready; no production endpoint has been enabled.

This is not a request to relax epsilon, delta, the caps, private alignment,
accuracy certification, or the cost target. See `STATUS_NB.md` for verification
and final commits and `INTEGRATION_NB.md` for the separate release wiring.
