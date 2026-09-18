# Addendum 4 measurement prerequisite — 2026-09-18

The requested measurement/capacity task is **incomplete**. This is not a renewed
traffic or scalar gate failure. The former traffic blocker remains withdrawn;
the exact OT backend and accepted LMM/GH5/GEE moment components remain intact.

The specific GEE prerequisite is still missing: the registration supplies
MomentOperands/MomentSums/MomentBoundary/MeatOperands/MeatFinal but no private
whitened-factor producer. Existing tests supply those factors. The propagated
GEE error certificate and matching integer profile are also incomplete. Thus
there is no complete GEE kernel whose release cost can be measured. This is
owned grouped implementation work, not the external Step-2 fusion dependency.
Implementing it is outside Addendum 4's “do only this” measurement scope.

LMM and GH5 components exist; their complete source/routing/validity-to-output
benchmark schedules still need assembly. That work is not intrinsically blocked
by missing Step-2 lifecycle, and has NOT been completed in this resume. No
component-only result is relabelled as a release measurement.

Public preflight of all 27 requested cells (n=2000/4000/10000,
grid=16/32/50, 10 slots per cluster, GLMM Q=5) rejects under current signed
prototype limits. See inst/grouped-validation/addendum4-preflight.json. Its
bytes/time are null, not zero. No run exceeded four hours; no extrapolation
exception was used. No capacity has been measured or newly admitted under the
110 GB / 4 h gate. Source materializers and client readers stay fail closed.

To unblock the complete requested matrix: complete and certify the GEE factor
producer, assemble actual family benchmark schedules including one permutation,
then measure before setting mirrored signed capacities. Authenticated
fusion/lifecycle remains Step 2's separate responsibility and is not implemented.
