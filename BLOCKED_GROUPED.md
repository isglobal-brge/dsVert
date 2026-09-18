# Grouped release gate blocked — 2026-09-18

This is an arithmetic/resource finding, not the earlier tool-quota outage.
The recovered restricted kernels and tests are preserved. Production remains
fail-closed; no protected producer/release has been enabled.

1. The binding Day-1 route requires the feasible certified scalar profile.
   Measured grouped emitters after safe optimization use 4027–5488 ANDs per
   evaluation, exceeding the <=2000 target. Exp alone projects to 87.8 GB of
   garbled tables at 10000 rows x 50 candidates, before quadrature, routing,
   OT, source traffic or joint noise. This cannot pass the <=30 GB target.
2. The designated shared Step-2 source was rechecked at commit c10bc0d.
   Its STATUS_V2/BENCH_V2 explicitly report the same failed promotion gate
   (2773–4019 ANDs/evaluation); its production release is also disabled.
   There is no approved replacement emitter to integrate now.
3. The restricted prototype is not the required full-size implementation.
   GEE's recovered R error=1 is unproved; outward coefficient generation and
   whole-workload numeric/noise utility certification are unfinished. Go/R
   cap mapping and authenticated chunk/source/noise/replay wiring are also
   unfinished. The synthetic DSLite test is not that release path.

Unblocking requires a certified, budget-compliant arithmetic implementation
(or a new explicit reviewer decision changing the gate), followed by the exact
remaining items in INTEGRATION_GROUPED.md. No epsilon/delta/cap or runner limit
has been relaxed. Successful small tests do not authorize promotion.
