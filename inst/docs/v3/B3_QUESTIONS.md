# B3 conservative decisions and B4 questions

The maintainer's Phase A, B1 and B2 session reviews were read. No `claude`
CLI is used. This file records decisions for session review under the brief's
file-based fallback; it does not substitute for that review.

* Admit the smoke name only with the complete signed schedule: binomial,
  C=64, p=3 including intercept, one row/person, zero start, T=2,
  refresh (true,true), terminal audit, split epsilon (1,1)/(1,1)/(2,2),
  box [-1,1]^3, floor 8/5, lambda=0, damping/trust both 1. Freeze the
  previously unspecified floor quantum at 1/4096, the curvature lattice.
  Recompute the exact arithmetic certificate for this choice.
* Real source values mean their exact finite IEEE-754 binary64 values.
  Convert deterministically to q16 with rational nearest-even rounding,
  after checking signed real bounds. Missing, malformed or out-of-domain
  persons contribute zero. No finite-failure conversion or public validity
  opening is admitted. The q16 conversion error is at most 2^-17.
* Statistical endpoints take only analysis_id. A transport endpoint may
  additionally accept an opaque authenticated frame; that frame cannot
  select beta, predecessor, budget, bounds, family or noise. No child lane
  has a public retrieval endpoint.
* The cost report shows cold compile and PSI separately and conservatively
  applies the 240-second stage gate including compile. This is stricter than
  the design's cold-compilation exclusion. Source, both noise lanes,
  publication and DSI transport remain in the complete-stage measurement.
* A failed gate stops progression; there is no optimization campaign or
  alternative backend after failure without the maintainer's decision.

B4 must address fixed certified 64-row tiles up to C=1024 with one final
translation/noise, the separately certified tight Poisson eta/y profile,
the full client front door and replay-plus-inverse inference candidate,
the approximately 200-dataset public refusal pre-check and accepted-fit
coverage, and showcase n selected in advance as the smallest public-
simulation size attaining at least 80% acceptance at epsilon=8,p=3.
Privileged whole-store rollback still needs an external monotonic witness.
