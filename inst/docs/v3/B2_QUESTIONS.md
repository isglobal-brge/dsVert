# B2 conservative choices and B3 review questions

The maintainer session's Phase A and B1 acceptance reviews were read. No
`claude` CLI is used. These choices let B2 proceed without a blocking decision;
the final measurements and evidence are recorded in `B2_REPORT.md`.

* Admit only p=3, two authorities, 1..64 signed padded person slots, and one
  row per person. The single fused circuit has no row or coordinate tiles.
  p=5/10, repeated rows, and n=200/1000 require further shape/cost admission.
  Larger-n timing figures in B2 are extrapolations, not admitted executions.
* Use q16 signed X, beta, and offset, with coordinate bounds [-1,1], eta
  [-4,4], and q12 score/upper-curvature outputs. Beta must be exactly on the
  authenticated B1 lattice. Explicit no-offset and intercept rules are bound
  in the plan and enforced by the circuit. Poisson counts are bounded at 8.
* Reuse the certified grouped q16 sigmoid and range-reduced exp arithmetic,
  not the grouped/formal optimizer lifecycle. This is a bounded estimating
  equation producer. Its curvature is a preconditioner; inference remains
  unavailable until B3/B4 qualification settles the derivative/target error.
* Use A_j=C*c_int,j exactly, with no extra translation margin. Endpoint
  saturation is retained for the later public-update/refusal rules.
* B2 ends at the private durable aggregate-share COMMIT. It has no public
  aggregate opening or noise-off option. B3 must attach the mandatory split
  noise lanes and atomic publication. It must never expose the shared
  validity bit or an exact clamp count. A conversion with a finite failure
  probability needs its own admitted privacy allowance before publication.
* The signed slot ordering is the person identity ABI. B3 must authenticate
  its materialization and complete provenance. Global alignment/validity
  handling must preserve the certified personwise sensitivity: silently
  replacing the entire aggregate because one row is malformed is not covered.

The B3 <=240-second gate still includes materialization, both noise lanes,
transport, and publication through R/DSI. A fast raw GC run cannot waive it.
The named smoke profile needs complete signed schedule admission in B3 before
delegating to B2's numeric profile; merely accepting the smoke name as an alias
would not check its fixed T, budgets, audit, floor, and update settings.
The accepted showcase selection and public refusal pre-check remain pending
for B5, as specified in `B1_QUESTIONS.md`.
