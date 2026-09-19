# NB family decisions

## Inherited family work (before the Day 1 addendum)

The resumed worktree contained uncommitted NB contracts, mirrored server/client
validators, a pure-R limb oracle, Go circuit source/reference tests, and a q64
Chebyshev certificate. The branch tips were server `4d7e6ae` and client `cb26ecd`.
No earlier NB decision/status file was present. These decisions preserve that
work's signed theta domain, candidate order, f50/f100 input ABI, private validity,
per-row clamping, whole-vector sensitivity, client postprocessing and closed
production gate. The unrelated same-owner NB correction is outside this lane.

1. Theta is paired with each public beta candidate, signed by all custodians,
   and restricted to exact powers of two `2^(-3:7)`. Candidate identity includes
   theta; no silent Cartesian expansion or reordering is permitted.
2. Use the complete NB2 negative log PMF. The stable representation is
   `C(theta,y)+(y+theta)*softplus(eta-log(theta))-y*eta`, where
   `C=lgamma(theta)+lgamma(y+1)-lgamma(y+theta)+y*log(theta)`.
   At theta=2,y=1,eta=0 this is 1.21639532432449.
3. Pure references remain tests. The sole R and Go registration functions
   describe integration; they do not authorize a release or register a general
   plaintext nonlinear command. The client validates both signatures, then
   fails closed until an authenticated release adapter is installed.

## Day 1 arithmetic decision applied (2026-09-18)

4. `../DECISION_DAY1_ARITHMETIC_ROUTE.md` supersedes the provisional high-degree
   nonlinear evaluator. Keep the source ABI and q64 eta boundary; securely round
   the shifted argument to q16 and evaluate the certified public softplus
   profile, w=32, K=64, degree=2, two Horner multiplications. This is exact
   evaluation of the certified finite profile, not an exact transcendental.
5. Use softplus symmetry: `max(z,0)+log1p(exp(-abs(z)))`. Quadratic pieces of
   width 1/4 cover the residual on [0,16); the residual is zero beyond 16 with
   its analytic tail included in the error. The domain covers [-22,22], including
   the frozen eta encoding slack and every supported log(theta). The same
   profile can be registered for binomial and the NB shifted argument; NB adds
   no distinct transcendental kernel.
6. The certified softplus error is at most 0.00003936. Candidate row error is
   `(M+theta)*0.00003936 + 1024*1.4655e-14 + 2^-63` before output quantization.
   The old quarter-output-ulp acceptance criterion is withdrawn by the addendum.
   Utility is a DP-selected finite candidate under loss approximation error
   `N*(E_j+1/(2S))`; it is not a claim to select the exact best candidate.
7. Cap construction uses the certified profile on public endpoints and the
   public q64 constants, rounded upward exactly to q16 by decimal long division.
   It never depends on protected observations or an uncertified lgamma cap.
   Convexity places the exact loss maximum at +/- A for each integer y. Public
   endpoint error is `(M+theta)*(0.00003936+2^-16)+2^-20`; the q16 term covers
   public endpoint argument rounding, and the final guard encloses binary64
   public arithmetic. Adding twice the certified row error bounds the maximum
   approximate loss plus another full error margin. Clamp each private row to
   [0,U_j], with `U_j=ceil(S*loss_bound)`. Keep `Delta1=a*sum(U_j)` and the
   outward guarded `Delta2=a*sqrt(sum(U_j^2))`; a remains 1 or 2.
8. Public-profile arithmetic in R is only for public cap metadata. All products
   in its q16 Horner evaluator are exact integers below 2^53. The private-input
   reference uses base-2^15 integer limbs and resides exclusively in test helpers.
9. Cost and arithmetic correctness are separate promotion gates. The generated
   Boolean profile is measured by compiled AND gates. The fused implementation
   must perform outcome-dependent constant/linear work with authenticated secret
   shares, without exposing y or privately selected constants. The existing
   full-row Boolean loss assembly is an exact integration reference, not an
   unmeasured scalable producer. Cost failures must be recorded, not hidden by
   state strings or a plaintext fallback.
10. LASSO remains public candidate postprocessing, handled in
    `DECISIONS_LASSO.md`. The test harness labels frozen Step 1 binomial/Poisson
    references explicitly until the parallel Step 2 profile adapter is available.

11. Compiled profile equality passes, but final Boolean cost is 5,720 AND gates
    (91.528 GB at 500,000 evaluations), above the binding target. Retain the
    certified profile and all correct contracts/oracles, keep production closed,
    and record the precise primitive dependency in `BLOCKED_NB.md`.
12. The engine miscompiles a direct wide signed negative-constant comparison.
    NB emitted source uses an equivalent absolute-value range guard, explicitly
    rejects the signed minimum, and encodes negative public q64 constants as
    their 192-bit two's-complement bit patterns. Compiled two-share tests cover
    all three extreme/central theta specializations and invalid domains. No
    shared compiler or generation-one files were changed.
13. Postprocessing requires integer release coordinates. Canonical layout tests
    compare the frozen canonical JSON contract, preserving array order while
    allowing named-object key normalization. Numeric-profile tampering tests
    must change a value: the NB constant at y=1 is identically zero, so its
    negative control now changes zero to one.

14. The DSLite synthetic harness rebinds/deparses registered method environments.
    Its public signed metadata is therefore embedded as exact R serialization,
    and each peer receives only its own synthetic local values. JSON formatting
    of f50 numeric values was also observed to round 2^50 by four integer units.
    The tagged test transport now uses canonical decimal integer strings with
    exact parsing and unchanged range checks. These are test-harness transport
    fixes; the frozen production Ring128 ABI is unchanged.

## Resumed — 2026-09-18

The quota outage did not invalidate the committed family implementation or
focused results. Preserve the coherent documentation left in the worktree,
finish package-check evidence, and retain fail-closed integration/cost gates.
Do not replace the pinned arithmetic profile or reopen completed milestones
merely to repeat validation.

### Resumed public-surface correction — 2026-09-18

Full client package testing identified an introduced inventory regression: the
two new exports were absent from the shared public maturity inventory, whose
contract requires all analysis entries to be promoted. Removed only our two
NAMESPACE additions; keep the implemented entry functions namespace-internal
and available through family registration until integration can register real
production evidence and public status together. This supersedes earlier claims
that the staging functions are exported. No maturity test or shared registry
was weakened; adding exports is now an explicit integration gate.
