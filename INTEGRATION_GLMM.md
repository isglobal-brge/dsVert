# GLMM integration

See [INTEGRATION_GROUPED.md](INTEGRATION_GROUPED.md) for the exact wiring and
[NUMERIC_CERTIFICATE_GROUPED.md](NUMERIC_CERTIFICATE_GROUPED.md) for open gates.
The typed GLMM registration is internal; production release remains disabled.

## Clause 5 update

Once-per-release packed routing; local fixed-block sums; compact scalar
chunks are implemented as components. Per-row/node scalar batches followed by share sums, secure outcome/mask products, stable private node maximum and Q=5 log-sum-exp, exact rescaling and signed cluster caps.

No signed capacity is admitted yet: the complete two-party arithmetic and
authenticated fusion traffic must be measured before the 60 GB / 2 h gate
can be applied. See CLAUSE5_ARITHMETIC_GROUPED.md and
BENCH_GROUPED_CLAUSE5.md. The old composed-GC traffic finding is withdrawn.
