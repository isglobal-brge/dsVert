# LMM integration

See [INTEGRATION_GROUPED.md](INTEGRATION_GROUPED.md) for the exact wiring and
[NUMERIC_CERTIFICATE_GROUPED.md](NUMERIC_CERTIFICATE_GROUPED.md) for open gates.
The typed LMM registration is internal; production release remains disabled.

## Clause 5 update

Once-per-release packed routing; local fixed-block sums; compact scalar
chunks are implemented as components. Secure residual squares and squared segment sums, exact q64 rescaling, private live-count coefficient selection and multiplication, signed final clamp/quantization.

No signed capacity is admitted yet: the complete two-party arithmetic and
authenticated fusion traffic must be measured before the 60 GB / 2 h gate
can be applied. See CLAUSE5_ARITHMETIC_GROUPED.md and
BENCH_GROUPED_CLAUSE5.md. The old composed-GC traffic finding is withdrawn.
