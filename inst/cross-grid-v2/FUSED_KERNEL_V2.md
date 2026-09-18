# Fused integer producer — internal, not admitted for release

`k2_exact_gc_glm_grid.go` implements a bounded source/loss batch for both
families. It is not a server-minted signed producer, durable worker, RPC,
materializer, or authorized release route. No R/client allowlist changed.

## Arithmetic and private inputs

Inputs are Ring128 additive shares of row-major `(value, validity)` pairs,
ordered predictors then outcome, followed by two XOR-shared alignment limbs
per participating source. The production source adapter still needs to map the
frozen V1 column-major source layout to these internal row batches. All source
owners' nonzero alignment digests must agree inside the circuit.

The local producer computes f100 partial predictors using public f50 integer
coefficients and its own feature shares, modulo 2^128. Only the garbler adds the
public intercept times 2^50. It never reconstructs or rounds an owner partial
predictor. Callers cannot supply extra eta slots to the typed input packer.

The circuit reconstructs and range-checks every original source value and
validity. It masks invalid, missing, padded or misaligned rows before nonlinear
work. The complete dot product is rounded once to eta16 (binomial) or eta26
(Poisson), then projected to the signed public envelope. Existing certified
K64 softplus and range-reduced exp tables are unchanged. Poisson privately
selects its f16 log-factorial once per row and assembles the loss at f26;
binomial assembles at f16. Lower clamping, ties-even output quantization and
upper clamping give exactly the same integer as clamping before quantization,
because the upper cap is integral on the output lattice.

Signed rounding uses `q = floor(v / 2^s)` and its nonnegative low-bit remainder.
Increment q iff the remainder exceeds half, or equals half and q is odd. This
works for negative ties too, without a wide absolute-value circuit. Explicit
signed32 eta avoids a compiler comparison issue between signed64 variables
and narrower negative literals. Synthetic regression tests cover this issue.

## Width and error obligations

For valid sources, `0 <= x <= 2^50`, each encoded coefficient has magnitude
at most 8*2^50 and their absolute sum is at most A*2^50 plus the frozen encoding
slack. Hence the complete f100 dot has magnitude <2^105 and fits signed128.
Private validity substitutes zero before rounding for inputs outside that
proof. Projection handles encoded boundary slack and is nonexpansive relative
to the real eta domain. The previously certified source-encoding/eta-rounding
budgets therefore apply unchanged.

After projection, binomial eta/loss at f16 fit signed32 (a conservative natural
loss bound is 64). Poisson eta26 fits signed32; exp16 plus outcome*eta26 and
log-factorial terms fit signed64 (a conservative natural loss bound is 2^24,
hence a loss integer below 2^50). g=8..18 quantization fits uint64. Public plan
validation requires rows*cap <= 2^53-1, so candidate sums also fit uint64.
Final shares and independent random masks occupy the full Ring128. The final
alignment validity bit is XOR-shared and is never opened by this primitive.

The embedded table bundle is reproduced by `generate_kernel_profiles.py`;
its SHA256 is pinned in code. Existing analytic profile/error certificates
remain authoritative. No new transcendental approximation was introduced.
Public kernel caps are clamp parameters: this low-level primitive does **not**
certify that an arbitrary supplied cap is the signed sensitivity cap. That
requires the absent new-profile signed admission layer. Small/artificial caps
are used in arithmetic tests only. The benchmark instead uses the certified
A=4 envelope caps, distinct candidates with exact coefficient L1=4, and M=4
for Poisson.

## Protocol boundary

Preparation compiles only public metadata, verifies dimensions and actual
input size, and owns a copy of the public plan. The purpose commits its entire
public plan; compact framing additionally commits every circuit wire/gate.
The special operation is rejected by the ordinary exact-GC compiler. Its
internal runner returns only independently masked candidate sums and the
masked alignment-validity bit. All runner failures use one fixed error.

A future authenticated worker must additionally bind source claims/snapshots,
recipient commitments, signed grid/profile, row/candidate position, and fresh
session/attempt identity, and must persist authenticated output evidence.
It must gate release on alignment success and prevent exactly-once/sticky
lifecycle replay. The primitive alone does not implement those requirements.
Encrypted-record replay tests are not durable-lifecycle tests.

## Evidence and reproduction

From dsVert:

```
python3 inst/cross-grid-v2/generate_kernel_profiles.py --check
python3 inst/cross-grid-v2/generate_fused_vectors.py --check
Rscript inst/cross-grid-v2/validate_fused_vectors.R
cd inst/dsvert-mpc
go test -run '^TestCrossGridKernel(Integer|Round|Predictor|SharedVectors|RejectsPublicPlanAndShares|TwoAuthority|JointNoise|PurposeAndAdmissionGate|BoundarySlack)$' -v -count=1
go test -run '^$' -bench '^BenchmarkCrossGridFusedBatch$' -benchtime=1x -count=1 -timeout=0
```

The shared synthetic fixture has 288 full f100-to-loss vectors across both
families, A=4/16, g=8/16/18, missing/malformed sources and alignment mismatch.
Python integer fixtures, Go big.Int, independent R signed limbs, and circuit
results agree. Additional randomized tests cover 80 source instances.
Two encrypted net.Pipe peers agree with the integer oracle for both families,
including alignment failure. Separate tests feed those shares directly to the
existing joint-DP vector **Laplace** sampler at epsilon=4, delta=2^-100 and
match its deterministic oracle after the sampler's documented output clamp.
These are real cryptographic kernel/sampler tests, not DSLite releases or
proof of the production policy's eventual mechanism selection.

The final rounding regression explicitly tests positive/negative half ties and
both adjacent integer points at each internal eta precision. Full-kernel stress
cases also cover eta=+/-16, one-past-source range, encoded aggregate slack
projected at A4, and both outcome endpoints. These tests use synthetic inputs.
On this Mac, profile reproduction used Python 3.11 at
`/opt/homebrew/opt/python@3.11/bin/python3.11` with mpmath 1.3.0; another selected
`python3` environment lacked mpmath. This is an interpreter selection detail,
not an arithmetic finding or an unhandled tooling blocker.
