# Primitive V: private permutation and coupled reductions

This is an additive internal Go circuit library and three worked circuit
specifications on `feature/oblivious-grouping`. It is not an enabled R method,
signed artifact version, DP release producer, or sticky-release capability.
The frozen V1 contract, numeric profile, Ring128 source layout and client ABI
are unchanged. The only existing engine change admits a new internal session
operation and explicitly rejects it in the generic circuit compiler.

## Inputs and disclosure

The common input is an aligned capacity-padded record vector. Each authority
holds randomized additive shares, initially supplied through the existing
authenticated source transport. Shares are reconstructed **only as GC wires**,
then the same private permutation is applied to all columns. Linearity makes
this identical to permuting both authorities' vectors before adding them.
Neither authority sees a reconstructed word. This reduces switching work.

The order owner privately routes its permutation to Beneš switch controls.
The routing routine runs locally, before the network transcript; it is not
constant time and is not a service callable by the other authority. Only its
private bits enter GC. The worked wrappers assign that owner the garbler role;
the emitter itself accepts control wires belonging to either party. The owner
also supplies private segment starts in the **permuted** order. Cox starts mean
distinct event-time blocks; LMM/GLMM starts mean cluster changes.

Public: padded capacity, family, candidate caps and variance parameters,
numeric profile/source digest, fixed transcript shape, two authority roles,
and a maximum cluster/tie size. Private: permutation, individual validity,
time values, ties, memberships, observed complete-case count, group sizes and
**number of groups**. Group count need not be public: reductions retain one
slot for every padded position and put secret zeros at non-endpoints. Opening
these vectors would reveal shape; consumers must keep them on circuit wires
or independently freshly masked shares. Padding cannot be dropped according
to observed data. Every padded network position is consumed, so arbitrary
switch settings cannot discard real rows into an unprocessed tail.

The guarantee is inherited two-party semi-honest, non-colluding Yao GC with
checked IKNP/KOS OT, authenticated peers and encrypted records. This is not a
malicious-input consistency proof. In particular, the time/cluster owner must
derive the order and starts faithfully from its authenticated local snapshot.
Private alignment and every input validity must already be ANDed into the
shared live bit before these family wrappers are called. Private order cannot
repair an incorrectly aligned pair of source vectors.

## Permutation

`primitiveVPermutationControls(perm)` uses `out[i]=in[perm[i]]`, rejects
duplicates/out-of-range indices, and fixes padded positions. Recursive
two-coloring of input-pair/output-pair edges gives one edge of each color at
every pair. Each color therefore defines a half-sized permutation; recursion
proves routability. The fixed topology is a Beneš network, with no data-dependent
wiring or source generation. This construction follows the rearrangeability
property of [Beneš networks](https://doi.org/10.1002/j.1538-7305.1964.tb04102.x).

For `N=2^ceil(log2 n)` and `N>=2`, there are
`s=N*log2(N)-N/2` two-by-two switches and private control bits. N=1 has none.
For d columns of w bits, each conditional XOR swap ideally needs `dw` AND and
`3dw` XOR gates: `delta=control ? (a XOR b) : 0; a^=delta; b^=delta`.
The pinned compiler implements its zero-branch mux with two additional XORs,
so the implemented switch bound is `s*d*w` AND and `5*s*d*w` XOR, before
constant propagation and one constant scaffold per compiled circuit.
XORs use no garbled tables; the existing engine uses 32 bytes per AND table.
This bound excludes input reconstruction, output masks, OT and record framing.
The current wire protocol also sends a four-byte row length for **every gate**,
including XOR. Thus switch gate rows consume 56 bytes per carried bit versus
32 bytes of table payload, before labels/OT and encrypted-record overhead.
Permutation adds **zero numerical error**.

## Reductions and numeric certificate

`primitiveVEmitSegmentedReduce` emits global prefixes, segment prefixes,
segment squared prefixes, segment counts, and segment-end sums/squared sums.
Plain sums are exact encoded integer additions. Squares are rounded q64
products; k terms add at most `k*2^-65` error against squared encoded inputs.
The first start must be true. The worked wrappers validate raw start/live bits
and value caps, and retain only masked loss and validity outputs. The producer
must first incorporate private alignment and source validity into the live bit;
the wrappers do not perform alignment themselves.
The low-level segment counts count slots. Family wrappers separately count
live rows, so padding and inactive rows do not inflate the private n_c.

`primitiveVEmitPrefixLogSumExp` computes capped q64 exponentials, exact prefix
exponential sums, and a bounded logarithm. Empty prefixes use zero plus a
secret zero exponent sum; this sentinel must not be interpreted as log(0).
See [the complete rational certificate](inst/dsvert-mpc/primitive_v_numeric_proof.md)
and `TestPrimitiveVNumericAnalyticCertificate` for derivations and executable
outward inequalities. The separate additive profile is
`primitive-v-taylor12-exp64-atanh20-q64-v1`:

| Quantity | Certified bound |
|---|---:|
| Exp on encoded eta in [-17,17] | relative error <7e-13 |
| Log of a positive q64 input below 2^127 | absolute error <3e-17 |
| Nonempty prefix LSE, encoded eta | absolute error <7.001e-13 |
| Prefix LSE including V1 predictor encoding | absolute error <7.2e-13 |
| At most n event differences including eta encoding | <n*(7.2e-13+1.4655e-14) |
| Stable negative exp, with zero below -32 | absolute error <1.4e-14 |

The exp proof uses a degree-12 Taylor core on eta/64, six rounded squares,
and relative rather than absolute error accumulation. If each exp has relative
error at most R, an exact sum of any k positive terms also has relative error
at most R. The logarithm amplifies that by at most `R/(1-R)`. Thus prefix error
does not grow with prefix length; summing n event contributions grows linearly.
The logarithm uses secret power-of-two normalization and 20 atanh terms.
All constants and arithmetic semantics are part of generated source and its
session-bound hash. All raw products fit signed 192 bits under the stated caps.

The V1 feature/coefficient input scale remains f50. Family inputs are q64 eta
or residual wires after the **complete** public-coefficient dot product has
been rounded once from f100. Independently rounded owner predictors are not
compatible. RN denotes symmetric nearest, ties to even throughout.

The Ring128 source-to-internal transition must reconstruct modulo Ring128
inside GC before sign extension and q64 conversion. Sign-extending each
authority's random Ring128 share separately does not implement that transition.
Public-beta products may be accumulated locally in the proven source ring;
the complete dot product is securely rounded once. This producer belongs to
the parallel step-2 integration, rather than to the worked family wrappers.

## Worked families

`primitiveVFamilySpec` selects one candidate. Public `Rows` is 1..10000;
`GroupCap` bounds live members of each private segment. The q64 arrays are
native 192-bit two's-complement words, not R doubles. Each authority supplies
row shares `[eta_or_residual, live, event_or_binary_outcome]`. Garbler inputs
also contain starts, controls and final independent masks for the two outputs.
Raw flags are validated as 0/1 inside GC; invalid rows are replaced by safe
zeros before nonlinear evaluation. A malformed live flag, bound violation,
oversized group or malformed private control causes shared validity zero and
shared loss zero, on the same circuit schedule. No failure bit is opened.

### Cox, Breslow ties

The outcome/time owner supplies descending time order, tie starts, and event
indicators; eta is shared across owners. For tied block t let R_t include
every live row up to the **end** of that block and d_t be its event count.
The output is the requested log partial likelihood
`sum_t [sum_{i:event in t} eta_i - d_t*log(sum_{i in R_t} exp(eta_i))]`.
Thus all events in a tied block use the same full risk set, including censored
members of that block. It returns log likelihood (nonpositive); a minimizing
grid selector must negate it. No left truncation or time-varying covariates
are implied by this worked specification.

The signed integer cap is `|eta|<=Cap<=17`; Cap=17 encloses the V1 |eta|<=16
domain plus encoding slack. A total clamp to `[-B,0]`, with
`B=Rows*(2*Cap+ceil(log2 Rows)+1)`, encloses the real target because every event
term lies in `[-(log Rows+2Cap),0]`. The extra unit safely encloses roundoff.

DP unit: one aligned row, including time, event and all owner covariates.
Coupled risk sets invalidate an independent-row loss-sensitivity sum. The
conservative **range bound** gives scalar sensitivity B for either add/remove
(a live-bit toggle within fixed public capacity) or row replacement: any two
valid results lie in the same interval of width B. With candidate bounds B_j,
`Delta1<=sum_j B_j`, `Delta2<=sqrt(sum_j B_j^2)` in natural units. This is safe
but often too noisy; no independent-patient GLM bound is reused. After output
rounding at S=2^g, use exact integer `U_j=S*B_j` and the same vector formulas.

### Random-intercept LMM

The cluster owner supplies grouping and starts. Owners jointly form residual
`r=y-eta` as q64 shares, bounded by public R=Cap. Public candidate-signed
`rho=RhoQ64/2^64` is in [0,16]. At a segment end, the circuit evaluates
`T - rho/(1+k*rho)*S^2`, where `T=sum r_i^2`, `S=sum r_i`, and k is its private
live count. It first rounds each square and the squared sum, then rounds the
complete correction numerator divided by `2^64+k*RhoQ64`. This avoids rounding
the reciprocal before multiplying by S squared. Rho zero gives ordinary SSE.
This is the requested quadratic form, with no log determinant added.

For exact values, Cauchy-Schwarz gives `S^2<=k*T`, so the quadratic is in
`[T/(1+k*rho),T] subset [0,k*R^2]`. The circuit clamps each computed segment to
this interval. Against encoded residuals the arithmetic error per nonempty
cluster is at most `(k+2)*2^-65`: k rounded squares, squared-sum rounding
amplified by `rho/(1+k*rho)<=1/k`, and final division rounding. Clamping is nonexpansive.
For real residual error e, add `2*k*R*e+k*e^2`; the quadratic matrix has spectral
norm at most one. If rho itself approximates an original real parameter, add
`(k*R)^2*|delta rho|`, since the derivative of rho/(1+k rho) is at most one.

DP unit: one entire cluster, with at most K=GroupCap rows and fixed membership
of every other cluster. Its contribution is in `[0,B_j]` for
`B_j=K*R_j^2`. For add/remove a cluster, `Delta1<=sum B_j` and
`Delta2<=sqrt(sum B_j^2)`. Replacement of one entire cluster has the same bound
because both contributions lie in the same interval `[0,B_j]`. A record that changes membership may touch two clusters; that is a
different adjacency and is not granted the one-cluster add/remove bound.

### Binomial random-intercept GLMM

The outcome/cluster owner supplies binary y, grouping and starts. Shared eta
obeys integer Cap<=14. The worked spec fixes random-intercept variance at one
and Q=5. Standard-normal nodes are
`0, +/-sqrt(5-sqrt(10)), +/-sqrt(5+sqrt(10))`; positive weights sum to one
**exactly on q64**, with the center absorbing the normalization ulp. Nodes
are below three in magnitude, keeping eta+node in [-17,17]. These are the
standard [Gauss-Hermite nodes and weights](https://dlmf.nist.gov/3.5#v).

For each segment c and node q the circuit sums
`h_cq=log(w_q)+sum_i[y_i*(eta_i+node_q)-log(1+exp(eta_i+node_q))]`.
It then returns `-logsumexp_q h_cq` using the private maximum, with a certified
zero tail below -32. A maximum-shifted term is exactly one, so the denominator
is at least one; the Q-term tail/evaluator contribution is at most
`Q*1.4e-14/(1-Q*1.4e-14)+3e-17`. Arithmetic on Q-node sums is certified against
the **fixed quadrature target**, not the exact normal integral. Q=5 quadrature
model error requires a separate scientific adequacy judgment.

For k live rows, certified arithmetic error against the encoded fixed-quadrature
target is below `7.001e-13*k + 7.01e-14` per cluster. Each softplus contributes
at most `-log(1-E_exp)+E_log`; exact summation adds these bounds, and the outer
log-sum-exp is 1-Lipschitz. Add log-weight evaluation and the max-shifted
exponential/log errors above. Original eta and node encoding add at most k
times their absolute encoding errors; normalized weight encoding adds less
than 5e-18. The complete family derivations are in
[the family proof notes](inst/dsvert-mpc/primitive_v_family_notes.md).

DP unit: an entire cluster of at most K rows, keeping other clusters fixed.
Since each binomial row NLL is in `[0,Cap+4]` at every node and the normalized
weights are positive, the integrated cluster NLL is in `[0,k*(Cap+4)]`.
The circuit enforces this exact interval by a private clamp. Set
`B_j=K*(Cap_j+4)` and use the same L1/L2 cluster formulas as LMM. For both
cluster families, final-total quantization at the frozen g in 8..18 preserves
the exact integer sensitivity `U_j=2^g*B_j`: U_j is even, nearest-even rounding
is monotone, and `RN(x+U_j)=RN(x)+U_j`. Thus `|x-y|<=U_j` implies the same bound
after rounding. Per-segment quantization also preserves that cap. Different,
nonintegral caps or output grids require a new rounding-bound derivation.

For all families, caps and quantization must be signed, validated and bound
before protected input access. The existing <=2^53-1 coordinate and workload
constraints still apply at the R release bridge. Masked validity is retained
through that bridge and ANDed across every candidate and source/alignment
check; zero loss alone is never successful materialization. Per-candidate
failure bits must not be opened or used to publish a partially valid grid.

## Integration surface

| Function | Family fan-out responsibility |
|---|---|
| `primitiveVPermutationControls` | Order owner derives private routing locally. |
| `primitiveVPermutationShape` | Public network/gate planning; accepts 10000 rows. |
| `primitiveVEmitPermutation` | Permute all shared row fields on GC wires. |
| `primitiveVEmitSegmentedReduce` | LMM moments; GLMM per-node cluster log likelihoods; correlated GEE moment building block. |
| `primitiveVEmitPrefixLogSumExp` | Cox private risk totals with tie-end consumption. |
| `primitiveVNumericSource` | Additive q64 exp/log/rounded arithmetic helpers. |
| `primitiveVFamilyInputShape`, `primitiveVFamilyCircuitSource` | Complete worked one-candidate masked circuits. |
| `primitiveVFamilyLiteral` | Safe public signed constants; emit `-int192(abs)` for negative wide values. |
| `primitiveVCompile` | Fixed public resource checks; compile generated source with existing MPCL compiler. |
| `primitiveVCompileFamily` | Check typed input limits before generating a worked family source, then compile. |
| `primitiveVRunGarbler`, `primitiveVRunEvaluator` | Existing exact-GC protocol/OT/record layer; fresh independent additive output shares. |

The authenticated signed-contract digest supplied to the runner must cover
ownership, row capacity, candidate caps, profile, adjacency, alignment and
batch plan. The runner additionally binds exact generated source to Purpose;
it does not substitute a digest for verification of signatures by its caller.
Reuse source sharing/private alignment from `dpGaussianCrossDS.R` and the
zero-release-prefix injection boundary in `dpCapsuleSourceTransportDS.R`.
Reuse `k2_exact_gc_core.go` garbler/evaluator protocols and
`k2_exact_gc_transport.go` records. The future family producer must issue
matching authenticated result evidence and feed candidate shares once into
the existing `k2_joint_dp_vector*` / one-draw release and sticky cache path.
Do not register this primitive as a general nonlinear RPC or expose order,
segment output, validity or exact loss through the client.

The primitive alone does not implement a general non-independence GEE loss,
random slopes, multivariate random effects, arbitrary quadrature, or a release
authorization path. Those are family consumers of the shared ordered moments.

## Measured costs and feasibility

Measurements and reproducible commands are recorded in `STATUS_P.md` and
[`costs_mac.json`](inst/primitive-v/costs_mac.json) and
[`costs_pod.json`](inst/primitive-v/costs_pod.json). Full n=10000, p=10, grid=50 figures distinguish
analytical work from measured materialized circuits. A monolithic full-size
circuit is not admitted: the internal runner caps source at 2 MiB, each input
at 512 Ki bits, and compiled gates at 32 million. These public limits fail
before private inputs are consumed. A production full-size fan-out requires
a signed schedule of network-stage chunks and shared reduction state; merely
raising a cap is not a resource plan. The worked library is useful for exact
specification, tests and bounded batches; it does not claim the full-scale
coupled workload is already economical or deployable.

Measured on this Mac (Apple M2, 16 GiB, Go 1.25.7), using public synthetic inputs,
actual checked OT and encrypted `net.Pipe` transport:

| Microcircuit | Gates | Table payload bytes | Garbler wire bytes | Compile s | Protocol s |
|---|---:|---:|---:|---:|---:|
| q64 square | 54,773 | 502,032 | 743,405 | 0.314 | 0.505 |
| exp | 643,178 | 5,979,728 | 8,579,004 | 5.112 | 1.469 |
| stable negative exp | 704,461 | 6,543,184 | 9,388,024 | 0.717 | 0.212 |
| log | 1,114,215 | 10,044,528 | 14,531,229 | 4.868 | 0.459 |
| private positive-divisor RN | 609,966 | 4,884,304 | 7,359,263 | 0.431 | 0.570 |
| illustrative 10-feature GC dot | 1,935,094 | 16,949,168 | 24,807,945 | 6.316 | 7.573 |

Garbler wire bytes include gate-row framing, labels, OT messages in that
direction and encrypted records; they do not include evaluator-to-garbler
traffic. These measurements include local two-party execution, not remote RTT.
Times vary with concurrent machine work and allocation/GC history; deterministic
gate/table counts are the sound basis for scaling. `heap_sys_bytes` in the JSON
is cumulative Go heap reservation, not process peak RSS or a per-circuit maximum.

The pod was measured only after `R_STACK_DONE` appeared in
`/workspace/logs/install_r.log`, using `./pod4` and a hash-verified snapshot under
`/workspace/dsvert/primitive`. Its CPU was an Intel Xeon Gold 6342 at 2.80 GHz
(96 logical CPUs), with 540,644,081,664 bytes RAM and Go 1.25.7 linux/amd64.
No GPU was used. The same seven synthetic microcircuits passed on both hosts;
the deterministic gate/table counts matched exactly.

| Microcircuit | Pod compile s | Pod protocol s | Pod garbler wire bytes |
|---|---:|---:|---:|
| q64 add | 0.010 | 0.065 | 51,740 |
| q64 square | 0.040 | 0.094 | 743,403 |
| exp | 0.354 | 0.376 | 8,579,004 |
| stable negative exp | 0.362 | 0.389 | 9,388,023 |
| log | 0.616 | 0.513 | 14,531,229 |
| private positive-divisor RN | 0.260 | 0.311 | 7,359,265 |
| illustrative 10-feature GC dot | 1.247 | 0.919 | 24,807,945 |

Owner-local routing of 10,000 positions took 8.957 ms on the Mac and 10.035 ms
on the pod. Compilation of a 32-row, three-column, 192-bit network took 7.864 s
and 0.903 s respectively. These are routing/compilation measurements, not a
10,000-row encrypted execution. Small complete family circuits were also
compiled and checked against their independent integer references:

| Family fixture | Rows | Gates | Table payload bytes | Mac compile s | Pod compile s |
|---|---:|---:|---:|---:|---:|
| Cox Breslow | 2 | 3,831,103 | 34,993,552 | 100.964 | 2.223 |
| LMM | 3 (padded to 4) | 5,082,865 | 43,747,088 | 119.456 | 2.759 |
| GH5 binomial GLMM | 2 | 28,020,152 | 256,548,304 | incomplete | 20.433 |

The redundant Mac GH5 compile was interrupted under heavy contention after
the identical circuit passed on the pod. Complete-family times above measure
compilation; the microcircuit protocol column measures encrypted execution.
An additional two-row LMM private-swap fixture passed through the actual
two-party encrypted protocol. All three family equality tests passed on the
pod, including private-boundary, inactive-row and malformed-input cases.

For n=10000 the worked wrappers process N=16384 positions for each of m=50
candidates. Their component-call model is:

| Family | Calls over the grid | Component gate model | Component table payload |
|---|---|---:|---:|
| Cox | 819,200 exp + 819,200 log | 1.440e12 | 13.127 TB |
| LMM | 1,638,400 squares + 819,200 divisions | 5.894e11 | 4.824 TB |
| GH5 GLMM | 4,096,000 exp + 4,096,000 negative exp + 4,915,200 log | 1.100e13 | 100.665 TB |

TB means decimal 10^12 bytes. These are sums of measured isolated components,
**not** compiled full circuits, rigorous total-gate bounds or full-run timings.
They omit family guards, resets, additions, clamps and final output conversion;
compiler sharing/constant propagation also changes exact totals. Every worked
wrapper currently repeats a three-column 192-bit permutation per candidate.
The conservative switch model adds 38,220,595,200 gates (6,370,099,200 AND)
and 203,843,174,400 table bytes over 50 candidates; its gate-row stream is
356,725,555,200 bytes before input labels/OT. Native flags may be optimized by
the compiler, so the full-width-column model is deliberately conservative.

p=10 affects the producer before these wrappers: 5,000,000 public-beta MACs and
500,000 complete dot conversions for 50 candidates. The frozen source layout
uses `2*n*(p+1)=220000` Ring128 value/validity coordinates per recipient,
3,520,000 bytes each, before encrypted/alignment overhead. Local public-beta
MACs plus a secure final conversion are permitted by the contract. For context,
the deliberately generic GC dot benchmark (ten coefficients RN(0.1*2^50))
would add 9.675e11 gates and 8.475 TB of tables if repeated 500,000 times; this
is not the required or recommended step-2 dot producer. Actual dot GC cost
depends on the signed coefficient integers and step-2 implementation.

A future fused consumer can instead permute feature/response/validity columns
once, form all candidates over those ordered wires, and reuse group structure.
The emitter supports that composition; the current one-candidate wrappers do
not claim that once-only saving. These measurements establish that a production
full-grid implementation needs resource planning and arithmetic optimization.
No 10000-by-50 run is presented as measured. Full-package build/test evidence,
the synthetic measurement commands and their exact scope are in `STATUS_P.md`.
