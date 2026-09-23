# Exact discrete-Laplace fallback: feasibility and stopped design

Date: 2026-09-23. Baseline: dsVert and dsVertClient v1.3.0.

## Decision

Do not implement or advertise the requested unconditional exact sampler under
the existing fixed-seed replay contract. A counter-mode extension can make the
stream arbitrarily long and replayable, but cannot make its distribution an
independent uniform random-bit sequence. The requirement that the implemented
sampler be exact, with representability its only residual, therefore cannot be
met as written. This invokes the requested stop-and-report condition; no
approximation, policy relaxation, sampler identifier, or release is shipped.

Two further requirements need correction before implementation: the stated
representability bound omits sensitivity and the sign bit, and unbounded noise
is incompatible with the existing deterministic no-wrap certificate.

## Existing paths and contracts

`inst/dsvert-mpc/k2_joint_dp_vector.go` contains the finite binary-geometric
planner, the XOR-stream reference circuit, and `jointDPVectorPrivateStream`.
Its stream derives from a 32-byte seed with HKDF-SHA256 and ChaCha20.

The production local-peer mechanism is in
`inst/dsvert-mpc/k2_joint_dp_vector_convolution_v3.go`. It has its own
`jointDPVectorConvolutionPrivateCipher` and
`dsVert/joint-dp/vector-convolution-private-stream/v3/` domain, samples two
finite geometric variables per coordinate into `int64`, and adds their
difference to a Ring128 share. Replacing only the reference private stream
would not change the production sampler.

The parser proves headroom from the finite maximum noise. The finalizer
reports `no_wrap_headroom_certified = true` and
`signed_decode = "canonical_Ring128_twos_complement_after_proven_no_wrap"`.
Those assertions require revision for any unbounded replacement; recognizing
a new sampler identifier alone is insufficient.

The active production identifiers remain:

- Plan: `dsvert-joint-dp-vector-independent-full-draw-convolution-plan-v3`
- Sampler: `hkdf-sha256-chacha20-independent-full-draw-binary-geometric-tv-v3`
- Backend: `independent_full_global_draw_convolution_ring128_v3`

The legacy reference plan remains `dsvert-joint-dp-vector-laplace-plan-v3`,
with sampler `hkdf-sha256-chacha20-xor-binary-geometric-tv-v3`.

## Exactness and deterministic replay are different properties

Canonne, Kamath and Steinke describe exact Bernoulli-exponential and
discrete-Laplace sampling with rational arithmetic and access to independent
uniform bits. Their Algorithms 1 and 2 can be implemented with `math/big` and
an uncapped bit reader, with no floating-point probabilities or finite noise
cutoff. See [the paper, Section 5](https://arxiv.org/html/2004.00010#S5) and
[the authors' reference implementation](https://github.com/IBM/discrete-gaussian-differential-privacy/blob/master/discretegauss.py).

However, for a fixed workload and fixed other-peer randomness, a deterministic
function of one uniformly chosen 256-bit seed has at most 2^256 terminating
outputs. Its event probabilities are integer multiples of 2^-256. Exact
two-sided geometric noise has infinitely many possible integer values with
positive probability. Moreover, for nonzero rational x, exp(-x) is
transcendental and cannot equal such a dyadic event probability. An arbitrarily
large counter and unbounded integer arithmetic do not change the finite seed
space. Allowing a nonterminating seed does not repair exact sampling either:
any such seed has positive probability, unlike almost-sure termination with
ideal independent bits.

Thus a deterministic CKS implementation over this keyed stream can remove
explicit truncation and threshold rounding, but its exactness theorem is
conditional on ideal independent bits. The deployed stream still needs a
cryptographic assumption. This observation does not imply that every
finite-randomness mechanism must have positive privacy delta: it specifically
rules out the requested exact distribution and the proposed unconditional
argument for this implementation.

True independent-bit sampling could instead persist the consumed random tape
or sampled noise for replay. That changes the fixed-seed protocol and the
independent-recomputation record contract, and is outside the requested design.

## Correct representability and wrap bounds

Write S for the unchanged joint L1 sensitivity in lattice steps,
alpha = epsilon/S, and q = exp(-alpha). For an ideal exact peer draw Z,

    Pr[Z = z] = (1-q)/(1+q) * q^|z|.
    Pr[|Z| > M] = 2*q^(M+1)/(1+q), for integer M >= 0.

For a signed W-bit ring, let B = 2^(W-1). The representable signed interval
is [-B, B-1], whose two tails start at -B-1 and B. Consequently,

    Pr[Z outside [-B, B-1]] = q^B
        = exp(-(epsilon/S) * 2^(W-1)).

For Ring128 the exponent is -(epsilon/S)*2^127. Across two peers and d
coordinates a union bound is min(1, 2*d*q^B). This is not bounded above by
exp(-epsilon*2^W), even when S=1. Its practical size depends on the public
parameter values; an exponentially small expression is not mathematically
zero, and arbitrarily small epsilon/S precludes a uniform negligibility claim.

Representability of each draw also does not prove that their sum plus the
statistic will not wrap. If each scaled statistic lies in [0,U], with U<=B-1,
put T=floor((B-1-U)/2). Requiring each peer's absolute draw to be at most T
suffices for no wrap. For d coordinates and two peers, this gives

    Pr[any sum wraps] <= min(1, 4*d*q^(T+1)/(1+q)).

Per-coordinate upper bounds can yield a tighter sum of such bounds. These
formulas describe the ideal distribution; they are not unconditional
statistical bounds for the finite-key pseudorandom implementation.

## A feasible revised privacy statement

For ideal independent bits, exact peer noise with rate alpha=epsilon/S gives
the usual vector likelihood-ratio bound exp(alpha*||f(D)-f(D')||_1) <=
exp(epsilon). The second independent peer's draw is post-processing of that
complete mechanism, including when the analyst knows one peer's contribution.

Reducing the complete noisy statistic modulo 2^128, then applying signed
decoding and fixed public clamping, is also post-processing and preserves
ideal pure DP. There is no unrepresentable residue: every arbitrary-precision
integer has a residue. Wrapping then measures deviation from the unbounded
integer release, a utility issue rather than a privacy delta. It cannot
simultaneously be called impossible or certified absent. Rejecting, clipping,
or resampling individual noise values is a different mechanism and cannot be
justified by moving its positive error probability to another metadata field.

A feasible revised scope would explicitly authorize:

1. Exactness with ideal bits and a computational privacy statement for the
   deployed HKDF/ChaCha20 stream, retaining that distinction in certificates.
2. Arbitrary-precision CKS sampling, a versioned counter-stream domain and
   specified bit order, followed by modular Ring128 addition.
3. Updated no-wrap contracts and the sensitivity-aware bounds above as utility
   metadata, while the Gaussian route retains its own positive delta.
4. Production-sampler battery calls and complete synthetic replay records
   bound to those revised contracts, followed by new known-answer vectors,
   tests, documentation and package versions.

No v4 identifiers are reserved by this stopped design. Replay specifications,
known-answer generation, and changes to both R validator layers must be agreed
with the resulting Go contract, rather than assigning a pure-DP label to the
existing finite-seed distribution.

## Verification status

Static source and contract inspection only. No tests, Go test binaries,
R CMD check, DSLite harnesses, statistical evaluations, builds, or sampler
executions were run. Existing v1.3.0 evaluation records and all implementation,
test, version, NEWS and mechanism-documentation files remain unchanged.
