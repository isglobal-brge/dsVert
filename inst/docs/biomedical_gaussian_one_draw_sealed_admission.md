# Biomedical Gaussian one-draw: sealed admission

This phase is an internal, non-production admission gate. It has no
DataSHIELD method, R export, runtime command, advertised capability, JSON
decoder, packaged-binary change, or opening.

## Verified by the gate

The gate accepts a public projection of the locally memoized biomedical
manifest and requires exactly one valid Ed25519 signature from every pinned
custodian. It then recomputes, rather than accepts from a caller:

- the sum of the signed manifest's exact rational squared-L2 components and
  its positive integer `ceil(sqrt(.))` sensitivity;
- every shifted coordinate upper bound with arbitrary-precision integer
  arithmetic (`raw_upper * 2^shift`);
- the signed-Ring128 range and independent sampler-support no-wrap checks;
- the one-global-draw Gaussian privacy plan and implementation-delta
  certificate;
- cryptographic role assignment for exactly two designated compute peers;
- the complete Phase-1.6 worker release binding and generic worker
  sensitivity certificate.

A second K-of-K signature barrier covers capsule, manifest, schema, workload,
source context and contract, logical snapshot, coordinate order, lattice,
privacy plan, release instance, actual release-contract hash, worker
transcript, pinset, K, designated roles, commitments, epsilon/delta, complete
shifted bounds, chunk policy, threat model, and the absence of request or
history denial inside this sealed worker phase. That phase-local flag does not
bypass the outer allocator commit, which must already have burned one lifetime
unit before protected-source access.

Chunks are derived only after this global admission. Their private seal binds
the global admission, absolute start/count, and deterministic compiled worker.
The sticky stream domain excludes public rechunking geometry and uses absolute
coordinate indices, so rechunking an immutable release cannot reroll noise.

The existing Gaussian worker binding was also corrected to verify
`raw_upper << shift == shifted_upper` exactly. The previous zero-shift-only
check was valid for the already-quantized formal-GLM slice but incorrectly
excluded biomedical coordinates with non-zero lattice shifts.

## Threat model and honest claims

The intended model is semi-honest pinned custodians, an untrusted analyst
relay, exactly two designated compute peers, and at least one honest,
non-colluding designated peer. K-of-K signatures prevent the relay or a single
peer from substituting the signed manifest or release. Deliberate collusion by
all relevant custodians, a compromised server host, malicious protected-data
materialization, denial of service, and side channels outside the fixed public
worker shape are not solved by this gate.

This phase proves admission consistency; it does not yet prove that the R
materializer has been wired to this exact Go object. Accordingly
`ProtectedDataE2EVerified` and `ProductionReady` remain false and the number of
openings remains zero.

## Deliberate blocker

Even after successful K-of-K admission, opening returns
`biomedical_gaussian_one_draw_r_dsi_admission_and_opening_unavailable`.
Production promotion still requires:

1. an R projection built exclusively from each server's memoized manifest and
   materializer contract;
2. K-of-K admission receipt collection over DSI;
3. an authenticated cross-process exact-GC token that reverifies the complete
   signature set inside the worker;
4. purpose-bound exact-GC transport support for the Gaussian operation; and
5. the single common DP-vector opening, durable finalizer, replay, and client
   certificate path.

Until all five are connected and independently tested, the older two-draw
Gaussian capsule remains the only exposed Gaussian vector route. No fallback
or capability silently labels the sealed one-draw route as production-ready.

## Validation

The Go tests cover K=2, K=3, and K=5; omitted, duplicated, extra, and wrong-key
signatures at both barriers; pin omission/substitution; re-signed arbitrary
sensitivity and semantic-hash substitutions; release-instance replay;
non-canonical/invalid rational components; signed-Ring128 overflow; exact
non-zero shifts and zero-shift compatibility; sticky absolute-coordinate
rechunking; private-seal mutation; generic-certificate substitution; JSON
non-exposure; and absence from the dispatcher and runtime capability manifest.
