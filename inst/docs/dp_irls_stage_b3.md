# B3 protected stage and mandatory split noise

The selector-only R adapter authenticates the B1 point, source epochs and
signed person slots before creating a private `exact-gc-worker` configuration.
The worker operation is `dp-irls-fused-stage-v1`; the ordinary GC compiler
continues to reject it. `dp-irls-noise-plan` validates the public numeric policy
and returns the exact purpose plus two lane descriptors, without reading data.

The required source ABI is `signed-person-q16-two-owner-valid-v1`. Each person
has seven Ring128 inputs in signed slot order: the two owner-valid bits, three
q16 X coordinates, integer y and q16 offset. Each owner contributes its own
validity and authorized values, with zero in unowned positions. The final four
XOR words bind the authenticated, fixed person-slot alignment. They must not
be derived from observed row validity. The circuit requires both owner-valid
bits to equal one, all X/offset values to be in [-65536,65536], and y in the
signed family domain. A malformed person contributes zero to every coordinate;
other persons remain present. The legacy B2 source ABI is test-only for this
route: the mandatory-noise worker rejects it.

One fused private evaluation produces and durably commits all nine translated
aggregate shares. B3 partitions that same COMMIT into g (three coordinates) and
H (six upper-triangle coordinates). The B2 certificate supplies the integer
add/remove sensitivities 12288 and 6144 for binomial; replace-one doubles both.
Each lane's alpha is recomputed as its exact signed epsilon divided by its own
sensitivity. Every authority supplies a full independent v4 draw under a lane,
role and coordinate separated private stream. There is no noise-disable path.
The output unit is 1/4096; A is capacity times the certified person cap, and
U=2A. The producer adds A once, before sharing. The finalizer performs v4
Ring128 modular signed decode and fixed clamping to [0,U], then publicly
subtracts A. It reports only DP coordinates and DP endpoint flags.

The authenticated private journal fixes source binding, noise seed binding,
protected COMMIT and each retained noised lane. Each local lane is fsynced
before an encrypted peer durability exchange. Both lane barriers must complete
before the worker emits any result. A crash resumes retained children and never
rerolls a completed sibling. Missing/corrupt committed state fails closed.
The worker emits no exact statistic, source validity, clamp count, private seed
or separate noise value. R persists and dual-signs both child receipts before
publishing the single parent; transport timings are outside canonical bytes.

`dp-irls-finalize` is a server-internal public postprocessor. It requires both
noised lanes from both authorities and recomputes the metadata, exact law,
translation and lattice. It returns g/H `translated_values`, `signed_values`,
`endpoint_hits` and the outward sum-wrap utility bound. The ideal-bit privacy
law has zero implementation delta, retaining the computational private-stream
assumption and physical timing/availability limitations of v4. The wrap bound
is a utility bound, not a claim of deterministic no-wrap or a privacy delta.
