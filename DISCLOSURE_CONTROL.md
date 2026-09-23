# Disclosure control in dsVert 1.4.0

The exact discrete-Laplace fallback releases one fixed, signed, clamped
Ring128 vector. Both designated peers independently draw full unbounded noise
with the public global L1 sensitivity and epsilon. Each draw is reduced modulo
`2^128` when committed; signed decoding and the existing public clamp are
post-processing. Noise is never clipped, magnitude-rejected or resampled.

Its artifact guarantee is exactly
`guarantee = "pure-dp-under-ideal-bits"` and
`randomness = "keyed-stream-computational"`. Ideal independent bits give pure
DP with zero mechanism and sampler implementation delta. Deployed sticky
HKDF/ChaCha20 replay requires the pseudorandomness assumption. The statement
assumes pinned, semi-honest, non-colluding peers with one hidden independent
noise contribution; it does not cover timing, availability, malicious peers or
compromised hosts.

Planning enforces `0 < epsilon <= 10000`, positive integer sensitivity `S`,
`epsilon/S >= 2^-100`, `1 <= d <= 1000000`, and `W = 128`. Zero delta is
accepted only by a route whose actual mechanism certificate permits it.
Gaussian and retained finite v3 samplers keep their declared positive delta.

Staged grouped/LMM/GLMM/GEE/Cox source protocols that require the retained
finite exact-GC private-validity release still require positive delta. Their
zero-delta requests fail during planning; this fallback does not replace that
source-validity protocol.

For the exact fallback, `wrap_bound_certified` replaces the old deterministic
no-wrap assertion. `wrap_bound_event` names individual-draw signed-ring
representability; its positive outward decimal bound and
`representability_bound` bound `min(1,2*d*q^B)`, where `q=exp(-epsilon/S)` and
`B=2^127`. Share/finalizer certificates separately carry `sum_wrap_bound`
and `sum_wrap_threshold` for the complete noisy sum. These utility events are
not mechanism delta. The mechanism still preserves ideal-bit pure DP on a wrap.

New plan, sampler, backend and stream identifiers distinguish v4 from v3.
Existing artifacts retain the semantics and replay stream of their own
version. A reader must validate the bound mechanism metadata and cannot
upgrade an old artifact's guarantee merely because the package was upgraded.

See [the exact mechanism specification](inst/docs/joint_dp_exact_laplace_ideal_bits.md),
[the two-peer release contract](inst/docs/joint_dp_independent_full_draw_convolution.md),
and [the historical and current design decisions](DESIGN_PURE_LAPLACE.md).

Upgrade with release traffic paused after completing pending v3 workflows.
Completed stored v3 artifacts remain readable and replayable, including a
retained acknowledgement. An unfinished v3 START/RESULT workflow, or the first
source-only acknowledgement without a retained record, is not migrated to the
new default planning policy by this release.
