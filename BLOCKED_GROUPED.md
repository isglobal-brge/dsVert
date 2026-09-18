# Grouped release dependency — clause 5, 2026-09-18

The prior composed-GC traffic blocker is WITHDRAWN. It measured an architecture
superseded by clause 5. The new scalar-only 32-value chunks pass the <=5000
AND/value gate, including guards/masks, on the pod with compact transport.
Measured results are in BENCH_GROUPED_CLAUSE5.md. No new full-release traffic
failure or admitted capacity is claimed.

The protected release still needs an exact two-authority arithmetic backend
and its authenticated chunk/fusion interface. Local additive-share sums do
not compute squares or private products. LMM's count-dependent coefficient
is private despite public variance parameters. GLMM and GEE also need private
products, masking, exact rescaling and clipping. See the concrete derivations
and existing-backend audit in CLAUSE5_ARITHMETIC_GROUPED.md.

The available Beaver route uses dealer-generated triples and approximate
truncation; adopting it silently changes the two-authority trust/rounding
contract. Retaining the old GC arithmetic silently contradicts the scalar-only
restriction. A dealer-free exact arithmetic backend is a viable engineering
route, not an impossibility result; ownership and its receipt interface have
been raised with the reviewer while independent work proceeds. Step 2 at
8b6c7bf has not supplied authenticated fusion. No fixture, dealer or public
state string is used as a substitute.

Other incomplete lane work remains explicit: full grouped composition and
certificates (including GEE bread/meat), Go/R cap mapping, full-release capacity
matrix, protected DSLite lifecycle and final package checks. These items are
not relabelled as completed or all attributed to the external dependency.
Production validators/materializers/readers remain fail closed.
