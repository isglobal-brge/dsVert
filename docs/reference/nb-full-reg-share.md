# Non-disclosive K=2 share-domain primitives for NB full-reg theta MLE

Server-side functions implementing the non-disclosive variant of
`ds.vertNBFullRegTheta(variant="full_reg_nd")` per the spec in
`docs/error_bounds/nb_t2_log_primitive_close_well_2026-04-29.md`. Closes
the D-INV-4 violation in the prior `full_reg` variant (which
transport-decrypted eta^nl plaintext at the label server) by keeping
eta^nl in Ring127 additive secret shares end-to-end through the
share-domain mu + log(mu+theta) + 1/(theta+mu) Beaver pipeline.

Threat model: K=2 OT-Beaver dishonest-majority (Demmler-Schneider-
Zohner ABY 2015 Sec.III.B). Inter-server channels Ed25519-pinned via
`trusted_peers` (`mpcUtils.R:530-556`). All entry points K=2-only via
`.k2_enforce_K(ss, 2L, ...)`.

Refs: Lawless 1987 *Can. J. Statist.* 15(3):209-225 (NB profile-MLE
theta score); Venables & Ripley 2002 *MASS* Sec.7.4 (`glm.nb` Newton);
Catrina & Saxena 2010 *Financial Cryptography* Sec.3.3 (multiplicative
depth ULP propagation); Trefethen ATAP Sec.8 (Bernstein-ellipse rel
error bound); Beaver 1991 *CRYPTO* Sec.3 (precomputed multiplication
triples); Boyle, Couteau & Gilboa 2019 (DCFNet – for future per-element
argument reduction).
