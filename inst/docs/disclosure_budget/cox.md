# Disclosure audit — `ds.vertCox` (quarantined)

Release status: **quarantined**. No Cox client frontdoor is a promoted
biomedical release route. `ds.vertCox()`, `ds.vertCoxProfileNonDisclosive()`,
`ds.vertCoxDiscreteNonDisclosive()`, `ds.vert.cox()` and `ds.vert.coxph()`
raise a typed migration error before any DSI call. The Cox-specific legacy
server endpoints are absent from the registered `AggregateMethods` allowlist.

Security-profile schema v4 independently reports
`route_claims$formal_cox_ready = FALSE` with state
`sealed_no_recipient_encrypted_r_dsi_lifecycle_or_end_to_end_numeric_certificate`.
The top-level client `ready` value and server compatibility alias
`formal_dp_claim_eligible` apply only to the biomedical joint-DP capsule route;
neither can promote this quarantined Cox frontdoor.

## Why the legacy route is not releasable

The retained research implementation used exact score, information and
likelihood aggregates and, in older variants, row-order risk-set metadata.
Encryption and pinned peer identities protect transport and peer
authentication, but they do not turn deliberate exact analyst openings into a
contribution-bounded DP release. Repeated or adaptive exact model aggregates
also have no non-reconstruction guarantee.

The discrete-time compatibility implementation targets a pooled-logistic
hazard estimand, not a Cox partial-likelihood estimand, and therefore cannot be
presented as an interchangeable fallback.

## Promotion gate

A releasable Cox route needs one purpose-bound, signed and sticky joint-DP
capsule with explicit clipping and contribution bounds; private risk-set
evaluation; certified ties, strata and delayed-entry semantics; covariance and
identifiability certificates; and independent multi-process DSI validation for
K=2 and K>=3. Internal prototype components are not release evidence until all
of those gates are closed together.

This note records the reason for quarantine. It is not authorization to call
the legacy implementation or register any of its retired server endpoints.
