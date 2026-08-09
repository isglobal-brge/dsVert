# Disclosure audit — `ds.vertLMM` (quarantined)

Release status: **quarantined**. `ds.vertLMM()`, `ds.vertLMM.k3()` and their
compatibility aliases raise a typed migration error before any DSI call. No LMM
route is a promoted biomedical release route, and its legacy cluster-granular
server endpoints are absent from the registered `AggregateMethods` allowlist.

## Why the legacy route is not releasable

The retained research implementation can reveal exact cluster sizes,
per-cluster residual sums and sums of squares, and random-effect design
cross-products. Some variants also disclose cluster membership to a compute
peer. These objects scale with the number of clusters and can be combined or
differenced across adaptive invocations.

Minimum cluster-size checks, encrypted transport, additive sharing and pinned
peer identities are valuable controls, but none makes both shares returned to
the analyst a DP release. They therefore do not establish a
non-reconstruction guarantee for the cluster-granular outputs.

## Promotion gate

A releasable LMM route needs contribution-bounded cluster statistics inside a
purpose-bound, signed and sticky joint-DP capsule; private cluster handling;
certified ML/REML and random-effects semantics; covariance and identifiability
certificates; and independent multi-process DSI validation for K=2 and K>=3.
Any accuracy claim must be tied to that replacement protocol and its numerical
certificate, rather than to the retired Ring63 research path.

This note records the reason for quarantine. It is not authorization to call
the legacy implementation or register any of its retired server endpoints.
