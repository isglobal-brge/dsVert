# Formal GLM Phase 1.7 authenticated admission

Phase 1.7 is an internal, non-production gate. It has no DataSHIELD
`AggregateMethod`, R export, runtime command, advertised capability, or packaged
binary change. It performs no opening.

## Public lifecycle status (security-profile schema v5)

This note preserves component-level research evidence; it is not readiness
evidence for a new public computation route. Schema v5 reports
`route_claims$formal_glm_ready = FALSE` with state
`sealed_no_registered_r_dsi_joint_dp_release_lifecycle`. The top-level client
`ready` value and the server compatibility alias `formal_dp_claim_eligible`
describe the biomedical joint-DP capsule route only; neither promotes formal
GLM or formal Cox. It separately reports the read-only completed-certificate
route; this component cannot create such a certificate.

Formal GLM remains sealed until the protected materializer, the complete
registered R/DSI schedule, the durable common finalizer and the route-level
end-to-end numeric certificate are bound into one tested release lifecycle.

## What the gate closes

The only typed formal-GLM admission constructor receives the complete Phase-1.5
plan, unanimous plan approvals from all `K` custodians, the final two compute-peer
receipts, the exact `K`-peer Ed25519 pinset, the Phase-1.5 DP bridge, the common
capsule binding, a manifest binding, and a source-contribution attestation.

It then:

1. validates the Phase-1.5 plan and exactly one valid plan approval from every
   custodian;
2. validates the exact pinset, designated compute-peer roles, and both final
   execution receipts;
3. rebuilds the bridge and the complete integer-lattice L2 sensitivity
   certificate from the approved plan and receipts, compares canonical bytes,
   and discards the caller's asserted object as a source of truth;
4. requires a separate `K`-of-`K` Ed25519-signed source-contribution contract
   binding fixed public capacity, zero-weight padding, patient adjacency, and at
   most one active aligned row per patient;
5. binds plan, kernel, bounds, quantization, snapshot, source context, source
   contract, fan-in transcript, final checkpoint, bridge, receipts, L2
   certificate, coordinate order, manifest, schema, workload, capsule, release
   instance, release contract, pinset, roles, mechanism, allocation, epsilon,
   delta, and the complete candidate worker contract into one canonical Phase-1.7
   preimage;
6. checks explicitly that `ReleaseContractSHA256` equals the worker transcript;
7. requires exactly one valid Ed25519 signature from every custodian over that
   exact preimage; and
8. returns a private typed admission whose worker and admission seal are not
   serialized. A generic Gaussian worker, including one carrying a self-hashed
   caller-created `machine_proven` certificate, is not this type and cannot pass
   the admission validator.

The admission seal is a deterministic integrity digest, not a MAC. This is
acceptable only while the admission type, its `worker` and `seal` fields, and
its constructor remain package-internal, and no command/config/R decoder can
instantiate it. Tests assert those fields are unexported and that the main
dispatcher, runtime capability manifest, exact-GC worker config, DESCRIPTION,
and NAMESPACE contain no Phase-1.7 route. Any future serialization or command
boundary must replace this static invariant with an authenticated durable token
verified from the full K-of-K signature set.

Identical signed retries are deterministic and idempotent. A signature set for
one release instance cannot be replayed against another release instance or any
substituted semantic hash.

## What remained blocked at Phase 1.7

The signed contribution statement authenticates the custodians' claim; it does
not inspect protected rows. At the time of this phase, the R protected-data
materializer, production DSI materialization path and authenticated common
single-opening finalizer had not been connected to this Go gate.

Consequently:

- `ProtectedDataE2EVerified` is always `false`;
- `ProductionReady` is always `false`;
- `OpeningsPerformed` is always zero; and
- both successful authenticated admission and every opening request return the
  typed `formal_glm_protected_materializer_and_dsi_opening_unavailable` blocker.

At Phase 1.7, no claim of end-to-end source enforcement or production release
was made; those component gaps were not closed within this phase.

Later internal phases added a protected materializer, durable local finalizer
and Phase-1.9 fan-in/release components. That later component evidence does not
change the public route state: there is still no registered R/DSI coordinator
joining the full lifecycle, no promoted finalizer consuming hidden execution
validity, no route-level end-to-end numeric certificate, and no real
multi-process DSI validation. The current frontdoor remains sealed with
`formal_glm_phase19_durable_r_dsi_release_bridge_not_promoted`.
