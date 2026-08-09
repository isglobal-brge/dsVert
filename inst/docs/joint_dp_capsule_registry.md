# Internal joint-DP capsule registry

This registry records one authenticated lifetime reservation for each
canonical capsule identity admitted at allocator commit.
It is internal implementation state: it is not exported, promoted as a
DataSHIELD method, or exposed over DSI.

## Identity and release contract

A capsule identity commits to the consortium, the complete policy-contract
hash, peer pinset, logical snapshot and alignment version, capsule schema,
admission and bounds contracts, operation-independent workload, and privacy
epoch. The policy contract must itself commit to the capsule epsilon, capsule
delta, and peer pinset. The capsule ID is the SHA-256 hash of that canonical
identity contract.

The clean pre-release ABI uses `dsvert-joint-dp-control-v3` and
`dsvert-joint-dp-capsule-identity-v3`; both bind the lifetime fields and
biomedical workload v7. V2 control/identity artifacts are legacy and fail
closed. The registry does not migrate or re-sign them automatically, so rollout
requires empty DP capsule state or a future audited offline migration.

Method names, arguments, operation IDs, query IDs, and release IDs are rejected
recursively from the durable admission, bounds, and workload components. At the
wire boundary, `capsule_id`, `query_id`, and `capsule_release_id` are aliases for
the same previously derived capsule identity; they are not independently
chosen identifiers. The policy constructor consumes exactly
`.dsvert_joint_dp_policy_context(policy)$common`, and regression tests require
the registry and control-plane identity objects to be byte-for-byte identical.
The common identity path is available to every custodian in the full pinned
set; designation remains mandatory only for allocator/noise execution.

Every previously unseen canonical capsule uses the same fixed epsilon and delta
and consumes one authenticated lifetime unit at allocator commit. The
custodian-owned `lifetime_max_distinct_capsules` defaults to `1`; exact decimal
validation requires `N * epsilon <= 8` and `N * delta < 1`. A committed unit is
not refunded if authorization, source transport, sampling or publication is
later abandoned. When no unit remains, the boundary returns only
`[dsvert_dp_lifetime_budget_exhausted:v1]`.

The same fixed token is also returned when the requested capsule cannot safely
advance because its irrevocable release-instance claim or sole publication
slot is already bound and that exact instance cannot continue or replay. This
is an opaque terminal union for privacy and compatibility, not evidence that
`remaining_distinct_capsules == 0`; distinct public tokens would reveal which
state occurred.

Status v5 scopes that bound to
`at_most_N_immutable_snapshot_workload_capsules_per_stable_privacy_accountant_namespace`.
It assumes that the custodians preserve one stable, unique accountant namespace
across domain, cohort, policy, pinset and ledger reconfiguration for each
protected privacy universe. The package does not currently discover competing
namespaces, enforce this uniqueness globally or migrate burned reservations
between reconfigured ledgers; those are custodial deployment obligations.

Reusing the exact same capsule and public release instance is pure
post-processing and does not consume another unit. Reusable records are
HMAC-authenticated and require both the private 256-bit secret and the expected
registry ID. The reusable-record HMAC key is domain-separated from the root by
that registry ID. A valid record from another registry or privacy epoch, or a
serialized analyst-supplied object, cannot authorize reuse. Status explicitly
reports `operation_accounting = "one_per_distinct_capsule_allocator_commit"`,
`operation_limit = TRUE`, `request_limit = FALSE`, and
`history_can_deny_operation = TRUE`. This is a privacy-loss gate on new capsule
reservation, not a request/session quota or an accuracy schedule.

The lifetime boundary is the local allocator commit, before bilateral
authorization. The commit has both signed prepare receipts plus the peer's own
signed commit, and atomically creates a dense HMAC-authenticated reservation
journal row whose `allocator_sequence` and `registry_sequence` are identical.
That evidence is sufficient to burn the unit even if the other commit or later
authorization never arrives. Reconciliation appends the bound registry row
through `.dsvert_capsule_registry_register_bound()`; a pre-existing unbound row
is never adopted and fails closed. `prepared` state alone consumes nothing.

The vector release has a separate anti-sibling boundary. Vector PREPARE stores
an authenticated candidate and consumes neither another lifetime unit nor the
capsule's release-instance claim. Sibling PREPARE candidates may therefore
coexist. At each designated peer, the first valid START atomically persists the
HMAC-authenticated `dsvert-joint-dp-vector-instance-claim-v1` row and the
authenticated `dsvert-joint-dp-vector-instance-claim-state-v1` set before that
peer reads its staged source or samples. The claim is irrevocable and not
refunded if the attempt stops: only the same release instance may subsequently
START, RESULT, transfer a final share or RELEASE at that peer. Source transport
may already have staged encrypted protected material before START, but no
sampler output or public value exists at the claim boundary. Matching bilateral
receipts are still mandatory, so split sibling claims cannot form a publishable
result. This is local authenticated history under the stated at-least-one-honest
designated-peer assumption, not a globally linearizable claim.

## Durability and concurrency

The SQLite registry uses a process lock, restrictive umask and permissions,
WAL mode, full synchronization, atomic transactions, unique capsule and
sequence constraints, per-row HMACs, a hash chain, and an authenticated current
head/count. An idempotent retry returns the authenticated existing record.
Concurrent attempts to register the same capsule produce one new row.

The allocator ledger and registry are separate SQLite databases, so they
cannot share one transaction. Their integration is a recoverable journaled
transition: `allocator commit + pending reservation` -> bound registry
append/reuse -> `registered`. A crash before the append retries it; a crash
after the append but before the journal update authenticates and seals the
existing row. The
allocator journal retains the registry sequence, row MAC, and chain hash. It
restores a verifiable rolled-back suffix in its original order and rejects an
alternate head, an unbound row, or any conflicting allocator binding. No crash
phase creates a second capsule or changes epsilon/delta.

The fast registration and status paths authenticate the current state, indexed
tail, and affected capsule row without `COUNT(*)` or a full-history scan. A
snapshot performs a full chain and row audit and is the appropriate integrity
check for historical rows.
The allocator preflight is also constant-history work in steady state: it
authenticates its singleton and committed/prepared head, after which the
operation authenticates its requested indexed row. Exact COMMIT/RELEASE replay
and sticky replay in the same live session are O(1). End-to-end cold
reconstruction after restart is deliberately different: it returns through
AllocationProof, which audits the complete O(N) allocator journal before
returning the proof. This replay audit consumes no lifetime unit, draws no noise
and reads no protected source. Legacy migration and an explicit allocator
forensic audit are likewise linear in stored history.
Migration installs an authenticated fast-state version marker only after the
derived singleton state has been checked and persisted. Once that marker
exists, a missing singleton is corruption and fails closed; it is never
silently reconstructed as though the database were legacy. Allocator migration
is protected by the process lock and a SQLite savepoint; registry marker
promotion is an atomic transaction performed only after both singleton states
validate, so a failed upgrade leaves the previous schema recoverable.
Regression tests observe eight indexed
SQLite reads for allocator preflight at histories of 10 and 128 capsules.
The allocator journal and the bound registry each maintain a separate
HMAC-authenticated count/head state. In steady state, reconciliation compares
those states and authenticates only the requested journal, registry row and
allocator admission, so it performs O(1) SQL calls and decodes O(1) rows;
each indexed SQLite B-tree lookup remains O(log N). A crash leaves a small
indexed `pending` set; a registry rollback costs O(the missing suffix), and an
old-schema migration or explicit forensic snapshot costs O(the full history).
Counts and sequence numbers authenticate completeness, ordering and rollback
boundaries and are compared with the signed lifetime maximum. They count all
allocator-commit burns, including reservations that never reach authorization
or publication. The current wire/SQLite implementation also represents exact
indices only up to `2^53 - 1`; that separate numeric/storage ceiling does not
replace the normally much smaller privacy bound.
Corrupt state, a wrong secret, a changed identity, a broken chain, an unbound
row, or altered release parameters fail closed. The allocator journal detects
or repairs registry-only rollback. This design does not claim protection
against simultaneous rollback of the allocator, registry, peer evidence, and
secret-bearing service state to mutually consistent older images; that still
requires at least one non-colluding designated peer to retain and use complete
authenticated monotonic history, or an external linearizable CAS.

## Authenticated lifetime composition

The snapshot reports simple composition as
`basic_composition_authenticated_lifetime_bound`: the number of burned
reservations times fixed epsilon and delta. The policy is rejected before use
unless the exact configured upper bounds satisfy `N * epsilon <= 8` and
`N * delta < 1`; consequently authenticated status must never report vacuous
delta. `remaining_distinct_capsules` is `N - capsule_count` and gates only a
previously unseen capsule.

The registry authenticates accounting and identity; it cannot make an unsafe
or insufficient capsule statistic safe. Each capsule schema still needs a
valid sensitivity, contribution-bound, clipping, and release proof.

## Internal API

- `.dsvert_capsule_registry_config()` builds and validates the immutable
  registry/policy binding.
- `.dsvert_capsule_registry_config_from_policy()` derives that binding from the
  exact joint-control policy context and chooses a registry path distinct from
  both DP ledgers.
- `.dsvert_capsule_registry_identity()` derives the canonical capsule ID.
- `.dsvert_capsule_registry_register()` atomically memoizes a new capsule or
  returns the authenticated existing record as a low-level registry primitive;
  an unbound result is not eligible for allocator use.
- `.dsvert_capsule_registry_register_bound()` atomically couples the row to an
  authenticated, cross-signed allocator admission and is the only active
  control-plane registration path.
- `.dsvert_capsule_registry_reuse()` validates an authenticated record against
  its required expected registry ID without ledger access.
- `.dsvert_capsule_registry_status()` validates authenticated head state and
  returns bounded lifetime composition without a full-history audit.
- `.dsvert_capsule_registry_snapshot()` performs a complete audit and returns
  bounded lifetime composition.
- `.dsvert_capsule_registry_lookup()` performs an indexed, authenticated
  capsule-ID lookup without scanning history; use `snapshot()` for a forensic
  full-history audit.

The control plane enforces `capsule_id == query_id`, signs both aliases in
`own_prepare`, and reconciles the authenticated registry binding before it can
mint or consume an `open_authorized` token. The integration is internal and
adds no remote method, capability flag, payload getter or request-count limit.
Its history-dependent rule is intentionally narrow: a new capsule reservation
may be denied, while exact replay of an existing capsule/release instance is
unlimited.
