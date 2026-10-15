# v3impl01 Phase A consensus

Date: 2026-10-15. **CONSENSUS reached; design only. No implementation started.**

Document: [DESIGN_V3_DP_IRLS.md](DESIGN_V3_DP_IRLS.md)

SHA256 of the exact on-disk UTF-8 bytes: `f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`.

Codex independently recomputed this hash after Claude's approval and confirmed that the approved document has not changed. The document is outside the package repositories; no Git commit or package-tree modification is implied by “canonical bytes.”

Claude (Anthropic) was consulted through the available Claude CLI in read-only text review, with tool use disabled and the complete document supplied. [Round 1](claude-review-v3impl01-r1.md) requested five specification changes. [Round 2](claude-review-v3impl01-r2.md) explicitly states **CONSENSUS**, names this hash, and closes all five blockers. Claude reviewed the supplied text; Codex performed the file/hash verification.

Codex agrees with the final design and the review dispositions. This consensus is distinct from approval of issue #26. Phase B still requires the maintainer's 1.4.2 merge and Claude-created new worktrees under the conditions in §11. This task authorizes no implementation, test execution or MPC benchmark.

## Agreed decisions

- Production cross-grid R/DSI lifecycle and durable stage executor, with a new fused public-point score/H program.
- Two full independent v4 draws; split score/H lanes in one durably committed stage publication, with one protected evaluation and lane-specific calibration.
- Exact rational public update, dual-authority successor signatures, an independent client verifier, and frozen provenance epochs.
- Explicitly budgeted terminal score/H audit for the replay-plus-information inference candidate; no claim of validated sampling inference.
- Mechanism-level validation only, with a fixed short live profile and a week-2 end-to-end stage cost gate.
- Eight-week commitment: Tier 1 and conditional first Tier-2 slice. NB2/ordinal follow unless demonstrated slack; Tier 3 is outside that commitment. Statistical coverage qualification is a separate milestone.

## Normative clarifications from Claude's non-blocking errata

These clarify the approved text without changing its bytes. Read them with the design before Phase B.

1. §4 controls: use a shared rational-arithmetic **specification**, authoritative Go code and an independent bignum verifier. The later phrase “one shared implementation” does not remove the verifier.
2. The route has an **inference candidate**, not a statistically qualified candidate. §§8 and 11 govern its status.
3. Baseline v1 geometry is **split blocks**. A single scaled joint vector is an alternative signed profile; the primary sampler in either case is v4 two-full-draw convolution.
4. The proposed `privacy --case clamps` command means `privacy --case input-clamps`. Finalizer endpoints have a separate signed-translation case.
5. Slippage of the week-2 timing milestone itself triggers go/no-go review; the milestone does not silently move behind later client work.
6. The smoke profile must sign q_floor, every lattice, cap and numeric certificate before its first measurement. No runtime choice of omitted constants is allowed.
7. Fraction-free semidefinite PSD elimination must specify previous-pivot bookkeeping when zero rows are skipped, with independent known-answer fixtures for semidefinite cases.

## Work performed

Read-only source and issue audit, design drafting, independent subtask reviews, and two Claude text-review rounds. Verified the document hash and existence of 24 explicitly pinned source paths. No MPC benchmarks, test suites, simulations, package source edits, branch operations or worktree creation were performed. Existing long federation jobs were not touched.

Remaining work is implementation and acceptance evidence: numeric certificates, measured fused/R/DSI cost, final signed inference thresholds/schedules, and capability promotion. There are no unresolved Phase-A design blockers.
