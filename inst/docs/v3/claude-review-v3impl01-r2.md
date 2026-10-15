# Phase A delta review: dsVert v3 fixed-path DP Newton/IRLS (revision)

**Verdict: CONSENSUS.** All five blockers are resolved.

**Document SHA256:** `f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`

I reviewed the document text as pasted in this request. I did not recompute the hash from a file, so this approval binds to the hash as stated. `CONSENSUS_V3_DP_IRLS.md` should record that the hash was computed from the canonical committed bytes. Any byte change needs a new hash and a delta check.

The scope is the five blockers and the non-blocking items from my first review. Agreed decisions were not reopened. This is separate from the issue #26 approval.

## Blocker disposition

**1. Split-block stage atomicity: RESOLVED (§5, §7)**
- (a) Child identities `(K_t,"g")` and `(K_t,"H")` are immutable and each has its own fixed geometry.
- (b) Both lanes partition one committed protected evaluation output, including its validity binding.
- (c) The commit barrier requires both lanes durable at both authorities. Children have no readable endpoint. A crash resumes only the missing lane under its own key, and committed blocks never reroll. The full-stage reservation conservatively covers any partial exposure after an abort.
- (d) The predecessor digest hashes the canonical g‖H concatenation in signed order.
- (e) A score-only stage uses its g payload plus a signed reference to the prior H artifact. ε_H=0 is not an empty lane.
- (f) `purpose_t ∈ {optimizer, terminal-audit}` is bound in `K_t` and in both parent and child identities.
- (g) The per-lane `S1_g` and `S1_H` match the requested formulas. Each lane has its own α, translation and lattice. Substituting the joint S1 or ε_t is explicitly prohibited.

**2. Detecting a mis-calibrated lane: RESOLVED (§10)**
- The integer-sensitivity witness runs on the actual DAG at the corners, checked against an independent oracle. It is correctly labelled as not a privacy proof, and the algebraic certificate is verified separately.
- The lane-law case recomputes α exactly and rejects tampered ε or S1 metadata. Its GOF test has size 0.01 and power ≥0.9 against both half-scale and one-draw alternatives, and insufficient power fails the case.
- The translation case covers negative and off-diagonal coordinates and ±C·c_int,j. It separates input clamps from finalizer endpoints and requires refusal, never zeroing.

**3. Rational path verifier and size bound: RESOLVED (§4)**
- The Go implementation is authoritative. An independent `gmp::bigq` verifier shares the known-answer fixtures.
- Elimination is fraction-free Bareiss with a fixed pivot order. The Hadamard bound `k^(k/2)·2^(kw)` is correct, and L and 2L+2 follow from it.
- The Gershgorin `k_max = ceil((floor+R_H)/q_floor)` is a valid sufficient bound, since λ_min(H) ≥ −R_H. Exceeding it is a path failure.
- The ceiling is a signed constant that the certificate must show covers the whole DAG, including damping, trust and addition. It is never adaptive. Re-lattice rounding bounds denominator growth across T.

**4. Cost gate and early go/no-go: RESOLVED (§10)**
- `irls-smoke-k2-c64-p3-v1` fixes T=2, mask (T,T), terminal audit on, and ε = 2+2+4 = 8.
- The time budget is 3×240 s + 120 s = 840 s, which is consistent with the 14-minute timeout.
- Prebuilt artifacts are allowed, with cold costs measured separately, and materialization stays inside the timed run.
- The week-2 gate covers one full stage through exported R/DSI. Its failure outcomes are explicit, with no silent backend switch.

**5. Eight-week scope: RESOLVED (§10, §11)**
- Tier 3 is outside the commitment and its demo is conditional.
- Tier-1 inference ships as candidate/unavailable. The 3–4 days cover only refusal semantics, replay and the demo. The coverage qualification campaign is uncommitted.
- Tier 2 order is PEM/person-period, then multinomial. NB2 and ordinal come after week 8 unless slack is shown, and Tier 2 is cut before any Tier 3.

## Non-blocking items

- **N1.** Retaining the conservative refusal is acceptable, as I said originally, because it is signed and relaxation requires a new qualified profile.
- **N2** and **N3** are addressed. The SE check uses H̃_T⁻¹. The replay seed, stream order, replicate count and rational covariance are pinned in the inference profile.

The additional audit corrections are correct. In particular, modular wrap of the noisy release is post-processing and therefore a utility tail rather than δ, provided deterministic headroom holds for the noiseless aggregate, which the document requires.

## Errata (non-blocking; record in CONSENSUS file, fix in any later revision)

- **E1.** §11 says "canonical rational updates need one shared implementation." §4 is normative: the requirement is a shared *specification* plus an independent verifier. The §11 line must not be cited to drop the R verifier.
- **E2.** §1 says "a qualified inference candidate." This should read "inference candidate." §8 and §11 govern.
- **E3.** §5 labels joint geometry "Primary" but says the baseline uses split blocks. The v1 contract uses split-block geometry.
- **E4.** Rename `privacy --case clamps` to `input-clamps`, to match the input/finalizer distinction.
- **E5.** The contract (4–5 d) and fused producer (6–8 d) buckets take 10–13 days, which can overrun the week-2 gate. A slip of the gate itself triggers the same go/no-go review; it does not silently move the gate.
- **E6.** The smoke profile's q_floor, lattices and caps must be in the signed profile before the first measurement. The document already requires this, but it does not list them.
- **E7.** Bareiss with skipped zero rows needs explicit previous-pivot bookkeeping. Cover it with known-answer fixtures that include semidefinite cases.

## Status

**CONSENSUS on the Phase A design at SHA256 `f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`.**

No code is written or started in this task. Phase B begins only under §11's conditions, after the maintainer's 1.4.2 merge and with new worktrees. The inference route remains a guarded candidate and is not statistically validated.
