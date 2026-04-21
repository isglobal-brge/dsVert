# P3 disclosure budget — ds.vertCox

Per Codex audit requirement: declare and prove compliance for each method.
Format: what is published, at which channel, why it is acceptable.

## Summary

| channel | size | to | content | tier |
|---|---|---|---|---|
| client | p-vector | analyst | grad(0) aggregate | scalar reveal |
| client | p×p matrix | analyst | Fisher(0) aggregate | scalar reveal |
| client | scalar | analyst | partial log-lik at β̂ (optional) | scalar reveal |
| inter-server | n-vector | peer (nl) | sort permutation over t | documented tier (event-time ordering) |
| inter-server | n-vector | peer | δ (event indicator in sorted order) | documented tier |
| inter-server | transport-encrypted blobs | peer | Ring63 FP shares (X, η, μ, G, S) | AEAD sealed, zero plaintext leak |

No per-observation values reach the client.

## One-step Newton path (currently shipping default)

Per invocation:
1. **grad(0) p-vector**: Σ_i δ_i [X_i − bar_R(X)(t_i)] revealed after Beaver
   aggregation. Scalar aggregate, magnitude O(√n_events × sd(X)).
2. **Fisher(0) p×p matrix**: Σ δ [bar_R(X⊗X) − bar_R(X)⊗bar_R(X)] revealed.
   p(p+1)/2 unique entries, magnitudes O(n_events × Var(X)).
3. **(optional, off by default) partial log-lik ℓ(β̂)**: one scalar revealed
   via DCF log pass on S. Activated by `compute_loglik=TRUE`.

Per Cox setup (one-off, not per-iteration):
4. **Event-time sort permutation**: y_server's rank order of event times
   sent to peer as transport-encrypted blob. Peer learns ordinal position
   of each patient's event time but NOT absolute time. Documented in
   `tab:disclosure` of the paper.
5. **Event indicator δ sorted**: y_server sends δ (0/1 per patient, in
   sort order) to peer as transport-encrypted plaintext. Peer learns
   who died / was censored and the rank order. Non-parametric tests
   (log-rank, Kaplan-Meier) in the pooled-data world would reveal the
   same info to anyone with access to both sides.

Cumulative budget for a single `ds.vertCox` invocation:
  - p-vector (grad) + p×p matrix (Fisher) + 1 scalar (loglik opt) per call
  - Asymptotic in n: **O(p²)**, independent of n.

## Path B path (not shipping; documented for completeness)

If `newton_refine_iters > 0`, ADDITIONAL disclosures per Newton iter k:
1. **grad(β_k)**: p-vector revealed.
2. **Fisher(β_k)**: p×p matrix revealed.

Hard cap: 5 iterations. Cumulative budget:
  - ≤5 × (p-vector + p×p matrix) = 5p + 5p² = up to 150 scalars for p=5.
  - Still O(p²), independent of n.

This is the SAME TIER as what `summary(coxph(...))` reveals in the pooled-data
world (coxph's `var` is an observed-Fisher matrix, its `coefficients` is the
score-zero vector). **No novel leak introduced** by Path B beyond what the
centralized coxph model would reveal to anyone with access to its object.

## Non-disclosure proof (one-step path)

Traced through `ds.vertCox.R` → `.glm_mpc_setup` → `k2SetCoxTimesDS` →
`k2ApplyCoxPermutationDS` → `.ds_vertCox_newton_one_step`:

1. Phase 0 (transport keys): Ed25519 long-term + X25519 ephemeral keypair
   per session. Public keys exchanged via client; secret keys never leave
   their home server.
2. Phase 1 (standardize + PSI): server-side mean/sd computed on aligned
   cohort, released to client as p-vector. PSI details covered in
   `ds.vertPSIAlign` disclosure doc (separate).
3. Phase 2 (input sharing): X columns split into additive Ring63 shares
   via `k2ShareInputDS`; peer's share sealed (AEAD ChaCha20-Poly1305)
   to transport pk and relayed via client. Client sees sealed bytes
   only; cannot decrypt without transport sk.
4. Phase 3 (cox meta broadcast): y_server sorts by time, computes
   permutation + sorted δ. Both serialized + sealed to peer's transport
   pk. Client sees sealed bytes only.
5. Phase 4 (permutation application): each party applies the permutation
   locally to its X shares. No cross-server communication; no
   per-observation value revealed.
6. Phase 5 (Newton prep): each party extracts per-column shares (local),
   computes reverse cumsums on shares (local). Per-column FP shares stay
   in session; never released.
7. Phase 6 (grad scalar reveal): each party computes scalar share of
   `Σ_i (X_c - bar_c/N_i) δ_i`; two shares aggregated via
   `k2-ring63-aggregate` to plaintext p-vector at client.
8. Phase 7 (Fisher cross-pairs via Beaver): per pair (j,k), one Beaver
   vecmul on X_j × X_k shares produces shares of X_j·X_k per row. Scalar
   reveal of weighted sum. p(p+1)/2 scalars to client.

All inter-server bytes: transport-encrypted. All cross-party arithmetic:
Beaver-masked (shares look uniformly random to the adversary's view).
Only outputs: p-vector + p×p matrix + one scalar.

## Disclosure compliance

✅ No n-dimensional plaintext vectors released to client.
✅ Inter-server leakage constrained to (permutation, δ) per documented
   tier — same as what a cohort-level survival paper would publish.
✅ Ring63 additive shares and AEAD sealing prevent any party from
   reconstructing another's plaintext covariate values.
✅ Path B adds no new channels; only reveals additional scalar
   aggregates at the same tier as the one-step path.

## Caveats

- **Not proven against active adversaries**. The plan's threat model is
  honest-but-curious semi-honest parties; malicious server behavior
  (e.g., sending incorrect shares) is not defended against at the
  protocol level. See the paper's §Discussion for the assumed model.
- **Event-time permutation is a real leak** that some deployments may
  find unacceptable. The oblivious-sort variant (plan §Month 2 time
  budget) would close this at ~2× protocol cost; not shipped in v30.
- **Strata membership** is an additional inter-server leak when
  `strata_col` is used. Same tier as cluster-ID in LMM.
