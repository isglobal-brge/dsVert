# P3 disclosure budget — ds.vertLMM

Per Codex audit requirement: declare + prove compliance for each method.

## Summary

| channel | size | to | content | tier |
|---|---|---|---|---|
| client | p-vector | analyst | β_hat fixed effects (after closed-form GLS) | scalar reveal |
| client | p×p matrix | analyst | cov(β_hat) (from inverse Gram) | scalar reveal |
| client | scalar | analyst | σ² residual variance | scalar reveal |
| client | scalar | analyst | σ_b² random-intercept variance | scalar reveal |
| client | scalar | analyst | REML log-likelihood (optional) | scalar reveal |
| inter-server | n-vector | peer (nl) | cluster membership (plaintext integer ids in cohort order) | **documented tier (cluster ID)** |
| inter-server | per-cluster scalars | peer | per-cluster residual sums (K-vector) | derivable-aggregate |
| inter-server | transport-encrypted blobs | peer | Ring63 FP shares of transformed X̃, ỹ | AEAD sealed |

## Per-invocation disclosure

1. **β_hat** p-vector: fixed-effects coefficient estimate. Released as
   plaintext after client-side `solve(XtX, Xty)` on Beaver-aggregated
   Gram. Magnitude O(|β_true|); dimension p.
2. **cov(β_hat)** p×p matrix: inverse Gram, used for Wald SE. p(p+1)/2
   unique entries.
3. **σ², σ_b²** scalars: variance components estimated via REML profile
   optimisation on the LIVE aggregates rsum_per_cluster, rss_per_cluster,
   rss_total. No per-observation disclosure.
4. **REML log-likelihood**: one scalar (if compute_loglik=TRUE).

Cumulative per invocation: 1 p-vector + 1 p×p matrix + 3 scalars.
Asymptotic in n → 0 (disclosure independent of cohort size).

## Inter-server leakage (documented tier)

**Cluster ID broadcast** (documented in `tab:disclosure`): the outcome
server that owns the cluster indicator broadcasts the cluster id per
observation (as plaintext integer, in cohort-alignment order) to the
peer. Peer learns which observations share a cluster, NOT the clinical
identity of the cluster. Same tier as Cox's event-time permutation —
reveals aggregate-structure but not absolute covariate values.

**Per-cluster residual sums** (K-vector, with K = number of clusters):
rsum_cluster and rss_cluster aggregates are exchanged peer↔y_server
for the REML profile likelihood evaluation. These are AGGREGATED
(summed) over each cluster; no per-observation value exposed. Under
the standard DataSHIELD privacy policy (nfilter.tab ≥ 3, default 5),
any cluster of size < 5 would trigger a privacy exception — verified
by `.check_glm_disclosure` in dsVert/R/mpcUtils.R (with the explicit
carve-out for the internal `dsvertlmmint` column whose binary-valued
1-λ_i pattern is an artefact of the transform, not a binary covariate).

## Transformed X̃, ỹ shares

Each party takes its local covariate columns, applies the cluster-mean
centering transform `X̃ = X - λ_i × X̄_cluster(X)` where λ_i depends on
cluster size and variance ratio. The transformed vectors are then
Ring63 FP-split into additive shares and relayed peer↔server via
AEAD-sealed blobs. The client sees sealed bytes only; no party can
reconstruct another's X̃ values without the transport secret key.

## Non-disclosure proof

Traced through `ds.vertLMM.R` → `.ds_vertLMM_closed_form`
(`dsVertClient/R/ds.vertLMM.closed_form.R`):

1. Phase 0: transport keys exchanged (Ed25519 long-term + X25519
   ephemeral per session). Standard Cox-tier setup.
2. Phase 1: `dsvertLMMLocalGramDS` (server-side) computes the
   within-server Gram block in clear on each server's local X̃, ỹ;
   these stay server-local. Cross-server Beaver-shared columns are
   AEAD-sealed to peer.
3. Phase 2: `dsvertLMMReceiveGramSharesDS` consumes the sealed blob
   per party. Decrypted shares stay session-local.
4. Phase 3: per cross-pair, run full Beaver vecmul (`k2BeaverVecmul*`)
   to compute scalar share of the cross-Gram entry. Two parties'
   scalar shares are aggregated client-side via `k2-ring63-aggregate`
   → one plaintext scalar per cross entry.
5. Phase 4: assemble XtX (p×p), Xty (p-vector) at client, solve
   `β_hat = solve(XtX, Xty)`.
6. Variance components: separate pipeline uses per-cluster aggregates
   from `dsvertLMMPerClusterSumDS` (aggregates only, no per-patient
   reveal) to compute σ², σ_b².

## Disclosure compliance

✅ No n-dimensional plaintext vectors to client.
✅ Cluster ID membership leaked inter-server under documented tier
   (same class as Cox event-time ordering).
✅ Per-cluster sums respect nfilter.tab ≥ 3 privacy policy.
✅ Ring63 additive sharing + AEAD transport encryption prevent
   cross-party plaintext reconstruction of X̃, ỹ.

## Caveats

- **Cluster ID is a real inter-server leak**. Deployments where
  cluster membership is itself sensitive (e.g., research-site
  membership of participants revealed to peer) should NOT use
  ds.vertLMM in its current form. Oblivious clustering (Month 4
  stretch per plan) closes this at ~2× protocol cost.
- **Variance components σ², σ_b² revealed to client** — standard
  for LMM, but this gives the client more information about the
  within-cluster variability than a pure β-only release.
- **`dsvertlmmint` internal column carve-out**: the transform creates
  a near-binary (1 - λ_i) column for intercept handling. The
  `.check_glm_disclosure` binary-firewall skip is documented in
  `dsVert/R/mpcUtils.R` and `feedback_mpc_validation_gotchas.md`
  Rule 3.

## Accuracy trade-off note

LMM currently achieves |Δ|_abs < 1e-3 for all coefficients with
|β|≤1, but for |β|>1 the relative bound `rel < 1e-4` is violated
(X4 observed 2.2e-4 vs target 1e-4) by a factor of 2.2×. Root cause
is Ring63 FP floor on the Gram accumulation path. Two honest fixes
on the table:
- Iterative refinement via second MPC round (local, band-aid per
  docs/acceptance/path_b_targets.md).
- Full uint64→big.Int migration in k2_truncation.go (task #111).

Until one is shipped, LMM result is formally PASS_PRACTICAL for |β|>1
coefficients and must be reported as such in the paper — NOT claimed
at the plan's <1e-4 rel bar.
