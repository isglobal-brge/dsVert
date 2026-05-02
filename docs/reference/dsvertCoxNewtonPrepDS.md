# Cox-Newton prep: extract+cumsum all columns and build plaintext weights

Invariant inputs (already in session): ss\$k2_x_share_fp row-major FP
share, n*p_own ss\$k2_peer_x_share_fp row-major FP share, n*p_peer
ss\$k2_x_n, ss\$k2_x_p, ss\$k2_peer_p ss\$k2_cox_delta_fp plaintext FP
(same bytes at both parties) ss\$k2_cox_strata optional integer vector
(plaintext, same bytes)

This helper: 1. Extracts each column into its own FP share slot
cox_n_Xc\_*fp (idx = 1..p_total, canonical order (own \| peer)) 2.
Computes reverse cumsums (strata-reset) on each column share
cox_n_Sc*\_fp 3. Builds plaintext FP vectors (SAME bytes at both parties
by construction – both parties read identical delta_fp and strata)
cox_n_delta_fp delta (already stored; repeated here) cox_n_W1_fp
delta(i)/N(i) (plaintext FP) cox_n_W2_fp delta(i)/N(i)^2 (plaintext FP)

Returns: list(n, p_own, p_peer, p_total, n_events).

## Usage

``` r
dsvertCoxNewtonPrepDS(
  session_id = NULL,
  is_coordinator = NULL,
  p_coord = NULL,
  p_nl = NULL
)
```

## Arguments

- session_id:

  MPC session id.

- is_coordinator:

  Logical – TRUE at the outcome server. Determines the canonical mapping
  from local "own" / "peer" share matrices to the global (coord \|
  nonlabel) column order that BOTH parties must agree on. Without this
  mapping each party's grad_j / Fisher_jk refers to a different column
  and scalar aggregation across parties is garbage.

- p_coord, p_nl:

  Canonical column counts (coordinator / nonlabel covariates). The
  concatenated beta order is (coord, nl), total p.

## Value

list(n, p_own, p_peer, p_total, n_events).
