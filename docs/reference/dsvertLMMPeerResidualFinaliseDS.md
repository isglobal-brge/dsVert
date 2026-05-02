# LMM cross-server exact: peer-side residual slot finaliser

On the peer (non-outcome) server, the residual share is the NEGATIVE of
the share we kept from `dsvertLMMPeerFittedShareDS` (because the total
residual equals y - alpha - X_local \* beta_local - f_peer, so peer
contributes -f^peer_share_kept to the sum). This helper moves the
negated value into the canonical `k2_lmm_exact_r_share` slot so the
subsequent Beaver vecmul picks it up automatically.

## Usage

``` r
dsvertLMMPeerResidualFinaliseDS(n = NULL, session_id = NULL, frac_bits = 20L)
```

## Arguments

- n:

  Optional integer – the vector length. If omitted, we try `ss\$k2_x_n`
  (populated by k2ShareInputDS in the full GLM pipeline) and then fall
  back to decoding the peer-share byte length. Pass explicitly from the
  client orchestration whenever the session wasn't initialised by
  k2ShareInputDS.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).
