# LMM cross-server exact residual pipeline – peer side

On the non-outcome server (which holds some of the predictors), compute
the per-patient linear-predictor contribution \\f^{peer}\_{ij} =
x^{peer}\_{ij}{}^T \hat\beta^{peer}\\ in plaintext (both \\x^{peer}\\
and \\\hat\beta^{peer}\\ live on this server), split it into two
additive Ring63 shares \\f^{peer} = f^0 + f^1\\, keep \\f^1\\ in the
session under `k2_lmm_exact_peer_share` for the Beaver r^2 step, and
return the complementary share \\f^0\\ transport-encrypted to the
outcome server's pk so the caller can relay it via `mpcStoreBlobDS`.

Inter-party leakage: none beyond existing (the outcome server already
learns an additive share of \\f^{peer}\_{ij}\\, which is random and
reveals nothing on its own; reconstruction requires combining with
\\f^1\\ on the peer).

## Usage

``` r
dsvertLMMPeerFittedShareDS(
  data_name,
  x_names,
  betahat,
  peer_pk,
  session_id = NULL,
  frac_bits = 20L
)
```

## Arguments

- data_name:

  Aligned data-frame name.

- x_names:

  Predictor names on THIS (peer) server.

- betahat:

  Plaintext coefficient vector matching `x_names`.

- peer_pk:

  Transport pk of the outcome server (base64url).

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20).

## Value

list(peer_blob, n) – peer_blob is the transport-sealed share destined
for the outcome server.
