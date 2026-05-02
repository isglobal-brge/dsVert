# Cox residual finalisation: r = delta - mu*G (party 0) / -mu*G (party 1)

Assuming the Beaver vecmul has populated `ss$k2_cox_mu_g_share_fp` with
this party's share of \\\mu \odot G\\, compute the Cox residual share
\\r^0 = \delta - (\mu G)^0, r^1 = -(\mu G)^1\\ (recall \\\delta\\ is
plaintext at BOTH parties via `k2SetCoxTimesDS` / `k2ReceiveCoxMetaDS`)
and store it in `secure_mu_share` so the existing `X^T r` Beaver
gradient machinery can consume it without modification.

## Usage

``` r
k2CoxFinaliseResidualDS(
  is_party0,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
```

## Arguments

- is_party0:

  Logical.

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits. At ring=127 forced to 50.

- ring:

  Integer 63 (default) or 127.

## Value

list(done = TRUE).
