# Cox partial-log-likelihood aggregate

Return per-party scalar shares of the two summands of the Cox partial
log-likelihood evaluated at the current \\\hat\beta\\: \\T_1 =
\sum\_{j:\delta_j=1} \eta_j\\ \\T_2 = \sum\_{j:\delta_j=1} \log S(t_j)\\
where `eta` = `ss$k2_eta_share_fp` (cached from the last
`k2ComputeEtaShareDS` call at \\\hat\beta\\) and `logS` =
`ss$secure_mu_share` after the DCF log pass. The client reconstructs
\\\ell(\hat\beta) = (T_1^{(0)} + T_1^{(1)}) - (T_2^{(0)} + T_2^{(1)})\\.

## Usage

``` r
k2CoxPartialLogLikAggregateDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(sum_delta_eta, sum_delta_logS).
