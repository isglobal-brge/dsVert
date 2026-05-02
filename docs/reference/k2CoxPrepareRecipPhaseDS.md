# Prepare the DCF reciprocal phase for the Cox 1/S step

Copy `ss$k2_cox_S_share_fp` (the reverse cumsum of exp(eta) produced by
`k2CoxReverseCumsumSDS`) into `ss$k2_eta_share_fp` so the standard
4-phase wide-spline pipeline (family = "reciprocal") operates on
\\S(t_i)\\ and produces shares of \\1/S(t_i)\\ in `ss$secure_mu_share`.

## Usage

``` r
k2CoxPrepareRecipPhaseDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(prepared = TRUE, length = n)
