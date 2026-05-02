# Prepare the DCF log phase for the Cox S -\> logS step

Copies `ss$k2_cox_S_share_fp` into `ss$k2_eta_share_fp` so a subsequent
4-phase wide-spline pass with `family = "log"` produces the share of
\\\log S(t_j)\\ in `ss$secure_mu_share`. Used by `ds.vertCox`'s
post-convergence partial-log-likelihood aggregate.

## Usage

``` r
k2CoxPrepareLogSPhaseDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(prepared = TRUE, length).
