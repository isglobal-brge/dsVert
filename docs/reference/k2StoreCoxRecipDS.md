# Cache the reciprocal-of-S share returned by the DCF-reciprocal pass

If `recip_S_share_fp` is NULL, copy the current `ss$secure_mu_share`
(which holds the 1/S share left over by the most recent wide-spline
reciprocal pass) into `ss$k2_cox_recip_S_share_fp`. This is the usual
in-session callers' path; passing an explicit vector is supported for
tests.

## Usage

``` r
k2StoreCoxRecipDS(recip_S_share_fp = NULL, session_id = NULL)
```

## Arguments

- recip_S_share_fp:

  base64 FP vector (1/S share) or NULL.

- session_id:

  GLM session id.

## Value

list(stored = TRUE)
