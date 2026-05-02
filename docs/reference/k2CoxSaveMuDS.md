# Cox save-mu helper (copy mu share before DCF reciprocal overwrites it)

`secure_mu_share` is re-used by each wide-spline pass as the output
slot; to do Cox's mu\*G Beaver product later we must snapshot the
exp-share into `ss$k2_cox_mu_share_fp` before running the reciprocal
pass on \\S(t)\\.

## Usage

``` r
k2CoxSaveMuDS(session_id = NULL)
```

## Arguments

- session_id:

  MPC session id.

## Value

list(saved = TRUE, length).
