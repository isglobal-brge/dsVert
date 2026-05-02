# Prepare deviance: store residual as 1-column X matrix for Beaver Sumr^2

After convergence, computes r = mu_share - y_share in Ring63 and stores
as k2_x_full_fp (nx1 "matrix"). Then the standard k2GradientR1DS/R2DS
with p=1 triples computes "gradient" = r^T x r = Sum r_i^2 (deviance).

## Usage

``` r
glmRing63PrepDevianceDS(mode = "rss", session_id = NULL)
```

## Arguments

- mode:

  Character. Operation mode (e.g. `"rss"` or `"canonical"`).

- session_id:

  Character or NULL.

## Value

List with status.
