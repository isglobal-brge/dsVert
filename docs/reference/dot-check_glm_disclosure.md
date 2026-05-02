# Check GLM disclosure controls (saturated model + binary variables)

Checks two disclosure risks following dsBase glmDS1/glmDS2 pattern:

1.  **Model saturation**: Blocks if `p > nfilter.glm * n`, preventing
    models where the number of parameters approaches the number of
    observations (risk of individual data reconstruction).

2.  **Binary variable small cells**: For any binary variable (response
    or predictor), blocks if the smaller category has fewer than
    `nfilter.tab` observations.

## Usage

``` r
.check_glm_disclosure(X, y = NULL, p_total = NULL)
```

## Arguments

- X:

  Numeric matrix. Design matrix (n x p).

- y:

  Numeric vector. Response variable (optional, NULL to skip y check).

- p_total:

  Integer. Total number of parameters across ALL servers in the vertical
  partition. If NULL, uses ncol(X).

## Value

TRUE if all checks pass, otherwise stops with error.
