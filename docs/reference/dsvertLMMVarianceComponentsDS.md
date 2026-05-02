# Cluster ANOVA moments for LMM K=3 variance-component recovery

Computes the within-cluster (SSW) and between-cluster (SSB) sums of
squares of the outcome y on the outcome server, plus per-cluster sizes.
Aggregate-only output: only the two scalars SSW + SSB plus the
per-cluster size vector (the latter already disclosed by
`dsvertClusterSizesDS`). No per-row data leaves the server.

Used by `ds.vertLMM.k3` to recover the random-intercept and residual
variance components after the federated weighted-GLM fixed-effects fit
converges (Pinheiro & Bates 2000 *Mixed- Effects Models in S/S-PLUS*
§2.4.2 within-between ANOVA estimator).

For balanced designs (constant n_i = n) the standard ANOVA estimator on
raw y gives:


      E(MSW) = sigma^2 + Var_within(X beta) ; MSW = SSW / (N - K)
      E(MSB) = sigma^2 + n sigma_b^2 + Var_between(X beta) ; MSB = SSB / (K - 1)
      

For covariates X with no within-cluster correlation (iid within
cluster), Var_within(X beta) ~ n \* Var_between(X beta), and sigma_b^2 =
(MSB - MSW) / n is approximately unbiased. The sigma^2 estimate inherits
a Var_within(X beta) bias from the X contribution; flag this honestly in
the wrapper.

## Usage

``` r
dsvertLMMVarianceComponentsDS(data_name, y_var, cluster_col)
```

## Arguments

- data_name:

  Character. Aligned data-frame name on the outcome server.

- y_var:

  Character. Outcome column name.

- cluster_col:

  Character. Cluster id column.

## Value

list(SSW, SSB, n_per_cluster, K, N, ybar, ssw_per_cluster).
