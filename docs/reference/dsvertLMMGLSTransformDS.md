# Cluster-mean-center columns for random-intercept GLS (LMM)

Apply the Laird-Ware closed-form GLS transform for a random-intercept
LMM. For each requested column `v` and each cluster `i`, compute
\$\$\tilde v_j = v_j - \lambda_i \bar v_i, \quad j \in C_i\$\$ where
\\\bar v_i\\ is the within-cluster mean of `v` and \\\lambda_i = 1 -
\sqrt{\sigma^2 / (\sigma^2 + n_i \sigma_b^2)}\\. OLS on the transformed
design matrix (with an explicit cluster-specific intercept column \\1 -
\lambda_i\\) yields the exact REML / GLS fixed-effects estimate –
matches [`lme4::lmer`](https://rdrr.io/pkg/lme4/man/lmer.html) to
machine precision.

Operates locally on the server: no cross-server traffic, no Beaver MPC.
Just a per-cluster mean subtraction using the cluster IDs previously
broadcast by `dsvertLMMBroadcastClusterIDsDS`.

## Usage

``` r
dsvertLMMGLSTransformDS(
  data_name,
  columns,
  lambda_per_cluster,
  output_suffix = "_lmmtx",
  create_intercept = TRUE,
  intercept_col = "__dsvert_lmm_int",
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Aligned data frame on this server.

- columns:

  Character vector of columns to transform.

- lambda_per_cluster:

  Numeric vector of length `n_clusters` giving \\\lambda_i\\ (may
  include zeros for privacy-suppressed cluster ids).

- output_suffix:

  Suffix appended to the transformed column name. Default `"_lmmtx"`.
  Set to `""` to overwrite in place.

- create_intercept:

  Whether to add a \\(1 - \lambda_i)\\ column (per-observation). Default
  TRUE on the server that holds the cluster_col; only one server should
  create it (the rest have it relayed via PSI-aligned rows).

- intercept_col:

  Name for the created intercept column. Default `"__dsvert_lmm_int"`.

- session_id:

  MPC session id.

## Value

list(n, columns_transformed, intercept_col, n_clusters).
