# Full-regression theta-MLE score on label server (per-patient mu)

Computes Sum psi(y_i+theta), Sum psi_1(y_i+theta), Sum
log(theta/(theta+mu_i)), and its derivative Sum mu_i/(theta(theta+mu_i))
on the label server, using per-patient mu_i = exp(eta_i_total) where
eta_i_total is assembled from the label's own eta_i_label (computed from
local x_vars_label + client-supplied beta_label) plus the peer's sealed
eta_i^nl blob (previously stored via `mpcStoreBlobDS` under
`peer_eta_key`).

This replaces the iid-mu approximation in `dsvertNBProfileSumsDS` with
the true per-patient form. Empirically closes the ~16% -\> ~0% gap to
[`MASS::glm.nb`](https://rdrr.io/pkg/MASS/man/glm.nb.html) (AUDITORIA C:
`MASS::theta.ml(y, mu=fed_mu_per_patient)` matches glm.nb theta at rel
err 7e-5 on NHANES-subset).

Reveals to the client exactly five scalars per theta evaluation:
`sum_psi`, `sum_tri`, `sum_log_theta_ratio`, `sum_mu_ratio`, `n`. Same
disclosure class as the existing `dsvertNBProfileSumsDS`.

## Usage

``` r
dsvertNBFullScoreDS(
  data_name,
  y_var,
  x_vars_label,
  beta_values_label,
  beta_intercept,
  peer_eta_key,
  theta,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Data frame on the label server.

- y_var:

  Character. Outcome column.

- x_vars_label:

  Character. Feature cols held on the label server.

- beta_values_label:

  Numeric. beta-slice for those columns (client- provided from prior
  Poisson fit).

- beta_intercept:

  Numeric scalar. The fit's intercept (revealed).

- peer_eta_key:

  Character. Session slot holding the peer's transport-sealed `eta_nl`
  blob (set via `mpcStoreBlobDS`).

- theta:

  Numeric scalar \> 0.

- session_id:

  Character.

## Value

List of five numeric scalars.
