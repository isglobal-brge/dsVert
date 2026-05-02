# Materialise r^2 as a column on the outcome server (GEE sandwich prep)

On the outcome server (which holds `y` plaintext), compute the Pearson
(Gaussian: plain) residual squared \\r_i^2 = (y_i - x_i^T \hat\beta -
\hat\beta_0)^2\\ using the plaintext `betahat` broadcast by the client,
and write the result into the aligned data frame under `r2_column`. Used
as the `weights=` column for the second-stage fit in `ds.vertGEE`, which
produces the Liang-Zeger meat matrix without ever materialising
\\n\\-length residuals on the client.

Only the outcome server participates; features on other servers are NOT
consulted here, because the fitted values \\x_i^T \hat\beta\\ only use
the `x_names` provided (which must all live on the outcome server for
the Gaussian sandwich to be tractable from this helper alone; a
cross-server r^2 needs a Beaver path that is part of Month 4).

## Usage

``` r
dsvertPearsonR2ColDS(
  data_name,
  y_var,
  x_names,
  betahat,
  intercept = 0,
  family = "gaussian",
  r2_column = "__dsvert_r2"
)
```

## Arguments

- data_name:

  Character.

- y_var:

  Outcome column.

- x_names:

  Character vector of predictor names that live on this server.

- betahat:

  Numeric vector of coefficients matching `x_names` (plaintext; the
  client broadcasts these).

- intercept:

  Scalar intercept (default 0).

- family:

  "gaussian" (default), "binomial", or "poisson". Controls the link +
  variance function used to form the Pearson residual.

- r2_column:

  Name of the new column (default "\_\_dsvert_r2").

## Value

list(n_observed, n_missing, method) – no per-patient values.
