# Standardize Features for GLM (Server-Side)

Standardizes specified columns of a data frame (center + scale) and
stores the result as a new data frame. Returns column means and standard
deviations for the client to unstandardize coefficients after
convergence. For Gaussian family, also standardizes the response
variable.

## Usage

``` r
glmStandardizeDS(
  data_name,
  output_name,
  x_vars,
  y_var = NULL,
  session_id = NULL,
  skip_standardize = FALSE,
  mode = "full"
)
```

## Arguments

- data_name:

  Character. Name of the source data frame.

- output_name:

  Character. Name for the standardized data frame.

- x_vars:

  Character vector. Feature columns to standardize.

- y_var:

  Character or NULL. Response variable to standardize (Gaussian only).

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage.

- skip_standardize:

  Logical. If TRUE, skip server-side standardisation (used by callers
  that pre-standardised).

- mode:

  Character. Operation mode (e.g. `"rss"` or `"canonical"`).

## Value

List with x_means, x_sds, y_mean (if y_var), y_sd (if y_var)
