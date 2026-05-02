# Server-side Bayesian-ridge imputation of a single column

Draw a Bayesian-ridge posterior predictive imputation for the missing
cells of a column, using the other complete-case columns of the aligned
data frame as predictors. The imputed column is written back into the
data frame under `output_column`. The client never sees the imputed
values; only an aggregate "n imputed" count.

Fits a Bayesian ridge regression with default hyperparameters \\\alpha_0
= 1, \beta_0 = 1\\, draws a posterior sample \\(\beta^\*,
\sigma^{2\*})\\, and imputes each missing cell as \\x\_\ast^T \beta^\* +
\sigma^\* \epsilon\\, \\\epsilon \sim N(0, 1)\\.

For categorical `impute_column`: fits a logistic / multinomial ridge
classifier and samples from the posterior predictive class distribution.
(First pass: supports numeric and binary factor columns; K\>2 factor
support is Month 4.)

## Usage

``` r
dsvertImputeColumnDS(data_name, impute_column, output_column = NULL, seed = 1L)
```

## Arguments

- data_name:

  Character. Aligned data-frame name.

- impute_column:

  Character. Column with missingness.

- output_column:

  Character. Name under which the imputed column is written.

- seed:

  Integer. RNG seed for reproducible draws.

## Value

List with components `n_imputed` (count of cells imputed), `n_observed`
(count with non-missing original values), `method` ("bayesian_ridge" or
"bayesian_logit").
