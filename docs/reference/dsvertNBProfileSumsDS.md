# NB profile-MLE score sums for dispersion theta (aggregate)

Compute scalar sums needed to evaluate the profile log-likelihood score
and its derivative for the negative-binomial dispersion parameter theta
at a given theta value. The outcome variable is held in plaintext by a
single (label) server; this function returns four scalar aggregates
computed on that plaintext – no per-patient disclosure.

The NB(mu, theta) log-likelihood, assuming a common mean mu, has score
dell/dtheta = Sum_i psi(y_i + theta) - n psi(theta) + n
log(theta/(ybar + theta)) and Fisher-like curvature -d^2ell/dtheta^2
approx -(Sum_i psi_1(y_i + theta) - n psi_1(theta)) - n \* (1/theta -
1/(ybar + theta)) where psi is the digamma function and psi_1 its
derivative (trigamma). This is the Anscombe / Lawless parametrisation
used by [`MASS::theta.ml`](https://rdrr.io/pkg/MASS/man/theta.md.html),
specialised to the homogeneous-mu case so that the outcome server does
not need any beta / eta quantities – only its own y plus a client-chosen
scalar theta.

Reveals exactly four floats per call: Sumpsi(y+theta),
Sumpsi_1(y+theta), n, ybar. All are already-aggregate functions of y.
The caller iterates theta client-side via Newton-Raphson.

## Usage

``` r
dsvertNBProfileSumsDS(data_name, variable, theta)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- variable:

  Character. Name of the non-negative integer outcome.

- theta:

  Numeric scalar. Candidate dispersion value (\> 0).

## Value

A list with four numeric scalars:

- `sum_psi`: Sum psi(y_i + theta)

- `sum_tri`: Sum psi_1(y_i + theta)

- `n_total`: count of non-missing observations

- `y_mean`: sample mean of y (ybar)

Returned as `NA_real_` if the cohort falls below the
`datashield.privacyLevel` threshold.

## See also

`dsvertLocalMomentsDS`, `ds.vertNB`, `dsvertNBMomentSumsDS`
