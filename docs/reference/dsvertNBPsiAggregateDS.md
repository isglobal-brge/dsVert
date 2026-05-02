# Label-side: plaintext Sumpsi(y+theta) and Sumpsi_1(y+theta)

The score / Hessian terms involving psi(y_i + theta) and psi_1(y_i +
theta) (digamma / trigamma) only require y at label and theta as a
scalar – no mu_i shares needed. Computed plaintext at label and returned
as scalars. No per-patient disclosure (only the two sums).

## Usage

``` r
dsvertNBPsiAggregateDS(theta, session_id = NULL)
```

## Arguments

- theta:

  Numeric scalar.

- session_id:

  Character.

## Value

List with `sum_psi`, `sum_tri`, `n`.
