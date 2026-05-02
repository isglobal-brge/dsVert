# NB Method-of-Moments aggregate sufficient statistics

Returns the four scalar y-sufficient statistics needed to compute the
iid-mu Method-of-Moments theta-estimator (Anscombe 1950 Biometrika
37(3-4):358-382; Saha & Paul 2005 Biometrics 61(1):179-185 Sec.3
reduction under common-mu). All outputs are functions of y alone (no mu
or beta disclosure), revealing 4 floats per call (Sumy, Sumy^2, n,
ybar). Disclosure budget is the SAME as `dsvertNBProfileSumsDS` – y
aggregates only; ZERO new disclosure beyond the existing iid-mu path.

Under common-mu (mu == ybar), the regression-aware Saha-Paul 2005 moment
equation reduces to the Anscombe 1950 sample-moment form theta_MoM =
ybar^2 / (s^2 - ybar) where s^2 = (Sumy^2 - n\*ybar^2)/(n-1) is the
bias-corrected sample variance. Closed form – no Newton iteration on
theta. The iid-mu approximation propagates through both estimators
(iid-mu MLE and iid-mu MoM) with the same structural bias direction;
full-regression MoM (Saha-Paul Method 2 with per-patient mu_i) requires
eta at OS, currently outside the K=2-safe disclosure budget.

## Usage

``` r
dsvertNBMomentSumsDS(data_name, variable)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- variable:

  Character. Name of the non-negative integer outcome.

## Value

List with `n_total`, `sum_y`, `sum_y_sq`, `y_mean`, `y_var`.

## See also

`ds.vertNBMoMTheta`, `dsvertNBProfileSumsDS`
