# Identity link: set mu = eta (for Gaussian GLM)

Copies the eta share to the mu share in session storage. Used for
Gaussian family where mu = eta (no sigmoid/exp transformation).

## Usage

``` r
k2IdentityLinkDS(session_id = NULL)
```

## Arguments

- session_id:

  Character or NULL. Session identifier.

## Value

List with ok = TRUE.
