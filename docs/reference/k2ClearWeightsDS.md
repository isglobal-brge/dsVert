# Clear registered weights from a session

Remove the cached weights vector so subsequent iterations fall back to
unweighted GLM. Safe no-op if no weights were registered.

## Usage

``` r
k2ClearWeightsDS(session_id = NULL)
```

## Arguments

- session_id:

  Character.

## Value

`list(cleared = TRUE)`
