# Clear a registered offset for a session (server-side)

Remove any offset stored via
[`k2SetOffsetDS()`](https://isglobal-brge.github.io/dsVert/reference/k2SetOffsetDS.md)
so that subsequent eta computations fall back to plain X beta.

## Usage

``` r
k2ClearOffsetDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. GLM session identifier.

## Value

`list(cleared = TRUE)`
