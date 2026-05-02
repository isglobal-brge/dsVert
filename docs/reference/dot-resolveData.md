# Resolve a data frame by name, checking session storage first

Resolve a data frame by name, checking session storage first

## Usage

``` r
.resolveData(data_name, env, session_id = NULL)
```

## Arguments

- data_name:

  Character. Name of the data frame to find.

- env:

  Environment to search if not found in session storage (typically
  parent.frame() of caller).

- session_id:

  Character or NULL. Session identifier for session-scoped storage.

## Value

The data frame
