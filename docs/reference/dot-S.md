# Get or create a session-scoped storage environment

Returns the sub-environment for the given session_id. Creates it if it
does not exist. Requires a valid session_id.

## Usage

``` r
.S(session_id = NULL)
```

## Arguments

- session_id:

  Character. Session identifier (UUID).

## Value

An environment for storing session state.
