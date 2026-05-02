# Clean up session state

Removes all cryptographic material from server memory: transport keys,
Ring63 shares, DCF keys, and any residual protocol state. Called by the
client at the end of each protocol execution.

## Usage

``` r
mpcCleanupDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. Session identifier to clean up.

## Value

TRUE on success
