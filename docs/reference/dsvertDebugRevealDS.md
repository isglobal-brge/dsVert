# Debug-only server reveal of session share slot (task \#116 G)

Returns the FP share stored at `slot_key` in the current session. Used
by ds.vertCox diagnostic hook to enable client-side aggregation +
plaintext comparison of Path B intermediate quantities (mu, S, 1/S, G,
muG, residual). NOT intended for production analysis flows – revealing a
session share is a disclosure-trust decision and only appropriate in
diagnostic sessions where the analyst is the protocol designer.

**SERVER-SIDE GATE (task \#113 P3 audit)**: the function is listed in
`AggregateMethods`, so any authorized DS analyst can call it via
`datashield.aggregate`. By itself a single share is info-theoretically
random, but combining both servers' shares reconstructs per-observation
plaintext. To prevent this in production deployments, this function
refuses to execute unless the env var `DSVERT_DEBUG_REVEAL_ALLOW=1` is
set on the server R session. Default (unset) -\> the call stops with a
clear error; production deployments therefore remain 0-bit per-obs.

## Usage

``` r
dsvertDebugRevealDS(slot_key = NULL, session_id = NULL)
```

## Arguments

- slot_key:

  Character. Name of the session slot to fetch.

- session_id:

  Character. MPC session id.

## Value

list(share_fp = base64 FP vector, slot_key, length).
