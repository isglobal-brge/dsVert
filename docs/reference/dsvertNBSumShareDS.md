# Both-side: scalar share sum reveal helper

Reads a Ring127 share vector from session under `input_key`, computes
its modular sum via `k2-fp-sum`, returns the scalar share. Caller adds
the two server's `sum_share_fp` via `k2-ring63-aggregate` (which routes
to the Ring127 modular-add path when `ring="ring127"`) to reconstruct
the float scalar.

Disclosure: this is the standard final-reveal step at the K=2 audit
boundary. Only the scalar SUM is revealed (per-element shares stay
uniform random and are NOT exposed).

## Usage

``` r
dsvertNBSumShareDS(input_key, session_id = NULL)
```

## Arguments

- input_key:

  Character. Session slot holding the Ring127 share vector to reduce.

- session_id:

  Character.

## Value

List with `sum_share_fp` (base64url Uint128 scalar share), `n`.
