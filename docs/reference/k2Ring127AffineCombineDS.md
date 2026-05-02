# Ring127 affine combine – server-side local op for Horner/NR orchestration.

Computes, on one party's Ring127 shares: \$\$out\[i\] = sign_a \cdot
a\[i\] + sign_b \cdot b\[i\] + (public_const \text{ if party 0 else }
0)\$\$ where \\sign_a, sign_b \in \\-1, 0, +1\\\\. The result is stored
back into the session slot named `output_key`. No cross-party
communication – the client orchestrates one such call on each party per
Horner / NR iteration.

Called by `dsVertClient:::.exp127_round` and
`dsVertClient:::.recip127_round` (task \#116 step 5c(I-c)). Not
Ring63-applicable; fails fast if invoked in a session whose ring is not
127.

## Usage

``` r
k2Ring127AffineCombineDS(
  a_key = NULL,
  b_key = NULL,
  sign_a = 0L,
  sign_b = 0L,
  public_const_fp = NULL,
  is_party0 = FALSE,
  output_key,
  n,
  session_id = NULL
)
```

## Arguments

- a_key:

  Session slot holding the first Ring127 share vector (base64 Uint128 at
  16 B/elt). Ignored when `sign_a == 0`; may be `NULL` in that case.

- b_key:

  Session slot holding the second Ring127 share vector. Ignored when
  `sign_b == 0`.

- sign_a:

  Integer in {-1, 0, +1}. Sign coefficient for the a slot.

- sign_b:

  Integer in {-1, 0, +1}. Sign coefficient for the b slot.

- public_const_fp:

  Base64 string encoding a single Ring127 FP Uint128 (16 B). Added to
  every element on party 0 only. `NULL` for no constant.

- is_party0:

  Logical. TRUE for the coordinator (outcome-holder) party; controls
  whether `public_const_fp` is applied.

- output_key:

  Session slot name to store the resulting share vector.

- n:

  Integer vector length.

- session_id:

  MPC session identifier.

## Value

list(stored = TRUE, output_key, n).
