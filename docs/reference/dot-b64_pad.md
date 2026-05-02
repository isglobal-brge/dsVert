# Restore base64 padding from base64url

Opal DSL parser chokes on `=`, `+` and `/` inside double-quoted string
literals. Client converts base64 -\> base64url; we restore standard
base64 via the already-existing `.base64url_to_base64` helper in
`mpcUtils.R` (documented since pre-session as the canonical "Opal/Rock
string parameter" workaround).

## Usage

``` r
.b64_pad(x)
```

## Arguments

- x:

  base64url-encoded string (or NULL / empty).

## Value

Standard base64 string with padding restored, or `x` unchanged if NULL /
empty.
