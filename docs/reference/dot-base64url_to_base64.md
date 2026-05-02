# Convert base64url to standard base64

Converts base64url encoding (URL-safe) to standard base64. This is
needed because R's parser on Opal/Rock has issues with "/" and "+"
characters in long strings passed as function parameters.

## Usage

``` r
.base64url_to_base64(x)
```

## Arguments

- x:

  Character string in base64url encoding

## Value

Character string in standard base64 encoding
