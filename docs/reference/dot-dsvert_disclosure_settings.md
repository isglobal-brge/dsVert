# MPC Utility Functions

Internal utility functions for calling the dsvert-mpc Go binary and
handling base64/base64url encoding conversions.

## Usage

``` r
.dsvert_disclosure_settings()
```

## Value

Named list with nfilter.tab, nfilter.glm, nfilter.subset, and
datashield.privacyLevel.

## Details

### Why base64url?

DataSHIELD passes function arguments through R's parser on the Opal/Rock
server. Standard base64 contains `+` and `/` characters that R's parser
can misinterpret in long strings (particularly in function call
arguments). Base64url replaces these with `-` and `_`, which are safe.
All data is converted to base64url for transit between client and
server, then back to standard base64 before passing to the Go binary
(which uses Go's standard base64 library).

### File-based I/O

The `.callMpcTool` function uses temporary files (not stdin/stdout
pipes) for JSON I/O because encrypted data can be hundreds of KB.
Pipe-based I/O can cause R's C stack to overflow with large outputs.
