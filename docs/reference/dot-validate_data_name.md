# Validate that a data_name is a safe R identifier

Prevents command injection via eval(parse(text = ...)) by ensuring
data_name contains only letters, digits, dots, and underscores.

## Usage

``` r
.validate_data_name(data_name)
```

## Arguments

- data_name:

  Character. Name to validate.

## Value

TRUE if valid, otherwise stops with an error.
