# Write a persistent key (adaptive: small -\> memory, large -\> disk)

Write a persistent key (adaptive: small -\> memory, large -\> disk)

## Usage

``` r
.key_put(name, value, ss)
```

## Arguments

- name:

  Character. Key name (e.g., "cpk", "secret_key")

- value:

  Character. Key data (single string or character vector)

- ss:

  Session environment
