# Reorder X_full columns to canonical order on fusion party

After k2ComputeEtaShareDS, the fusion party's X_full has column order
`(coord | extras | fusion)`. This reorders to canonical
`(coord | fusion | extras)` to match the coordinator's order, ensuring
Beaver gradient works correctly.

## Usage

``` r
glmRing63ReorderXFullDS(p_coord, p_fusion, p_extras, session_id = NULL)
```

## Arguments

- p_coord:

  Integer. Number of coordinator features.

- p_fusion:

  Integer. Number of fusion features.

- p_extras:

  Integer. Number of extra (non-DCF) features.

- session_id:

  Character or NULL.

## Value

List with status.
