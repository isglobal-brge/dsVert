# Cluster-size aggregate (for LMM / GEE)

Return a vector of cluster sizes for an ID column on the outcome server.
Only per-cluster counts leave the server; individual memberships are not
revealed to the client. Subject to the standard
`datashield.privacyLevel` suppression: clusters with fewer than the
privacy threshold are returned as 0.

## Usage

``` r
dsvertClusterSizesDS(data_name, cluster_col)
```

## Arguments

- data_name:

  Character. Aligned data-frame name.

- cluster_col:

  Character. Column holding the cluster id.

## Value

list(sizes: integer vector; n_clusters; n_total).
