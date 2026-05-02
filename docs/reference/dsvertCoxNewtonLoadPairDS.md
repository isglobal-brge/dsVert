# Seed and prepare for the per-pair Beaver vecmul round

For a single Fisher pair (j, k), copy the column shares into the
canonical x_key/y_key slots that k2BeaverVecmulR1DS / R2DS expect. Two
variants: which = "X" -\> copy cox_n_Xc\_*fp -\> cox_n_Beaver_A_fp copy
cox_n_Xcfp -\> cox_n_Beaver_B_fp which = "S" -\> copy cox_n_Scfp -\>
cox_n_Beaver_A_fp copy cox_n_Sc*\_fp -\> cox_n_Beaver_B_fp After R1 +
R2, the Beaver z-share sits in cox_n_Beaver_Z_fp; the caller then runs
dsvertCoxNewtonFisherScalarDS to produce the scalar share for the chosen
term.

## Usage

``` r
dsvertCoxNewtonLoadPairDS(j, k, which = c("X", "S"), session_id = NULL)
```

## Arguments

- j, k:

  1-based column indices (canonical (own \| peer) order).

- which:

  "X" for first Fisher term, "S" for second.

- session_id:

  MPC session id.

## Value

list(stored = TRUE).
