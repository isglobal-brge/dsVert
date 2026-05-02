# NL-side mirror: pin NL's eta_total share + cache n

Tiny helper invoked after `dsvertNBEtaShareDS` so the NL server's
session has the same canonical key (`k2_nb_eta_share_fp`, `k2_nb_eta_n`)
as the label side post-receive. NL's eta_total share already equals its
eta^nl share (NL contributes 0 to eta_label + beta_0); this function
just confirms the slot is populated.

## Usage

``` r
dsvertNBEtaShareConfirmDS(session_id = NULL)
```

## Arguments

- session_id:

  Character.

## Value

List with `stored` (TRUE if shares present; FALSE otherwise), `n`.
