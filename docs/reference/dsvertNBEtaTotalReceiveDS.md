# Label-side: receive NL's eta^nl share + assemble eta_total share

Decrypts the relayed Ring127 share blob from the non-label server
(label's share of eta^nl), then computes the label's own contribution
eta_label + beta_0 plaintext from local x_vars + client- supplied
beta_label slice + intercept, FP-encodes it, and adds to the received
share via `k2-fp-add`. The result stored under `ss$k2_nb_eta_share_fp`
is the label's Ring127 share of eta_total = eta^nl + eta_label + beta_0.

Sum across parties: \$\$\eta^{\mathrm{NL}}\_{\mathrm{share}} +
(\eta^{\mathrm{label}}\_{\mathrm{share}} + (\eta\_{\mathrm{label}} +
\beta_0)\_{\mathrm{FP}}) = \eta^{\mathrm{nl}} + \eta\_{\mathrm{label}} +
\beta_0 = \eta\_{\mathrm{total}}\$\$ OK correct reconstruction.

Caches y for later `Sumpsi(y+theta)` computation under `ss$k2_nb_y`.

## Usage

``` r
dsvertNBEtaTotalReceiveDS(
  data_name,
  y_var,
  x_vars_label,
  beta_values_label,
  beta_intercept,
  peer_eta_share_blob_key,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character.

- y_var:

  Character. Outcome column.

- x_vars_label:

  Character. Label-held feature column names.

- beta_values_label:

  Numeric. beta-slice for those columns.

- beta_intercept:

  Numeric scalar. Intercept (revealed at convergence).

- peer_eta_share_blob_key:

  Character. Session blob slot holding the relayed Ring127 share blob
  from the NL server.

- session_id:

  Character.

## Value

List with `stored = TRUE`, `n`.
