# Cox residual share (DEPRECATED - use the 4-step Beaver orchestration)

Kept for backward compatibility. The single-call helper has been
superseded by the proper 2-round Beaver protocol orchestrated from the
client:

1.  dealer calls
    [`k2BeaverVecmulGenTriplesDS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulGenTriplesDS.md);

2.  each party calls
    [`k2BeaverVecmulConsumeTripleDS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulConsumeTripleDS.md);

3.  each party calls
    [`k2BeaverVecmulR1DS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulR1DS.md)
    with `x_key="k2_cox_mu_share_fp"`, `y_key="k2_cox_G_share_fp"`;

4.  each party calls
    [`k2BeaverVecmulR2DS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulR2DS.md)
    with `output_key="k2_cox_mu_g_share_fp"`;

5.  each party calls
    [`k2CoxFinaliseResidualDS`](https://isglobal-brge.github.io/dsVert/reference/k2CoxFinaliseResidualDS.md).

## Usage

``` r
k2CoxResidualDS(peer_pk = NULL, session_id = NULL)
```
