# Cox-gradient second-term computation using reverse/forward cumsums

Given a secret-shared exp(eta) vector (ss\$secure_mu_share after the
wide-spline exp pass) already permuted to ascending-time order, compute
shares of:


      S(i) = sum over k >= i of exp(eta_k)              (reverse cumsum)
      G(j) = sum over i with delta_i=1 and i <= j of    (forward cumsum
             1 / S(i)                                    of delta*recip)
      

and store S and G in the session as k2_cox_S_share_fp and
k2_cox_G_share_fp. These are reused by the gradient reduction step that
forms x_j \* exp(eta_j) \* G_j and sums over j.

NOTE: the reciprocal-on-shares step is delegated to the 4-phase
k2-wide-spline-full protocol with family="reciprocal" (wired in commit
75f6883); callers orchestrate that phase first and pass the resulting
1/S share back in via k2StoreCoxRecipDS.

## Usage

``` r
k2CoxReverseCumsumSDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(S_length, G_length)
