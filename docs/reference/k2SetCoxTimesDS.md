# Register Cox survival times and sort the cohort (outcome server, stratified)

Read the time and event columns from the outcome server, determine the
ascending-time sort permutation locally, store the event indicator delta
as a plaintext FP vector for subsequent Cox-gradient primitives, and
return an encrypted blob (containing the permutation and the delta
vector) destined for the DCF peer so both parties can align their shares
with the sorted cohort.

Cox reformulated gradient:


      grad = sum over j with delta_j=1 of x_j  -  sum_j x_j exp(eta_j) G_j,
      G_j = sum over i with delta_i=1 and t_i <= t_j of 1 / S(t_i),
      S(t_i) = sum over k with t_k >= t_i of exp(eta_k).
      

After sorting by ascending t, S(t_i) is the REVERSE cumsum of exp(eta)
and G_j is a forward cumsum of delta / S. Both are local cumsums on
secret shares (k2-fp-cumsum primitive), so no new Beaver rounds are
introduced beyond the existing DCF exp + DCF reciprocal + triple-product
steps.

Inter-server disclosure: the DCF peer learns the sort permutation (i.e.,
the RANK order of event times) and the event indicator. Absolute event
times are not disclosed. This is a deliberate, documented leakage tier,
same class as cluster-ID in LMM; see V2_PROGRESS.md disclosure table.

## Usage

``` r
k2SetCoxTimesDS(
  data_name,
  time_column,
  event_column,
  peer_pk,
  session_id = NULL,
  strata_column = NULL,
  ring = NULL
)
```

## Arguments

- data_name:

  Aligned data frame on this server.

- time_column:

  Numeric time-to-event column (\>= 0).

- event_column:

  Binary event indicator (1 = event, 0 = censored).

- peer_pk:

  Transport X25519 public key of the DCF peer.

- session_id:

  GLM session id.

- strata_column:

  Character. Name of the stratification column for stratified Cox.

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.

## Value

list(peer_blob = \<encrypted permutation + delta\>, n = length)
