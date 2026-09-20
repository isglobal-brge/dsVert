# Independent pure-R wide-integer oracle; never loaded by a protected route.
.grouped_sqrt_ratio_q64 <- function(num, den) {
  target <- .cross_shift_left(.cross_small(num), 128)
  denominator <- .cross_small(den)
  value <- .cross_int()
  for (bit in 65:0) {
    candidate <- .cross_add(value, .cross_pow2(bit))
    square <- .cross_mul(.cross_mul(candidate, candidate), denominator)
    if (.cross_cmp_abs(square, target) <= 0) value <- candidate
  }
  value
}

.grouped_gee_whitening_integer <- function(eta_q64, features_f50, outcome, live,
    family, correlation, rho, clip, cluster_cap, bread_cap, bits) {
  n <- length(live); d <- ncol(features_f50)+1L
  stopifnot(all(live %in% 0:1), rho %in% c(0,.25,.5))
  zero_matrix <- function(rows, cols) matrix(rep(list(.cross_int()), rows*cols), rows, cols)
  base <- zero_matrix(n,d+1L); W <- zero_matrix(n,n)
  total_loss <- .cross_int()
  for (i in which(live == 1)) {
    eta <- .cross_double(.cross_round_shift(.cross_parse(eta_q64[i]),48))
    x <- c(65536, vapply(features_f50[i,], function(v)
      .cross_double(.cross_round_shift(.cross_parse(v),34)), numeric(1)))
    if (family == "binomial") {
      mu <- .grouped_profile(eta,"sigmoid")
      a <- .grouped_profile(eta,"sqrt_variance")
      b <- .grouped_profile(eta,"inverse_sqrt_variance")
      loss <- .grouped_profile(eta,"softplus")-outcome[i]*eta
    } else {
      mu <- .grouped_profile(eta,"exp")
      a <- .grouped_profile(round(eta/2),"exp")
      b <- .grouped_profile(-round(eta/2),"exp")
      loss <- mu-outcome[i]*eta+c(0,0,45426,117425,208277)[outcome[i]+1L]
    }
    total_loss <- .cross_add(total_loss,.cross_shift_left(.cross_small(loss),16))
    for (k in seq_len(d)) base[[i,k]] <- .cross_mul(.cross_small(x[k]),.cross_small(a))
    base[[i,d+1L]] <- .cross_mul(.cross_small(outcome[i]*65536-mu),.cross_small(b))
  }
  idx <- which(live==1); m <- length(idx)
  if (m) {
    if (correlation == "independence") {
      for (i in idx) W[[i,i]] <- .cross_pow2(64)
    } else if (correlation == "exchangeable") {
      a <- .grouped_sqrt_ratio_q64(4,4-4*rho)
      b <- .grouped_sqrt_ratio_q64(4,4+(m-1)*4*rho)
      correction <- .grouped_div_even(.cross_sub(b,a),.cross_small(m))
      for (i in idx) for (j in idx) W[[i,j]] <- if (i==j) .cross_add(a,correction) else correction
    } else {
      W[[idx[1L],idx[1L]]] <- .cross_pow2(64)
      if (m>1) for (at in 2:m) {
        i <- idx[at]; prev <- idx[at-1L]; gap <- i-prev
        numerator <- (4*rho)^gap; denominator <- 4^gap
        a <- .grouped_sqrt_ratio_q64(denominator^2,denominator^2-numerator^2)
        W[[i,i]] <- a
        W[[i,prev]] <- .cross_neg(.grouped_div_even(
          .cross_mul(a,.cross_small(numerator)),.cross_small(denominator)))
      }
    }
  }
  factors <- zero_matrix(n,d+1L)
  for (i in seq_len(n)) for (k in seq_len(d+1L)) {
    sum <- .cross_int()
    for (j in seq_len(n)) sum <- .cross_add(sum,.cross_mul(W[[i,j]],base[[j,k]]))
    factors[[i,k]] <- .cross_round_shift(sum,32)
  }
  score <- numeric(d); bread <- meat <- numeric()
  for (k in seq_len(d)) {
    sum <- .cross_int()
    for (i in seq_len(n)) sum <- .cross_add(sum,.cross_mul(factors[[i,k]],factors[[i,d+1L]]))
    bound <- .cross_shift_left(.cross_small(clip),112)
    if (.cross_cmp_abs(sum,bound)>0) { bound$s <- sum$s; sum <- bound }
    score[k] <- .cross_double(.cross_round_shift(sum,112))
  }
  shift <- if (correlation=="independence") 0 else bread_cap
  for (l in seq_len(d)) for (k in seq_len(l)) {
    sum <- .cross_int()
    for (i in seq_len(n)) sum <- .cross_add(sum,.cross_mul(factors[[i,k]],factors[[i,l]]))
    bread <- c(bread,max(0,min(bread_cap+shift,
      .cross_double(.cross_round_shift(sum,128-bits))+shift)))
    meat <- c(meat,.cross_double(.cross_round_shift(.cross_small(score[k]*score[l]+clip^2),32-bits)))
  }
  c(max(0,min(cluster_cap,.cross_double(.cross_round_shift(total_loss,32-bits)))),bread,meat)
}
