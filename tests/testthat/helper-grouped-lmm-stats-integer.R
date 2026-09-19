# Pure-R integer oracle for the sufficient-statistic LMM profile. Test only.
.grouped_lmm_stats_integer <- function(rows, beta, sigma, tau, cap, bits) {
  beta <- lapply(beta, .cross_parse)
  sigma <- .cross_parse(sigma)
  tau <- .cross_parse(tau)
  inverse <- .grouped_div_even(.cross_pow2(128), sigma)
  total <- squares <- .cross_int()
  count <- 0
  for (row in rows) {
    row <- lapply(row, .cross_parse)
    if (!row[[1L]]$s) next
    count <- count + 1
    r <- .cross_shift_left(row[[length(row)]], 50)
    for (j in seq_along(beta)) r <- .cross_sub(r, .cross_mul(row[[j]], beta[[j]]))
    total <- .cross_add(total, r)
    squares <- .cross_add(squares, .cross_mul(r, r))
  }
  denominator <- .cross_mul(sigma, .cross_add(sigma, .cross_mul(tau, .cross_small(count))))
  lambda <- .grouped_div_even(.cross_shift_left(tau, 128), denominator)
  value <- .cross_sub(.cross_mul(squares, inverse),
    .cross_mul(.cross_mul(total, total), lambda))
  value <- .cross_round_shift(value, 264-bits)
  if (value$s < 0) value <- .cross_int()
  cap <- .cross_parse(as.character(cap))
  if (.cross_cmp_abs(value, cap) > 0) value <- cap
  .cross_format(value)
}
