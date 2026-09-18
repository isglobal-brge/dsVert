# Pure-R test oracle. Uses the frozen signed base-2^15 helper arithmetic, with
# no floating-point large products and no native arbitrary-precision dependency.
.cross_nb_softplus <- function(shifted_eta, profile) {
  x <- .cross_width(.cross_round_shift(shifted_eta, 48), 32)
  magnitude <- x; magnitude$s <- abs(x$s)
  a <- .cross_double(magnitude)
  residual <- .cross_int()
  if (a < profile$residual_tail_start_q16) {
    piece <- floor(a / profile$piece_width_q16) + 1L
    r <- .cross_small(a %% profile$piece_width_q16)
    coefficients <- lapply(profile$softplus_quadratic_q16[[piece]], .cross_parse)
    first <- .cross_round_shift(.cross_width(.cross_mul(coefficients[[3L]], r), 64), 16)
    second <- .cross_round_shift(.cross_width(.cross_mul(
      .cross_add(coefficients[[2L]], first), r), 64), 16)
    residual <- .cross_add(coefficients[[1L]], second)
  }
  positive <- if (x$s > 0) x else .cross_int()
  .cross_shift_left(.cross_width(.cross_add(positive, residual), 32), 48)
}

.cross_nb_reference_batch <- function(features, outcome, validity, beta, caps,
                                      theta_exponents, g, profile,
                                      max_outcome = 1024) {
  stopifnot(g %in% 8:18, length(features) == length(outcome),
            nrow(validity) == length(outcome), all(validity %in% c(0, 1)),
            all(outcome == floor(outcome)), all(outcome >= 0),
            all(outcome <= max_outcome), max_outcome %in% 1:1024,
            length(beta) == length(caps), length(beta) == length(theta_exponents),
            all(theta_exponents %in% -3:7))
  tables <- profile$theta
  beta <- lapply(beta, function(row) lapply(row, .cross_parse))
  for (row in beta) {
    total <- .cross_int()
    for (value in row) {
      stopifnot(.cross_cmp_abs(value, .cross_pow2(53)) <= 0)
      value$s <- abs(value$s); total <- .cross_add(total, value)
    }
    limit <- .cross_add(.cross_pow2(54), .cross_small(ceiling(length(row) / 2)))
    stopifnot(.cross_cmp_abs(total, limit) <= 0)
  }
  totals <- lapply(caps, function(x) .cross_int())
  for (i in seq_along(features)) {
    x <- lapply(features[[i]], .cross_parse)
    stopifnot(length(x) == ncol(validity) - 1L, length(x) %in% 1:16)
    for (value in x) stopifnot(value$s >= 0,
                               .cross_cmp_abs(value, .cross_pow2(50)) <= 0)
    for (j in seq_along(beta)) {
      stopifnot(length(beta[[j]]) == length(x) + 1L)
      table <- tables[[theta_exponents[j] + 4L]]
      stopifnot(table$exponent == theta_exponents[j])
      eta <- .cross_eta(x, beta[[j]])
      soft <- .cross_nb_softplus(.cross_sub(eta, .cross_parse(table$log_theta_q64)), profile)
      weighted <- .cross_round_shift(.cross_width(.cross_mul(soft,
        .cross_small(8 * outcome[i] + table$theta_times_eight)), 192), 3)
      loss <- .cross_sub(.cross_add(.cross_parse(table$constant_q64[[outcome[i] + 1L]]), weighted),
                         .cross_mul(.cross_small(outcome[i]), eta))
      if (!all(validity[i, ] == 1)) loss <- .cross_int()
      cap <- .cross_parse(caps[j])
      stopifnot(cap$s >= 0, .cross_cmp_abs(cap, .cross_small(2^53 - 1)) <= 0)
      totals[[j]] <- .cross_add(totals[[j]], .cross_quantize(loss, cap, g))
    }
  }
  vapply(totals, .cross_format, character(1L))
}

.cross_nb_reference_row <- function(eta_q64, outcome, valid, theta_exponent,
                                    g, cap, profile) {
  stopifnot(outcome %in% 0:1024, is.logical(valid), length(valid) == 1L,
            !is.na(valid), theta_exponent %in% -3:7, g %in% 8:18)
  eta <- .cross_parse(eta_q64)
  stopifnot(.cross_cmp_abs(eta, .cross_add(.cross_pow2(68), .cross_small(270337))) <= 0)
  table <- profile$theta[[theta_exponent + 4L]]
  soft <- .cross_nb_softplus(.cross_sub(eta, .cross_parse(table$log_theta_q64)), profile)
  weighted <- .cross_round_shift(.cross_width(.cross_mul(soft,
    .cross_small(8 * outcome + table$theta_times_eight)), 192), 3)
  loss <- .cross_sub(.cross_add(.cross_parse(table$constant_q64[[outcome + 1L]]), weighted),
                     .cross_mul(.cross_small(outcome), eta))
  if (!valid) loss <- .cross_int()
  .cross_format(.cross_quantize(loss, .cross_parse(cap), g))
}
