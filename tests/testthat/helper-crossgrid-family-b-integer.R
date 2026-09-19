# Independent pure-R base-2^15 integer oracle. Depends only on the frozen
# test helper's limb arithmetic, never on a production cleartext evaluator.
.family_b_divround <- function(a, b) {
  stopifnot(b$s > 0)
  sign_a <- a$s
  a$s <- abs(a$s)
  quotient <- .cross_int()
  powers <- list(.cross_small(1))
  divisors <- list(b)
  while (.cross_cmp_abs(tail(divisors, 1L)[[1L]], a) <= 0) {
    divisors[[length(divisors) + 1L]] <- .cross_shift_left(tail(divisors, 1L)[[1L]], 1)
    powers[[length(powers) + 1L]] <- .cross_shift_left(tail(powers, 1L)[[1L]], 1)
  }
  for (i in rev(seq_along(divisors))) {
    if (.cross_cmp_abs(a, divisors[[i]]) >= 0) {
      a <- .cross_sub(a, divisors[[i]])
      quotient <- .cross_add(quotient, powers[[i]])
    }
  }
  comparison <- .cross_cmp_abs(.cross_shift_left(a, 1), b)
  if (comparison > 0 || (comparison == 0 && quotient$d[1L] %% 2 == 1)) {
    quotient <- .cross_add(quotient, .cross_small(1))
  }
  quotient$s <- quotient$s * sign_a
  quotient
}

.family_b_logq <- function(value) {
  stopifnot(value$s > 0)
  bits <- 15 * (length(value$d) - 1L) + floor(log2(tail(value$d, 1L))) + 1
  exponent <- bits - 65
  mantissa <- .cross_round_shift(value, exponent)
  one <- .cross_pow2(64)
  z <- .family_b_divround(.cross_shift_left(.cross_sub(mantissa, one), 64),
    .cross_add(mantissa, one))
  z2 <- .cross_qmul(z, z)
  term <- total <- z
  for (k in 1:23) {
    term <- .cross_qmul(term, z2)
    total <- .cross_add(total, .cross_round_divsmall(term, 2 * k + 1))
  }
  .cross_add(.cross_shift_left(total, 1), .cross_mul(.cross_small(exponent),
    .cross_parse("12786308645202655660")))
}

.family_b_expq <- function(eta, coefficients) {
  value <- .cross_chebyshev(eta, coefficients)
  value <- .cross_qmul(value, value)
  .cross_qmul(value, value)
}

# Protected nonlinearities use only these signed 32-bit q16 words. Products
# are exact R doubles (<2^53); the quotient/remainder rule is integer-only.
.family_b_piecewise_profile <- function() {
  jsonlite::fromJSON(system.file("cross-grid-family-b", "piecewise_profile_v1.json",
    package = "dsVert"), simplifyVector = FALSE)$profile
}
.family_b_round_word <- function(value, shift) {
  stopifnot(is.finite(value), value == floor(value), abs(value) < 2^53)
  if (shift <= 0) return(value * 2^(-shift))
  magnitude <- abs(value); divisor <- 2^shift
  quotient <- floor(magnitude / divisor)
  remainder <- magnitude - quotient * divisor
  if (2 * remainder > divisor ||
      (2 * remainder == divisor && quotient %% 2 == 1)) quotient <- quotient + 1
  sign(value) * quotient
}
.family_b_piecewise <- function(value, table) {
  lower <- table$lower_q16; step <- table$step_q16
  stopifnot(value >= lower, value <= lower + 64 * step,
    value == floor(value))
  piece <- min(63, floor((value - lower) / step))
  t <- value - lower - piece * step
  coefficient <- unlist(table$coefficients_c_b_a_q16[[piece + 1L]])
  stopifnot(abs(coefficient[3L] * t) < 2^31)
  inner <- coefficient[2L] + .family_b_round_word(coefficient[3L] * t, 16)
  stopifnot(abs(inner * t) < 2^31)
  answer <- coefficient[1L] + .family_b_round_word(inner * t, 16)
  stopifnot(abs(inner) < 2^31, abs(answer) < 2^31)
  answer
}
.family_b_exp16 <- function(value, profile) {
  stopifnot(value <= 0, value >= -32 * 65536)
  if (value == 0) return(65536)
  if (value < -16 * 65536) return(0)
  .family_b_piecewise(value, profile$tables$exp)
}
.family_b_log16 <- function(value, profile) {
  stopifnot(value >= 65536, value <= 8 * 65536)
  exponent <- 0
  while (value >= 65536 * 2^(exponent + 1L)) exponent <- exponent + 1L
  mantissa <- .family_b_round_word(value, exponent)
  .family_b_piecewise(mantissa, profile$tables$log) + exponent * profile$log2_q16
}
.family_b_soft16 <- function(value, profile) {
  stopifnot(abs(value) <= 16 * 65536)
  max(value, 0) + .family_b_piecewise(abs(value), profile$tables$softminus)
}
.family_b_eta16 <- function(features, beta) {
  value <- .cross_shift_left(beta[[1L]], 50)
  for (k in seq_along(features)) {
    value <- .cross_add(value, .cross_mul(features[[k]], beta[[k + 1L]]))
  }
  .cross_double(.cross_round_shift(.cross_width(value, 192), 84))
}
.family_b_public_gap16 <- function(lower, upper, coefficients) {
  gap <- .cross_shift_left(.cross_sub(upper, lower), 14)
  # High precision is restricted to candidate-signed public metadata. No
  # protected predictor reaches this legacy public gap-constant helper.
  loggap <- .family_b_logq(.cross_sub(.cross_pow2(64),
    .family_b_expq(.cross_neg(gap), coefficients)))
  .cross_double(.cross_round_shift(loggap, 48))
}
.family_b_integer_losses <- function(spec, features, outcome, validity,
    profile = .family_b_piecewise_profile()) {
  stopifnot(spec$family %in% c("multinomial", "ordinal"),
    length(features) == length(outcome), nrow(validity) == length(outcome),
    ncol(validity) == length(spec$predictor_order) + 1L,
    all(validity %in% c(0, 1)), all(outcome == floor(outcome)),
    all(outcome >= 0 & outcome < spec$class_count))
  public_gaps <- NULL
  if (spec$family == "ordinal") {
    public_profile <- jsonlite::fromJSON(system.file("cross-grid-v1", "numeric_profile_v1.json",
      package = "dsVert"), simplifyVector = FALSE)$profile
    coefficients <- lapply(public_profile$exp_quarter_coefficients_q64, .cross_parse)
    stopifnot(length(coefficients) == 33L)
    public_gaps <- lapply(spec$candidate_encoded, function(candidate) {
      thresholds <- lapply(candidate$thresholds, .cross_parse)
      if (length(thresholds) < 2L) return(numeric())
      vapply(seq_len(length(thresholds) - 1L), function(k) {
        .family_b_public_gap16(thresholds[[k]], thresholds[[k + 1L]], coefficients)
      }, numeric(1L))
    })
  }
  caps <- vapply(spec$sensitivity$candidate_bounds, `[[`, numeric(1L), "per_patient_cap")
  totals <- lapply(caps, function(x) .cross_int())
  for (i in seq_along(features)) {
    x <- lapply(features[[i]], .cross_parse)
    stopifnot(length(x) == length(spec$predictor_order))
    for (value in x) stopifnot(value$s >= 0,
      .cross_cmp_abs(value, .cross_pow2(50)) <= 0)
    for (j in seq_along(totals)) {
      if (spec$family == "multinomial") {
        beta <- lapply(spec$beta_encoded[[j]], .cross_parse)
        dimension <- length(x) + 1L
        eta <- vapply(seq_len(spec$class_count - 1L), function(k) {
          .family_b_eta16(x, beta[seq.int((k - 1L) * dimension + 1L, k * dimension)])
        }, numeric(1L))
        maximum <- max(0, eta)
        total <- sum(vapply(c(0, eta) - maximum, .family_b_exp16,
          numeric(1L), profile = profile))
        loss <- maximum + .family_b_log16(total, profile)
        label <- spec$class_order[[outcome[i] + 1L]]
        index <- match(label, unlist(spec$non_reference_order))
        if (!is.na(index)) loss <- loss - eta[index]
      } else {
        candidate <- spec$candidate_encoded[[j]]
        eta <- .family_b_eta16(x, lapply(candidate$beta, .cross_parse))
        encoded_thresholds <- lapply(candidate$thresholds, .cross_parse)
        thresholds <- vapply(encoded_thresholds, function(value) {
          .cross_double(.cross_round_shift(value, 34))
        }, numeric(1L))
        arguments <- thresholds - eta
        y <- outcome[i]
        if (y == 0) {
          loss <- .family_b_soft16(arguments[1L], profile) - arguments[1L]
        } else if (y == spec$class_count - 1L) {
          loss <- .family_b_soft16(tail(arguments, 1L), profile)
        } else {
          hi <- arguments[y + 1L]; lo <- arguments[y]
          gap_log <- public_gaps[[j]][y]
          loss <- .family_b_soft16(hi, profile) + .family_b_soft16(lo, profile) - hi - gap_log
        }
      }
      if (!all(validity[i, ] == 1)) loss <- 0
      # Lift exactly to the frozen quantizer; q16->g>=16 has no rounding.
      raw <- .cross_quantize(.cross_shift_left(.cross_small(loss), 48),
        .cross_small(caps[j]), spec$numeric_grid_bits)
      totals[[j]] <- .cross_add(totals[[j]], raw)
    }
  }
  vapply(totals, .cross_format, character(1L))
}
