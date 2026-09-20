# Test-only signed integers, base 2^15. Every limb operation is exact in R.
# No package, native code, or floating-point large product is used.
.cross_int <- function(d = 0, s = 1) {
  while (length(d) > 1L && tail(d, 1L) == 0) d <- head(d, -1L)
  list(d = as.numeric(d), s = if (all(d == 0)) 0 else s)
}
.cross_cmp_abs <- function(a, b) {
  if (length(a$d) != length(b$d)) return(sign(length(a$d) - length(b$d)))
  for (i in rev(seq_along(a$d))) if (a$d[i] != b$d[i]) {
    return(sign(a$d[i] - b$d[i]))
  }
  0
}
.cross_neg <- function(a) { a$s <- -a$s; a }
.cross_add <- function(a, b) {
  if (!a$s) return(b)
  if (!b$s) return(a)
  if (a$s != b$s) {
    if (.cross_cmp_abs(a, b) < 0) return(.cross_add(b, a))
    d <- a$d; carry <- 0
    for (i in seq_along(d)) {
      v <- d[i] - if (i <= length(b$d)) b$d[i] else 0
      v <- v - carry; carry <- as.numeric(v < 0)
      d[i] <- v + carry * 32768
    }
    return(.cross_int(d, a$s))
  }
  d <- numeric(max(length(a$d), length(b$d)) + 1L); carry <- 0
  for (i in seq_len(length(d) - 1L)) {
    v <- carry + if (i <= length(a$d)) a$d[i] else 0
    v <- v + if (i <= length(b$d)) b$d[i] else 0
    d[i] <- v %% 32768; carry <- floor(v / 32768)
  }
  d[length(d)] <- carry
  .cross_int(d, a$s)
}
.cross_sub <- function(a, b) .cross_add(a, .cross_neg(b))
.cross_mul <- function(a, b) {
  d <- numeric(length(a$d) + length(b$d))
  for (i in seq_along(a$d)) for (j in seq_along(b$d)) {
    d[i+j-1L] <- d[i+j-1L] + a$d[i] * b$d[j]
  }
  for (i in seq_len(length(d) - 1L)) {
    d[i+1L] <- d[i+1L] + floor(d[i] / 32768)
    d[i] <- d[i] %% 32768
  }
  .cross_int(d, a$s * b$s)
}
.cross_small <- function(n) {
  stopifnot(length(n) == 1L, is.finite(n), n == floor(n), abs(n) <= 2^53)
  d <- numeric(); s <- sign(n); n <- abs(n)
  repeat {
    d <- c(d, n %% 32768); n <- floor(n / 32768)
    if (!n) break
  }
  .cross_int(d, s)
}
.cross_parse <- function(text) {
  stopifnot(is.character(text), length(text) == 1L,
            grepl("^(0|-?[1-9][0-9]*)$", text))
  s <- if (startsWith(text, "-")) -1 else 1
  digits <- utf8ToInt(sub("^-", "", text)) - 48L
  value <- .cross_int()
  for (digit in digits) {
    value <- .cross_add(.cross_mul(value, .cross_small(10)), .cross_small(digit))
  }
  value$s <- value$s * s
  value
}
.cross_divsmall <- function(a, divisor) {
  stopifnot(divisor > 0, divisor <= 32768, divisor == floor(divisor))
  d <- a$d; remainder <- 0
  for (i in rev(seq_along(d))) {
    v <- remainder * 32768 + d[i]
    d[i] <- floor(v / divisor); remainder <- v %% divisor
  }
  list(q = .cross_int(d, a$s), r = remainder)
}
.cross_format <- function(a) {
  if (!a$s) return("0")
  s <- a$s; a$s <- 1; digits <- character()
  while (a$s) {
    qr <- .cross_divsmall(a, 10); a <- qr$q
    digits <- c(as.character(qr$r), digits)
  }
  paste0(if (s < 0) "-" else "", paste0(digits, collapse = ""))
}
.cross_shift_left <- function(a, bits) {
  stopifnot(bits >= 0, bits == floor(bits))
  if (!a$s) return(a)
  a <- .cross_mul(a, .cross_small(2^(bits %% 15)))
  .cross_int(c(rep(0, bits %/% 15), a$d), a$s)
}
.cross_pow2 <- function(bits) .cross_shift_left(.cross_small(1), bits)
.cross_round_shift <- function(a, bits) {
  if (bits <= 0) return(.cross_shift_left(a, -bits))
  s <- a$s; a$s <- abs(s)
  whole <- bits %/% 15; partial <- bits %% 15
  q <- if (whole >= length(a$d)) .cross_int() else {
    .cross_divsmall(.cross_int(a$d[seq.int(whole+1L, length(a$d))]), 2^partial)$q
  }
  r <- .cross_sub(a, .cross_shift_left(q, bits))
  cmp <- .cross_cmp_abs(r, .cross_pow2(bits-1L))
  if (cmp > 0 || (cmp == 0 && q$d[1L] %% 2 == 1)) {
    q <- .cross_add(q, .cross_small(1))
  }
  q$s <- q$s * s
  q
}
.cross_round_divsmall <- function(a, divisor) {
  qr <- .cross_divsmall(a, divisor)
  if (2 * qr$r > divisor ||
      (2 * qr$r == divisor && qr$q$d[1L] %% 2 == 1)) {
    qr$q <- .cross_add(qr$q, .cross_small(if (a$s < 0) -1 else 1))
  }
  qr$q
}
.cross_double <- function(a) a$s * sum(a$d * 32768^(seq_along(a$d)-1L))
.cross_width <- function(a, bits) {
  stopifnot(.cross_cmp_abs(a, .cross_pow2(bits-1L)) < 0)
  a
}
.cross_qmul <- function(a, b, twice = FALSE) {
  product <- .cross_mul(a, b)
  if (twice) product <- .cross_shift_left(product, 1)
  .cross_round_shift(.cross_width(product, 192), 64)
}
.cross_chebyshev <- function(eta, coefficients) {
  t <- .cross_round_divsmall(eta, 17)
  b1 <- .cross_int(); b2 <- .cross_int()
  for (i in rev(seq.int(2L, length(coefficients)))) {
    value <- .cross_add(coefficients[[i]],
                       .cross_sub(.cross_qmul(t, b1, TRUE), b2))
    b2 <- b1; b1 <- .cross_width(value, 128)
  }
  .cross_width(.cross_add(coefficients[[1L]],
                          .cross_sub(.cross_qmul(t, b1), b2)), 128)
}
.cross_eta <- function(features, beta) {
  value <- .cross_shift_left(beta[[1L]], 50)
  for (k in seq_along(features)) {
    value <- .cross_add(value, .cross_mul(features[[k]], beta[[k+1L]]))
  }
  .cross_round_shift(.cross_width(value, 192), 36)
}
.cross_quantize <- function(loss, cap, g) {
  if (loss$s < 0) loss <- .cross_int()
  upper <- .cross_shift_left(cap, 64-g)
  if (.cross_cmp_abs(loss, upper) > 0) loss <- upper
  .cross_round_shift(loss, 64-g)
}
.cross_reference_batch <- function(features, outcome, validity, beta, caps,
                                    family, g, profile,
                                    max_outcome = if (family == "binomial") 1 else 1024) {
  stopifnot(family %in% c("binomial", "poisson"), g %in% 8:18,
            length(features) == length(outcome),
            nrow(validity) == length(outcome), all(validity %in% c(0, 1)),
            all(outcome == floor(outcome)), all(outcome >= 0),
            all(outcome <= max_outcome),
            length(beta) == length(caps))
  coefficients <- lapply(if (family == "binomial") profile$softplus else profile$exp_core,
                         .cross_parse)
  log_factorial <- lapply(profile$log_factorial, .cross_parse)
  beta <- lapply(beta, function(row) lapply(row, .cross_parse))
  for (row in beta) {
    total <- .cross_int()
    for (value in row) {
      stopifnot(.cross_cmp_abs(value, .cross_pow2(53)) <= 0)
      value$s <- abs(value$s); total <- .cross_add(total, value)
    }
    # Encoding can increase L1 by half an f50 ulp per public coefficient.
    limit <- .cross_add(.cross_pow2(54), .cross_small(ceiling(length(row)/2)))
    stopifnot(.cross_cmp_abs(total, limit) <= 0)
  }
  totals <- lapply(caps, function(x) .cross_int())
  for (i in seq_along(features)) {
    x <- lapply(features[[i]], .cross_parse)
    stopifnot(length(x) == ncol(validity)-1L, length(x) <= 16L)
    for (value in x) stopifnot(value$s >= 0,
                               .cross_cmp_abs(value, .cross_pow2(50)) <= 0)
    for (j in seq_along(beta)) {
      stopifnot(length(beta[[j]]) == length(x)+1L)
      eta <- .cross_eta(x, beta[[j]])
      nonlinear <- .cross_chebyshev(eta, coefficients)
      loss <- if (family == "binomial") {
        # Binary private outcome is a mux, with no multiplication/truncation.
        if (outcome[i] == 1) .cross_sub(nonlinear, eta) else nonlinear
      } else {
        exponential <- .cross_qmul(nonlinear, nonlinear)
        exponential <- .cross_qmul(exponential, exponential)
        .cross_add(.cross_sub(exponential, .cross_mul(.cross_small(outcome[i]), eta)),
                   log_factorial[[outcome[i]+1L]])
      }
      # This is an integer oracle, not a data-oblivious implementation.
      if (!all(validity[i, ] == 1)) loss <- .cross_int()
      raw <- .cross_quantize(loss, .cross_parse(caps[j]), g)
      totals[[j]] <- .cross_add(totals[[j]], raw)
    }
  }
  vapply(totals, .cross_format, character(1L))
}
