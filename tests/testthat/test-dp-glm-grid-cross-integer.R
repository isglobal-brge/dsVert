.cross_numeric_fixture <- function() {
  jsonlite::fromJSON(system.file("cross-grid-v1", "numeric_profile_v1.json",
                               package = "dsVert"), simplifyVector = FALSE)
}
.cross_numeric_profile <- function(fixture) {
  list(softplus = unlist(fixture$profile$softplus_coefficients_q64),
       exp_core = unlist(fixture$profile$exp_quarter_coefficients_q64),
       log_factorial = unlist(fixture$profile$log_factorial_q64))
}

test_that("pure R multiword arithmetic handles signed ties and wide products", {
  for (value in c("0", "1", "-1", "9007199254740993",
                  "-18446744073709551616", "6277101735386680763835789423207666416102355444464034512895")) {
    expect_identical(.cross_format(.cross_parse(value)), value)
  }
  a <- .cross_parse("9007199254740993")
  expect_identical(.cross_format(.cross_mul(a, a)),
                   "81129638414606699710187514626049")
  for (value in c(-7, -5, -3, -1, 1, 3, 5, 7)) {
    expect_equal(.cross_double(.cross_round_shift(.cross_small(value), 1)),
                 round(value / 2))
  }
  expect_identical(.cross_format(.cross_round_divsmall(.cross_parse("-25"), 2)), "-12")
  expect_identical(.cross_format(.cross_round_divsmall(.cross_parse("-27"), 2)), "-14")
  expect_error(.cross_width(.cross_pow2(191), 192))
})

test_that("pure R circuit agrees bit for bit with the shared integer fixtures", {
  fixture <- .cross_numeric_fixture()
  profile <- .cross_numeric_profile(fixture)
  for (case in fixture$reference_cases) {
    calculate <- function(validity) .cross_reference_batch(
      lapply(case$features_encoded, function(x) sprintf("%.0f", unlist(x))),
      unlist(case$outcomes), validity, lapply(case$beta_encoded, unlist),
      sprintf("%.0f", unlist(case$caps)), case$family, case$g, profile)
    valid <- do.call(rbind, lapply(case$validity, unlist))
    expect_identical(unname(calculate(valid)),
                     sprintf("%.0f", unlist(case$expected_sums)))
    valid[,] <- 0
    expect_identical(unname(calculate(valid)), rep("0", length(case$caps)))
  }
})

test_that("fixed point endpoints and nonlinear zero lie within the certificate", {
  fixture <- .cross_numeric_fixture()
  profile <- .cross_numeric_profile(fixture)
  for (eta in c(-16, -8, 0, 8, 16)) {
    encoded <- .cross_shift_left(.cross_small(eta), 64)
    sp <- .cross_chebyshev(encoded, lapply(profile$softplus, .cross_parse))
    ep <- .cross_chebyshev(encoded, lapply(profile$exp_core, .cross_parse))
    ep <- .cross_qmul(ep, ep); ep <- .cross_qmul(ep, ep)
    expect_lte(abs(.cross_double(sp) / 2^64 -
                     (max(eta, 0) + log1p(exp(-abs(eta))))),
                as.numeric(fixture$numeric_contract$binomial$certified_uniform_error))
    expect_lte(abs(.cross_double(ep) / 2^64 - exp(eta)),
                as.numeric(fixture$numeric_contract$poisson$certified_uniform_error))
  }
})

test_that("every output precision clamps then rounds ties to even", {
  for (g in 8:18) {
    cap <- .cross_small(10)
    for (n in 0:9) {
      half <- .cross_shift_left(.cross_small(2*n+1), 63-g)
      expect_equal(.cross_double(.cross_quantize(half, cap, g)), round(n+0.5))
    }
    expect_identical(.cross_format(.cross_quantize(.cross_small(-1), cap, g)), "0")
    expect_identical(.cross_format(.cross_quantize(.cross_pow2(100), cap, g)), "10")
    expect_identical(.cross_format(.cross_quantize(
      .cross_shift_left(cap, 64-g), cap, g)), "10")
  }
})

test_that("dot products retain wide products and do not depend on owner grouping", {
  x <- lapply(rep("562949953421312", 16), .cross_parse)
  beta <- lapply(c("0", rep("1125899906842624", 16)), .cross_parse)
  expect_identical(.cross_format(.cross_eta(x, beta)),
                   .cross_format(.cross_shift_left(.cross_small(8), 64)))
  # Rounding owner partial sums would fail this exact accumulate-then-round check.
  x <- lapply(c("1", "1"), .cross_parse)
  beta <- lapply(c("0", "34359738368", "34359738368"), .cross_parse)
  expect_identical(.cross_format(.cross_eta(x, beta)), "1")
})

test_that("encoded coefficients preserve the certified L1 rounding slack", {
  # Exact raw L1 is 16: (8-6u) + 4*(2+1.5u). Four ties round upward.
  encoded <- sprintf("%.0f", c(8*2^50-6, rep(2*2^50+2, 4)))
  profile <- .cross_numeric_profile(.cross_numeric_fixture())
  expect_identical(.cross_reference_batch(
    list(rep("1125899906842624", 4)), 0, matrix(1, 1, 5),
    list(encoded), "4194305", "binomial", 18, profile), "4194304")
})
