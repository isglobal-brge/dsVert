test_that("NB2 quantized row losses agree with the independent dnbinom oracle", {
  grid <- expand.grid(
    y = c(0, 1, 2, 10, 1024), theta = c(1e-200, 1e-8, 0.5, 1, 2, 64),
    eta = c(-16, -8, -1, 0, 1, 8, 16))
  expected <- with(grid, -stats::dnbinom(y, size = theta, mu = exp(eta),
                                       log = TRUE))
  for (bits in c(8L, 18L)) {
    actual <- vapply(seq_len(nrow(grid)), function(i) {
      .dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
        list(1, 1), grid$y[[i]],
        list(rep(grid$eta[[i]] / 2, 2)), grid$theta[[i]], bits, 1024L)
    }, numeric(1L))
    expect_equal(actual, round(expected * 2^bits), tolerance = 0)
    expect_lte(max(abs(actual / 2^bits - expected)), 0.5 / 2^bits)
  }
})

test_that("NB2 losses stay finite beyond the exponential range", {
  for (eta in c(-800, 800)) {
    # One hundred signed coefficients, each at its allowed boundary.
    actual <- .dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
      rep(list(1), 100), 0, list(rep(eta / 100, 100)), 2, 18L, 1024L)
    expected <- 2 * (max(eta - log(2), 0) +
                       log1p(exp(-abs(eta - log(2)))))
    expect_equal(actual, round(expected * 2^18), tolerance = 0)
    for (y in c(1, 1024)) {
      actual <- .dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
        rep(list(1), 100), y, list(rep(eta / 100, 100)), 1, 18L, 1024L)
      # theta=1 is geometric; exp(-800) underflows at this precision.
      expected <- if (eta > 0) eta else -y * eta
      expect_equal(actual, expected * 2^18, tolerance = 0)
    }
  }
})

test_that("NB2 malformed row inputs fail without disclosing their values", {
  for (outcome in list(-918273, 918273, NA_real_, Inf, 0.5)) {
    expect_error(.dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
      list(1, 0), outcome, list(c(0, 0)), 2, 18L, 1024L),
      "^Invalid negative-binomial likelihood-grid values\\.$")
  }
})

test_that("NB2 canonical row includes the count log denominator term", {
  actual <- .dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
    list(1, 0), 1, list(c(0, 0)), 2, 18L, 1L)
  expected <- -stats::dnbinom(1, size = 2, mu = 1, log = TRUE)
  expect_equal(expected, 1.21639532432449, tolerance = 1e-13)
  expect_equal(actual, round(expected * 2^18), tolerance = 0)
})
