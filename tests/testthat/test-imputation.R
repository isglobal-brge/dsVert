test_that("numeric imputation uses an aggregate mean fallback", {
  D <- data.frame(x = c(1, NA, 3, NA, 5, 6))

  res <- dsvertImputeColumnDS("D", "x", "x_imp", seed = 11L)

  expect_equal(res$n_imputed, 2L)
  expect_equal(res$method, "mean_intercept")
  expect_false(anyNA(D$x_imp))
  expect_equal(D$x_imp[!is.na(D$x)], D$x[!is.na(D$x)])
  expect_equal(D$x_imp[is.na(D$x)], rep(mean(D$x, na.rm = TRUE), 2L))
})

test_that("numeric imputation includes an unpenalized intercept", {
  D <- data.frame(
    x = c(10, 11, 12, NA, NA, 15, 16, 17),
    z = rep(0, 8))

  res <- dsvertImputeColumnDS("D", "x", "x_imp", seed = 22L)

  expect_equal(res$n_imputed, 2L)
  expect_equal(res$method, "bayesian_ridge")
  expect_false(anyNA(D$x_imp))
  expect_gt(mean(D$x_imp[is.na(D$x)]), 8)
})

test_that("binary imputation uses an aggregate mode fallback", {
  D <- data.frame(x = factor(c("a", "b", NA, "b", NA, "a")))

  res <- dsvertImputeColumnDS("D", "x", "x_imp", seed = 33L)

  expect_equal(res$n_imputed, 2L)
  expect_equal(res$method, "mode_intercept")
  expect_false(anyNA(D$x_imp))
  expect_equal(levels(D$x_imp), c("a", "b"))
  expect_equal(as.character(D$x_imp[is.na(D$x)]), c("a", "a"))
})
