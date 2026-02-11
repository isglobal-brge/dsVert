test_that("glmPartialFitDS updates coefficients for Gaussian family", {
  set.seed(42)
  n <- 100
  X <- matrix(rnorm(n * 2), n, 2)
  y <- X %*% c(1, 2) + rnorm(n, sd = 0.1)

  test_data <- data.frame(
    y = y,
    x1 = X[, 1],
    x2 = X[, 2]
  )
  assign("D", test_data, envir = .GlobalEnv)

  # Initial values
  eta_other <- rep(0, n)
  beta_current <- c(0, 0)

  result <- glmPartialFitDS(
    "D", "y", c("x1", "x2"),
    eta_other, beta_current, "gaussian", 1e-4
  )

  expect_type(result, "list")
  expect_length(result$beta, 2)
  expect_length(result$eta, n)
  expect_true(result$converged)

  # Coefficients should be close to true values after sufficient iterations
  # This is just one iteration, so we just check they're not zero
  expect_true(all(abs(result$beta) > 0))

  rm("D", envir = .GlobalEnv)
})

test_that("glmPartialFitDS works with binomial family", {
  set.seed(42)
  n <- 100
  X <- matrix(rnorm(n * 2), n, 2)
  eta_true <- X %*% c(0.5, -0.5)
  prob <- 1 / (1 + exp(-eta_true))
  y <- rbinom(n, 1, prob)

  test_data <- data.frame(
    y = y,
    x1 = X[, 1],
    x2 = X[, 2]
  )
  assign("D", test_data, envir = .GlobalEnv)

  eta_other <- rep(0, n)
  beta_current <- c(0, 0)

  result <- glmPartialFitDS(
    "D", "y", c("x1", "x2"),
    eta_other, beta_current, "binomial", 1e-4
  )

  expect_type(result, "list")
  expect_length(result$beta, 2)
  expect_true(result$converged)

  rm("D", envir = .GlobalEnv)
})
