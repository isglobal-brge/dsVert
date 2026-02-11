# Tests for Inverse Gaussian family GLM

test_that("glmPartialFitDS works with inverse.gaussian family", {
  # Create test data with positive continuous response
  set.seed(789)
  n <- 100
  x1 <- rnorm(n)
  x2 <- rnorm(n)
  # Inverse Gaussian-like response (using Gamma as approximation for testing)
  mu <- exp(1 + 0.2 * x1 + 0.1 * x2)
  # Using Gamma to simulate positive continuous data
  y <- rgamma(n, shape = 5, rate = 5 / mu)
  y <- pmax(y, 0.01)  # Ensure positive

  test_data <- data.frame(y = y, x1 = x1, x2 = x2)

  # Simulate server environment
  assign("test_data", test_data, envir = globalenv())

  # Initial values
  eta_other <- rep(0, n)
  beta_current <- c(0, 0)

  # Run one iteration
  result <- glmPartialFitDS(
    data_name = "test_data",
    y_name = "y",
    x_vars = c("x1", "x2"),
    eta_other = eta_other,
    beta_current = beta_current,
    family = "inverse.gaussian",
    lambda = 1e-4
  )

  # Check structure
  expect_type(result, "list")
  expect_named(result, c("beta", "eta", "converged"))
  expect_length(result$beta, 2)
  expect_length(result$eta, n)
  expect_type(result$converged, "logical")

  # Check that coefficients are reasonable
  expect_true(all(abs(result$beta) < 10))

  # Clean up
  rm("test_data", envir = globalenv())
})

test_that("glmDevianceDS works with inverse.gaussian family", {
  set.seed(101)
  n <- 100
  mu <- rep(2, n)
  y <- rgamma(n, shape = 5, rate = 5 / mu)
  y <- pmax(y, 0.01)

  test_data <- data.frame(y = y)
  assign("test_data", test_data, envir = globalenv())

  # Eta corresponding to mu = 2 (log link)
  eta <- rep(log(2), n)

  result <- glmDevianceDS(
    data_name = "test_data",
    y_name = "y",
    eta = eta,
    family = "inverse.gaussian"
  )

  expect_type(result, "list")
  expect_named(result, c("deviance", "null_deviance", "n_obs"))
  expect_equal(result$n_obs, n)
  expect_true(result$deviance >= 0)
  expect_true(result$null_deviance >= 0)

  rm("test_data", envir = globalenv())
})

test_that("glmPartialFitDS rejects invalid family", {
  test_data <- data.frame(y = 1:10, x = rnorm(10))
  assign("test_data", test_data, envir = globalenv())

  expect_error(
    glmPartialFitDS("test_data", "y", "x", rep(0, 10), 0, "invalid_family"),
    "family must be"
  )

  rm("test_data", envir = globalenv())
})
