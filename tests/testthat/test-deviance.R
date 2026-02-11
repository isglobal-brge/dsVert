# Tests for GLM Deviance calculation

test_that("glmDevianceDS works with gaussian family", {
  set.seed(111)
  n <- 50
  y <- rnorm(n, mean = 5, sd = 2)

  test_data <- data.frame(y = y)
  assign("test_data", test_data, envir = globalenv())

  # Perfect prediction (eta = y for gaussian)
  eta_perfect <- y

  result <- glmDevianceDS(
    data_name = "test_data",
    y_name = "y",
    eta = eta_perfect,
    family = "gaussian"
  )

  expect_equal(result$deviance, 0, tolerance = 1e-10)
  expect_true(result$null_deviance > 0)
  expect_equal(result$n_obs, n)

  rm("test_data", envir = globalenv())
})

test_that("glmDevianceDS works with binomial family", {
  set.seed(222)
  n <- 100
  y <- rbinom(n, 1, 0.5)

  test_data <- data.frame(y = y)
  assign("test_data", test_data, envir = globalenv())

  # Null model eta (log-odds of mean)
  p <- mean(y)
  eta_null <- rep(log(p / (1 - p)), n)

  result <- glmDevianceDS(
    data_name = "test_data",
    y_name = "y",
    eta = eta_null,
    family = "binomial"
  )

  # Deviance should equal null deviance for null model
  expect_equal(result$deviance, result$null_deviance, tolerance = 0.1)
  expect_true(result$deviance >= 0)

  rm("test_data", envir = globalenv())
})

test_that("glmDevianceDS works with poisson family", {
  set.seed(333)
  n <- 100
  y <- rpois(n, lambda = 3)

  test_data <- data.frame(y = y)
  assign("test_data", test_data, envir = globalenv())

  # Eta for mean prediction
  eta <- rep(log(mean(y)), n)

  result <- glmDevianceDS(
    data_name = "test_data",
    y_name = "y",
    eta = eta,
    family = "poisson"
  )

  expect_true(result$deviance >= 0)
  expect_true(result$null_deviance >= 0)
  # For null model, deviance should approximately equal null_deviance
  expect_equal(result$deviance, result$null_deviance, tolerance = 0.1)

  rm("test_data", envir = globalenv())
})

test_that("glmDevianceDS validates inputs", {
  test_data <- data.frame(y = 1:10)
  assign("test_data", test_data, envir = globalenv())

  # Wrong eta length
  expect_error(
    glmDevianceDS("test_data", "y", 1:5, "gaussian"),
    "eta length"
  )

  # Invalid family
  expect_error(
    glmDevianceDS("test_data", "y", 1:10, "invalid"),
    "family must be"
  )

  rm("test_data", envir = globalenv())
})
