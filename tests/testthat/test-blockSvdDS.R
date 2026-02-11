test_that("blockSvdDS computes SVD correctly", {
  # Create test data with known properties
  set.seed(42)
  n <- 100
  test_data <- data.frame(
    var1 = rnorm(n),
    var2 = rnorm(n),
    var3 = rnorm(n)
  )

  assign("D", test_data, envir = .GlobalEnv)

  result <- blockSvdDS("D", c("var1", "var2", "var3"), standardize = TRUE)

  expect_type(result, "list")
  expect_equal(result$n_obs, n)
  expect_equal(result$var_names, c("var1", "var2", "var3"))
  expect_equal(nrow(result$UD), n)
  expect_equal(ncol(result$UD), 3)

  rm("D", envir = .GlobalEnv)
})

test_that("blockSvdDS enforces privacy level", {
  # Create small dataset
  test_data <- data.frame(
    var1 = rnorm(3),
    var2 = rnorm(3)
  )
  assign("D", test_data, envir = .GlobalEnv)

  # Should fail due to insufficient observations
  expect_error(
    blockSvdDS("D", c("var1", "var2")),
    "Insufficient observations"
  )

  rm("D", envir = .GlobalEnv)
})
