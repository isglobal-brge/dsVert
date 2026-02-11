# Tests for ID format validation

test_that("validateIdFormatDS returns correct structure", {
  test_data <- data.frame(
    id = paste0("ID", sprintf("%04d", 1:100)),
    value = rnorm(100)
  )
  assign("test_data", test_data, envir = globalenv())

  result <- validateIdFormatDS("test_data", "id")

  expect_type(result, "list")
  expect_named(result, c("n_obs", "n_unique", "n_missing", "all_match",
                         "pct_match", "format_signature", "id_class"))
  expect_equal(result$n_obs, 100)
  expect_equal(result$n_unique, 100)
  expect_equal(result$n_missing, 0)
  expect_true(nchar(result$format_signature) == 64)  # SHA-256 hex length

  rm("test_data", envir = globalenv())
})

test_that("validateIdFormatDS detects missing values", {
  test_data <- data.frame(
    id = c(paste0("ID", 1:95), rep(NA, 5)),
    value = rnorm(100)
  )
  assign("test_data", test_data, envir = globalenv())

  result <- validateIdFormatDS("test_data", "id")

  expect_equal(result$n_missing, 5)
  expect_equal(result$n_unique, 95)

  rm("test_data", envir = globalenv())
})

test_that("validateIdFormatDS validates pattern matching", {
  test_data <- data.frame(
    id = paste0("AB", sprintf("%06d", 1:100)),
    value = rnorm(100)
  )
  assign("test_data", test_data, envir = globalenv())

  # Pattern that matches
  result <- validateIdFormatDS("test_data", "id", "^AB[0-9]+$")
  expect_true(result$all_match)
  expect_equal(result$pct_match, 100)

  # Pattern that doesn't match
  result2 <- validateIdFormatDS("test_data", "id", "^XY[0-9]+$")
  expect_false(result2$all_match)
  expect_equal(result2$pct_match, 0)

  rm("test_data", envir = globalenv())
})

test_that("validateIdFormatDS detects duplicates indirectly", {
  test_data <- data.frame(
    id = c(rep("ID001", 10), paste0("ID", sprintf("%03d", 2:91))),
    value = rnorm(100)
  )
  assign("test_data", test_data, envir = globalenv())

  result <- validateIdFormatDS("test_data", "id")

  expect_equal(result$n_obs, 100)
  expect_equal(result$n_unique, 91)  # 90 unique + 1 duplicate ID

  rm("test_data", envir = globalenv())
})

test_that("validateIdFormatDS handles numeric IDs", {
  test_data <- data.frame(
    id = 1:100,
    value = rnorm(100)
  )
  assign("test_data", test_data, envir = globalenv())

  result <- validateIdFormatDS("test_data", "id")

  expect_equal(result$id_class, "integer")
  expect_equal(result$n_unique, 100)

  rm("test_data", envir = globalenv())
})

test_that("validateIdFormatDS validates inputs", {
  test_data <- data.frame(id = 1:10)
  assign("test_data", test_data, envir = globalenv())

  expect_error(
    validateIdFormatDS("test_data", "nonexistent"),
    "not found"
  )

  expect_error(
    validateIdFormatDS("nonexistent_data", "id"),
    "not found|not a data frame"
  )

  rm("test_data", envir = globalenv())
})
