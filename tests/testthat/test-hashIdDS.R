test_that("hashIdDS hashes identifiers correctly", {
  # Create test data
  test_data <- data.frame(
    id = c("patient_001", "patient_002", "patient_003"),
    age = c(25, 30, 35),
    stringsAsFactors = FALSE
  )

  # Assign to global environment (simulating server environment)
  assign("D", test_data, envir = .GlobalEnv)

  # Test hashing
  result <- hashIdDS("D", "id", "sha256")

  expect_type(result, "list")
  expect_equal(result$n, 3)
  expect_length(result$hashes, 3)
  expect_type(result$hashes, "character")

  # Verify hashes are consistent
  expected_hash <- digest::digest("patient_001", algo = "sha256")
  expect_equal(result$hashes[1], expected_hash)

  # Clean up
  rm("D", envir = .GlobalEnv)
})

test_that("hashIdDS handles different algorithms", {
  test_data <- data.frame(
    id = c("test_id"),
    stringsAsFactors = FALSE
  )
  assign("D", test_data, envir = .GlobalEnv)

  result_sha256 <- hashIdDS("D", "id", "sha256")
  result_md5 <- hashIdDS("D", "id", "md5")

  # Different algorithms should produce different hashes
  expect_false(result_sha256$hashes[1] == result_md5$hashes[1])

  rm("D", envir = .GlobalEnv)
})
