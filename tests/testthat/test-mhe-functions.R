# Tests for Multiparty Homomorphic Encryption functions

skip_if_not(mheAvailable(), "MHE tool binary not available")

# =============================================================================
# Test MHE Availability
# =============================================================================

test_that("mheAvailable returns TRUE when binary exists", {
  expect_true(mheAvailable())
})

test_that("mheVersion returns version string", {
  ver <- mheVersion()
  expect_type(ver, "character")
  expect_match(ver, "^[0-9]+\\.[0-9]+\\.[0-9]+$")
})

# =============================================================================
# Test Key Generation
# =============================================================================

test_that("mheKeyGenDS generates keys correctly", {
  result <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)

  expect_type(result, "list")
  expect_true("secret_key_share" %in% names(result))
  expect_true("public_key_share" %in% names(result))

  # Keys should be base64 encoded strings
  expect_type(result$secret_key_share, "character")
  expect_type(result$public_key_share, "character")

  # Keys should be substantial in size (thousands of base64 chars)
  expect_gt(nchar(result$secret_key_share), 1000)
  expect_gt(nchar(result$public_key_share), 1000)
})

test_that("mheKeyGenDS with different parameters produces different keys", {
  result1 <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)
  result2 <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)

  # Different calls should produce different keys (randomness)
  expect_false(result1$secret_key_share == result2$secret_key_share)
})

# =============================================================================
# Test Key Combination
# =============================================================================

test_that("mheCombineKeysDS combines keys correctly", {
  # Generate a key
  keys <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)

  # Combine (single party case)
  result <- mheCombineKeysDS(
    public_key_shares = keys$public_key_share,
    log_n = 13L,
    log_scale = 40L
  )

  expect_type(result, "list")
  expect_true("collective_public_key" %in% names(result))
  expect_true("relinearization_key" %in% names(result) || "rotation_keys" %in% names(result))

  # Combined public key should be substantial
  expect_gt(nchar(result$collective_public_key), 1000)
})

# =============================================================================
# Test Column Encryption
# =============================================================================

test_that("mheEncryptColumnsDS encrypts columns correctly", {
  # Generate keys
  keys <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)
  combined <- mheCombineKeysDS(
    public_key_shares = keys$public_key_share,
    log_n = 13L,
    log_scale = 40L
  )

  # Create test data
  set.seed(456)
  test_data <- data.frame(
    x = rnorm(30),
    y = rnorm(30)
  )
  assign("D_cols", test_data, envir = .GlobalEnv)

  # Encrypt columns
  result <- mheEncryptColumnsDS(
    data_name = "D_cols",
    variables = c("x", "y"),
    collective_public_key = combined$collective_public_key,
    log_n = 13L,
    log_scale = 40L
  )

  expect_type(result, "list")
  expect_true("encrypted_columns" %in% names(result))
  expect_true("var_names" %in% names(result))
  expect_equal(result$var_names, c("x", "y"))
  expect_equal(length(result$encrypted_columns), 2)

  # Each encrypted column should be a base64 string
  expect_type(result$encrypted_columns[[1]], "character")
  expect_type(result$encrypted_columns[[2]], "character")

  rm("D_cols", envir = .GlobalEnv)
})

# =============================================================================
# Test Local Correlation
# =============================================================================

test_that("localCorDS computes correlation correctly", {
  set.seed(789)
  n <- 50
  x <- rnorm(n)
  y <- 0.5 * x + rnorm(n, 0, 0.5)  # Correlated with x
  z <- rnorm(n)  # Independent

  test_data <- data.frame(x = x, y = y, z = z)
  assign("D_cor", test_data, envir = .GlobalEnv)

  result <- localCorDS("D_cor", c("x", "y", "z"))

  expect_type(result, "list")
  expect_true("correlation" %in% names(result))
  expect_true("n_obs" %in% names(result))
  expect_true("var_names" %in% names(result))

  expect_equal(result$n_obs, n)
  expect_equal(result$var_names, c("x", "y", "z"))

  # Diagonal should be 1
  expect_equal(diag(result$correlation), c(x = 1, y = 1, z = 1))

  # Correlation should be symmetric
  expect_equal(result$correlation, t(result$correlation))

  # x and y should be positively correlated
  expect_gt(result$correlation["x", "y"], 0.5)

  # Compare with base R cor()
  expected <- cor(test_data)
  expect_equal(result$correlation, expected, tolerance = 1e-10)

  rm("D_cor", envir = .GlobalEnv)
})

test_that("localCorDS enforces privacy level", {
  test_data <- data.frame(x = c(1, 2, 3), y = c(4, 5, 6))
  assign("D_small", test_data, envir = .GlobalEnv)

  expect_error(
    localCorDS("D_small", c("x", "y")),
    "Insufficient observations"
  )

  rm("D_small", envir = .GlobalEnv)
})

# =============================================================================
# Test Cross-Product Computation
# =============================================================================

test_that("mheCrossProductDS computes correct cross-correlation", {
  # Generate keys
  keys <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)
  combined <- mheCombineKeysDS(
    public_key_shares = keys$public_key_share,
    log_n = 13L,
    log_scale = 40L
  )

  # Create test data for two "servers"
  set.seed(101)
  n <- 50

  # Server A data
  data_A <- data.frame(
    a1 = rnorm(n),
    a2 = rnorm(n)
  )

  # Server B data (correlated with A)
  data_B <- data.frame(
    b1 = 0.3 * data_A$a1 + 0.7 * rnorm(n),
    b2 = 0.5 * data_A$a2 + 0.5 * rnorm(n)
  )

  assign("D_A", data_A, envir = .GlobalEnv)
  assign("D_B", data_B, envir = .GlobalEnv)

  # Encrypt server B's columns
  enc_B <- mheEncryptColumnsDS(
    data_name = "D_B",
    variables = c("b1", "b2"),
    collective_public_key = combined$collective_public_key,
    log_n = 13L,
    log_scale = 40L
  )

  # Compute cross-product homomorphically
  result <- mheCrossProductDS(
    plaintext_data_name = "D_A",
    plaintext_variables = c("a1", "a2"),
    encrypted_columns = enc_B$encrypted_columns,
    secret_key = keys$secret_key_share,
    n_obs = n,
    log_n = 13L,
    log_scale = 40L
  )

  expect_type(result, "list")
  expect_true("cross_correlation" %in% names(result))
  expect_true("cross_product" %in% names(result))

  # Compare with ground truth
  Z_A <- scale(as.matrix(data_A))
  Z_B <- scale(as.matrix(data_B))
  expected_G <- t(Z_A) %*% Z_B
  expected_R <- expected_G / (n - 1)

  # Should match with reasonable HE approximation error
  max_error <- max(abs(result$cross_correlation - expected_R))
  expect_lt(max_error, 0.15)  # Allow up to 15% error for HE approximation

  rm("D_A", "D_B", envir = .GlobalEnv)
})

# =============================================================================
# Test Full Correlation Workflow
# =============================================================================

test_that("MHE correlation matches local correlation for combined dataset", {
  # Generate keys
  keys <- mheKeyGenDS(party_id = 0L, num_parties = 1L, log_n = 13L, log_scale = 40L)
  combined <- mheCombineKeysDS(
    public_key_shares = keys$public_key_share,
    log_n = 13L,
    log_scale = 40L
  )

  # Create test data
  set.seed(202)
  n <- 60

  # Create correlated data
  base <- rnorm(n)
  data_full <- data.frame(
    x1 = base + rnorm(n, 0, 0.5),
    x2 = rnorm(n),
    y1 = 0.5 * base + rnorm(n, 0, 0.7),
    y2 = rnorm(n)
  )

  # Split into two "servers"
  data_A <- data_full[, c("x1", "x2")]
  data_B <- data_full[, c("y1", "y2")]

  assign("D_A", data_A, envir = .GlobalEnv)
  assign("D_B", data_B, envir = .GlobalEnv)
  assign("D_full", data_full, envir = .GlobalEnv)

  # Ground truth: local correlation on combined data
  expected_R <- cor(data_full)

  # Compute via MHE:
  # 1. Local correlations
  local_A <- localCorDS("D_A", c("x1", "x2"))
  local_B <- localCorDS("D_B", c("y1", "y2"))

  # 2. Cross-correlation via HE
  enc_B <- mheEncryptColumnsDS(
    data_name = "D_B",
    variables = c("y1", "y2"),
    collective_public_key = combined$collective_public_key,
    log_n = 13L,
    log_scale = 40L
  )

  cross_AB <- mheCrossProductDS(
    plaintext_data_name = "D_A",
    plaintext_variables = c("x1", "x2"),
    encrypted_columns = enc_B$encrypted_columns,
    secret_key = keys$secret_key_share,
    n_obs = n,
    log_n = 13L,
    log_scale = 40L
  )

  # 3. Assemble full matrix
  R <- matrix(0, 4, 4)
  rownames(R) <- colnames(R) <- c("x1", "x2", "y1", "y2")

  R[1:2, 1:2] <- local_A$correlation
  R[3:4, 3:4] <- local_B$correlation
  R[1:2, 3:4] <- cross_AB$cross_correlation
  R[3:4, 1:2] <- t(cross_AB$cross_correlation)

  # Compare - allow reasonable HE approximation error
  max_error <- max(abs(R - expected_R))
  expect_lt(max_error, 0.1)  # Allow up to 10% error for HE approximation

  rm("D_A", "D_B", "D_full", envir = .GlobalEnv)
})
