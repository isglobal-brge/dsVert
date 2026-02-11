# Tests for Multiparty Homomorphic Encryption (Threshold) functions

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
# Test mheGetObsDS
# =============================================================================

test_that("mheGetObsDS returns correct observation count", {
  set.seed(100)
  test_data <- data.frame(x = rnorm(30), y = rnorm(30))
  assign("D_obs", test_data, envir = .GlobalEnv)

  count <- mheGetObsDS("D_obs", c("x", "y"))
  expect_equal(count, 30)

  rm("D_obs", envir = .GlobalEnv)
})

test_that("mheGetObsDS handles missing values", {
  test_data <- data.frame(x = c(1, 2, NA, 4, 5), y = c(1, NA, 3, 4, 5))
  assign("D_na", test_data, envir = .GlobalEnv)

  count <- mheGetObsDS("D_na", c("x", "y"))
  expect_equal(count, 3)

  rm("D_na", envir = .GlobalEnv)
})

# =============================================================================
# Test Local Correlation
# =============================================================================

test_that("localCorDS computes correlation correctly", {
  set.seed(789)
  n <- 50
  x <- rnorm(n)
  y <- 0.5 * x + rnorm(n, 0, 0.5)
  z <- rnorm(n)

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
# Test MHE Threshold Protocol (mheInitDS)
# =============================================================================

test_that("mheInitDS generates keys for party 0 (CRP creator)", {
  result <- mheInitDS(party_id = 0L, crp = NULL, num_obs = 30L,
                      log_n = 12L, log_scale = 40L)

  expect_type(result, "list")
  expect_true("public_key_share" %in% names(result))
  expect_true("crp" %in% names(result))
  expect_equal(result$party_id, 0L)

  # Public key share and CRP should be base64url strings

  expect_type(result$public_key_share, "character")
  expect_type(result$crp, "character")
  expect_gt(nchar(result$public_key_share), 100)
  expect_gt(nchar(result$crp), 100)

  # Secret key should be stored internally, not returned
  expect_true(!is.null(.mhe_storage$secret_key))
})

test_that("mheInitDS generates keys for party 1 with CRP", {
  # First create party 0 to get a CRP
  result0 <- mheInitDS(party_id = 0L, crp = NULL, num_obs = 30L,
                       log_n = 12L, log_scale = 40L)

  # Use the CRP for party 1
  result1 <- mheInitDS(party_id = 1L, crp = result0$crp, num_obs = 30L,
                       log_n = 12L, log_scale = 40L)

  expect_type(result1, "list")
  expect_true("public_key_share" %in% names(result1))
  expect_equal(result1$party_id, 1L)

  # Party 1 should NOT generate a new CRP
  expect_null(result1$crp)
})

# =============================================================================
# Test mheCombineDS
# =============================================================================

test_that("mheCombineDS creates collective public key", {
  # Setup: 2 parties
  r0 <- mheInitDS(party_id = 0L, crp = NULL, num_obs = 30L,
                  log_n = 12L, log_scale = 40L)
  pk0 <- r0$public_key_share
  crp <- r0$crp

  r1 <- mheInitDS(party_id = 1L, crp = crp, num_obs = 30L,
                  log_n = 12L, log_scale = 40L)
  pk1 <- r1$public_key_share

  # Combine
  combined <- mheCombineDS(
    public_key_shares = c(pk0, pk1),
    crp = crp,
    num_obs = 30L,
    log_n = 12L,
    log_scale = 40L
  )

  expect_type(combined, "list")
  expect_true("collective_public_key" %in% names(combined))
  expect_type(combined$collective_public_key, "character")
  expect_gt(nchar(combined$collective_public_key), 100)
})

# =============================================================================
# Test mheStoreCPKDS
# =============================================================================

test_that("mheStoreCPKDS stores CPK correctly", {
  result <- mheStoreCPKDS(cpk = "dGVzdA")  # "test" in base64url
  expect_true(result)
  expect_false(is.null(.mhe_storage$cpk))
})

# =============================================================================
# Test mheStoreEncChunkDS / mheAssembleEncColumnDS
# =============================================================================

test_that("chunk storage and assembly works", {
  # Store 3 chunks for column 1
  expect_true(mheStoreEncChunkDS(col_index = 1L, chunk_index = 1L, chunk = "AAA"))
  expect_true(mheStoreEncChunkDS(col_index = 1L, chunk_index = 2L, chunk = "BBB"))
  expect_true(mheStoreEncChunkDS(col_index = 1L, chunk_index = 3L, chunk = "CCC"))

  # Assemble
  expect_true(mheAssembleEncColumnDS(col_index = 1L, n_chunks = 3L))

  # Check assembled result exists
  expect_false(is.null(.mhe_storage$remote_enc_cols))
  expect_equal(length(.mhe_storage$remote_enc_cols), 1)

  # Clean up
  .mhe_storage$remote_enc_cols <- NULL
})

test_that("mheAssembleEncColumnDS errors with missing chunks", {
  expect_error(
    mheAssembleEncColumnDS(col_index = 99L, n_chunks = 5L),
    "Missing chunks"
  )
})

# =============================================================================
# Test mheStoreCTChunkDS
# =============================================================================

test_that("mheStoreCTChunkDS stores ciphertext chunks", {
  .mhe_storage$ct_chunks <- NULL  # Reset
  expect_true(mheStoreCTChunkDS(chunk_index = 1L, chunk = "chunk1"))
  expect_true(mheStoreCTChunkDS(chunk_index = 2L, chunk = "chunk2"))

  expect_equal(length(.mhe_storage$ct_chunks), 2)

  # Clean up
  .mhe_storage$ct_chunks <- NULL
})

# =============================================================================
# Test mhePartialDecryptDS error handling
# =============================================================================

test_that("mhePartialDecryptDS errors without secret key", {
  .mhe_storage$secret_key <- NULL
  .mhe_storage$ct_chunks <- NULL
  expect_error(
    mhePartialDecryptDS(n_chunks = 1L),
    "Secret key not stored"
  )
})

test_that("mhePartialDecryptDS errors without ciphertext chunks", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$ct_chunks <- NULL
  expect_error(
    mhePartialDecryptDS(n_chunks = 1L),
    "Ciphertext chunks not stored"
  )
  .mhe_storage$secret_key <- NULL
})

# =============================================================================
# Test mheEncryptLocalDS error handling
# =============================================================================

test_that("mheEncryptLocalDS errors without CPK", {
  .mhe_storage$cpk <- NULL
  set.seed(42)
  test_data <- data.frame(x = rnorm(30))
  assign("D_enc_test", test_data, envir = .GlobalEnv)

  expect_error(
    mheEncryptLocalDS("D_enc_test", "x"),
    "CPK not stored"
  )

  rm("D_enc_test", envir = .GlobalEnv)
})

# =============================================================================
# End-to-End: Full 2-party threshold protocol
# =============================================================================

test_that("Full 2-party threshold MHE produces correct correlation", {
  set.seed(42)
  n <- 30

  # Create correlated data for 2 "servers"
  base <- rnorm(n)
  data_A <- data.frame(
    a1 = base + rnorm(n, 0, 0.5),
    a2 = rnorm(n)
  )
  data_B <- data.frame(
    b1 = 0.5 * base + rnorm(n, 0, 0.7),
    b2 = rnorm(n)
  )

  assign("D_A", data_A, envir = .GlobalEnv)
  assign("D_B", data_B, envir = .GlobalEnv)

  # Ground truth
  full_data <- cbind(data_A, data_B)
  expected_R <- cor(full_data)

  # --- Phase 1: Key generation ---
  r0 <- mheInitDS(party_id = 0L, crp = NULL, num_obs = as.integer(n),
                  log_n = 12L, log_scale = 40L)
  sk0 <- .mhe_storage$secret_key  # Save party 0's secret key

  r1 <- mheInitDS(party_id = 1L, crp = r0$crp, num_obs = as.integer(n),
                  log_n = 12L, log_scale = 40L)
  sk1 <- .mhe_storage$secret_key  # Save party 1's secret key

  # --- Phase 2: Combine keys ---
  combined <- mheCombineDS(
    public_key_shares = c(r0$public_key_share, r1$public_key_share),
    crp = r0$crp,
    num_obs = as.integer(n),
    log_n = 12L,
    log_scale = 40L
  )
  cpk <- combined$collective_public_key

  # Store CPK (simulating distribution)
  mheStoreCPKDS(cpk = cpk)

  # --- Phase 3: Encrypt data ---
  enc_A <- mheEncryptLocalDS("D_A", c("a1", "a2"))
  enc_B <- mheEncryptLocalDS("D_B", c("b1", "b2"))

  # --- Phase 4: Local correlations ---
  local_A <- localCorDS("D_A", c("a1", "a2"))
  local_B <- localCorDS("D_B", c("b1", "b2"))

  # --- Phase 5: Cross-server correlation ---
  # Transfer B's encrypted columns to A (simulate chunking)
  for (k in seq_along(enc_B$encrypted_columns)) {
    col_str <- enc_B$encrypted_columns[[k]]
    mheStoreEncChunkDS(col_index = as.integer(k), chunk_index = 1L, chunk = col_str)
    mheAssembleEncColumnDS(col_index = as.integer(k), n_chunks = 1L)
  }

  # Compute encrypted cross-product on server A
  cross_enc <- mheCrossProductEncDS("D_A", c("a1", "a2"),
                                     n_enc_cols = 2L, n_obs = as.integer(n))

  # Threshold decryption for each element
  cross_cor <- matrix(NA, 2, 2)
  for (i in 1:2) {
    for (j in 1:2) {
      er <- cross_enc$encrypted_results
      if (is.matrix(er)) {
        ct <- er[i, j]
      } else {
        ct <- er[[i]][j]
      }

      # Party 0 partial decrypt
      .mhe_storage$secret_key <- sk0
      mheStoreCTChunkDS(chunk_index = 1L, chunk = ct)
      pd0 <- mhePartialDecryptDS(n_chunks = 1L)

      # Party 1 partial decrypt
      .mhe_storage$secret_key <- sk1
      mheStoreCTChunkDS(chunk_index = 1L, chunk = ct)
      pd1 <- mhePartialDecryptDS(n_chunks = 1L)

      # Client fuse (using mhe-tool binary directly)
      ct_std <- .base64url_to_base64(ct)
      shares_std <- c(
        .base64url_to_base64(pd0$decryption_share),
        .base64url_to_base64(pd1$decryption_share)
      )

      input <- list(
        ciphertext = ct_std,
        decryption_shares = as.list(shares_std),
        num_slots = as.integer(n),
        log_n = 12L,
        log_scale = 40L
      )

      input_file <- tempfile(fileext = ".json")
      output_file <- tempfile(fileext = ".json")
      jsonlite::write_json(input, input_file, auto_unbox = TRUE)

      bin_path <- .findMheTool()
      system2(bin_path, "mhe-fuse", stdin = input_file, stdout = output_file)

      output <- jsonlite::read_json(output_file, simplifyVector = TRUE)
      unlink(c(input_file, output_file))

      cross_cor[i, j] <- output$value / (n - 1)
    }
  }

  # --- Phase 6: Assemble ---
  R <- matrix(0, 4, 4)
  rownames(R) <- colnames(R) <- c("a1", "a2", "b1", "b2")
  R[1:2, 1:2] <- local_A$correlation
  R[3:4, 3:4] <- local_B$correlation
  R[1:2, 3:4] <- cross_cor
  R[3:4, 1:2] <- t(cross_cor)

  # Verify: MHE result should match local correlation within CKKS precision
  max_error <- max(abs(R - expected_R))
  expect_lt(max_error, 0.05)  # CKKS approximation error < 5%

  # Diagonal should be exactly 1 (from local cors)
  expect_equal(unname(diag(R)), rep(1, 4), tolerance = 1e-10)

  # Clean up
  rm("D_A", "D_B", envir = .GlobalEnv)
  .mhe_storage$secret_key <- NULL
  .mhe_storage$cpk <- NULL
})
