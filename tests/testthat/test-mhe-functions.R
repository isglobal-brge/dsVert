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
# Test share-wrapping functions (transport keys, wrapped decrypt, fusion)
# =============================================================================

test_that("mheStoreTransportKeysDS errors without initialization", {
  .mhe_storage$secret_key <- NULL
  expect_error(
    mheStoreTransportKeysDS(list(fusion = "dGVzdA")),
    "MHE not initialized"
  )
})

test_that("mhePartialDecryptWrappedDS errors without fusion transport PK", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$ct_chunks <- list("dummy_chunk")
  .mhe_storage$peer_transport_pks <- NULL
  expect_error(
    mhePartialDecryptWrappedDS(n_chunks = 1L),
    "Fusion server transport PK not stored"
  )
  .mhe_storage$secret_key <- NULL
  .mhe_storage$ct_chunks <- NULL
})

test_that("mheFuseServerDS errors without transport SK", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$ct_chunks <- list("dummy")
  expect_error(
    mheFuseServerDS(n_parties = 2L, n_ct_chunks = 1L),
    "Transport secret key not stored"
  )
  .mhe_storage$secret_key <- NULL
  .mhe_storage$ct_chunks <- NULL
})

test_that("mheFuseServerDS errors without wrapped shares", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$transport_sk <- "dummy"
  .mhe_storage$ct_chunks <- list("dummy")
  .mhe_storage$ct_registry <- list()
  .mhe_storage$wrapped_share_parts <- NULL
  # Need to register a fake CT hash so the firewall doesn't block first
  ct_b64 <- .base64url_to_base64("dummy")
  .register_ciphertext(ct_b64, "test")
  expect_error(
    mheFuseServerDS(n_parties = 2L, n_ct_chunks = 1L),
    "No wrapped shares stored"
  )
  .mhe_storage$secret_key <- NULL
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$ct_chunks <- NULL
  .mhe_storage$ct_registry <- NULL
})

test_that("mheStoreWrappedShareDS stores and concatenates chunks", {
  .mhe_storage$wrapped_share_parts <- NULL
  expect_true(mheStoreWrappedShareDS(party_id = 1L, share_data = "AAA"))
  expect_true(mheStoreWrappedShareDS(party_id = 1L, share_data = "BBB"))
  expect_equal(.mhe_storage$wrapped_share_parts[["1"]], "AAABBB")
  .mhe_storage$wrapped_share_parts <- NULL
})

test_that("mheAuthorizeCTDS registers ciphertext hashes", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$ct_registry <- NULL
  .mhe_storage$op_counter <- NULL

  n_auth <- mheAuthorizeCTDS(c("hash1", "hash2", "hash3"), op_type = "cross-product")
  expect_equal(n_auth, 3)
  expect_equal(length(.mhe_storage$ct_registry), 3)
  expect_true("hash1" %in% names(.mhe_storage$ct_registry))

  .mhe_storage$secret_key <- NULL
  .mhe_storage$ct_registry <- NULL
  .mhe_storage$op_counter <- NULL
})

test_that("mheStoreBlobDS stores and auto-assembles chunks", {
  .mhe_storage$blobs <- NULL
  .mhe_storage$blob_chunks <- NULL

  # Single-call mode
  expect_true(mheStoreBlobDS(key = "test1", chunk = "hello"))
  expect_equal(.mhe_storage$blobs[["test1"]], "hello")

  # Chunked mode: auto-assembles when all chunks arrive
  expect_true(mheStoreBlobDS(key = "test2", chunk = "AA", chunk_index = 1L, n_chunks = 3L))
  expect_true(mheStoreBlobDS(key = "test2", chunk = "BB", chunk_index = 2L, n_chunks = 3L))
  expect_null(.mhe_storage$blobs[["test2"]])
  expect_true(mheStoreBlobDS(key = "test2", chunk = "CC", chunk_index = 3L, n_chunks = 3L))
  expect_equal(.mhe_storage$blobs[["test2"]], "AABBCC")

  .mhe_storage$blobs <- NULL
  .mhe_storage$blob_chunks <- NULL
})

# =============================================================================
# End-to-End: Full 2-party threshold protocol with share-wrapped fusion
# =============================================================================

test_that("Full 2-party threshold MHE with share-wrapped fusion produces correct correlation", {
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

  # Helpers to save/restore party state (single-process simulation)
  save_state <- function() as.list(.mhe_storage)
  restore_state <- function(state) {
    rm(list = ls(.mhe_storage), envir = .mhe_storage)
    for (nm in names(state)) .mhe_storage[[nm]] <- state[[nm]]
  }

  # --- Phase 1: Key generation ---
  # Party 0 (fusion server): generates CRP and GKG seed
  r0 <- mheInitDS(party_id = 0L, crp = NULL, gkg_seed = NULL,
                  num_obs = as.integer(n), log_n = 12L, log_scale = 40L)
  state0 <- save_state()

  # Party 1: uses party 0's CRP and GKG seed
  r1 <- mheInitDS(party_id = 1L, crp = r0$crp, gkg_seed = r0$gkg_seed,
                  num_obs = as.integer(n), log_n = 12L, log_scale = 40L)
  state1 <- save_state()

  # --- Phase 1b: Transport key distribution ---
  # Party 1 needs the fusion server's (party 0) transport PK for share-wrapping
  restore_state(state1)
  mheStoreTransportKeysDS(list(fusion = r0$transport_pk))
  state1 <- save_state()

  # Party 0 stores party 1's transport PK (needed for GLM routing, optional for correlation)
  restore_state(state0)
  mheStoreTransportKeysDS(list(fusion = r0$transport_pk, "1" = r1$transport_pk))
  state0 <- save_state()

  # --- Phase 2: Combine keys (on party 0) ---
  restore_state(state0)
  combined <- mheCombineDS(
    public_key_shares = c(r0$public_key_share, r1$public_key_share),
    crp = r0$crp,
    galois_key_shares = list(r0$galois_key_shares, r1$galois_key_shares),
    gkg_seed = r0$gkg_seed,
    num_obs = as.integer(n),
    log_n = 12L,
    log_scale = 40L
  )
  cpk <- combined$collective_public_key
  state0 <- save_state()

  # Distribute CPK + Galois keys to party 1
  restore_state(state1)
  mheStoreCPKDS(cpk = cpk, galois_keys = combined$galois_keys)
  state1 <- save_state()

  # --- Phase 3: Encrypt data ---
  # Party 0 encrypts its columns
  restore_state(state0)
  enc_A <- mheEncryptLocalDS("D_A", c("a1", "a2"))
  state0 <- save_state()

  # Party 1 encrypts its columns
  restore_state(state1)
  enc_B <- mheEncryptLocalDS("D_B", c("b1", "b2"))
  state1 <- save_state()

  # --- Phase 4: Local correlations ---
  local_A <- localCorDS("D_A", c("a1", "a2"))
  local_B <- localCorDS("D_B", c("b1", "b2"))

  # --- Phase 5: Cross-server correlation (share-wrapped fusion) ---
  # Transfer B's encrypted columns to party 0
  restore_state(state0)
  for (k in seq_along(enc_B$encrypted_columns)) {
    mheStoreEncChunkDS(col_index = as.integer(k), chunk_index = 1L,
                       chunk = enc_B$encrypted_columns[[k]])
    mheAssembleEncColumnDS(col_index = as.integer(k), n_chunks = 1L)
  }

  # Compute encrypted cross-product on party 0 (registers CTs in protocol firewall)
  cross_enc <- mheCrossProductEncDS("D_A", c("a1", "a2"),
                                     n_enc_cols = 2L, n_obs = as.integer(n))
  ct_hashes <- cross_enc$ct_hashes
  state0 <- save_state()

  # Authorize CTs on party 1 (relay ct_hashes so party 1's firewall accepts them)
  restore_state(state1)
  mheAuthorizeCTDS(ct_hashes, op_type = "cross-product")
  state1 <- save_state()

  # Threshold decryption with share-wrapping + server-side fusion
  cross_cor <- matrix(NA, 2, 2)
  er <- cross_enc$encrypted_results

  for (i in 1:2) {
    for (j in 1:2) {
      if (is.matrix(er)) {
        ct <- er[i, j]
      } else {
        ct <- er[[i]][j]
      }

      # Step 1: Party 1 computes wrapped partial decryption share
      restore_state(state1)
      mheStoreCTChunkDS(chunk_index = 1L, chunk = ct)
      pd1 <- mhePartialDecryptWrappedDS(n_chunks = 1L)
      state1 <- save_state()

      # Step 2: Client relays wrapped share to fusion server (party 0)
      restore_state(state0)
      mheStoreWrappedShareDS(party_id = 1L, share_data = pd1$wrapped_share)

      # Step 3: Fusion server unwraps + fuses all shares server-side
      mheStoreCTChunkDS(chunk_index = 1L, chunk = ct)
      fused <- mheFuseServerDS(n_parties = 2L, n_ct_chunks = 1L, num_slots = as.integer(n))
      state0 <- save_state()

      cross_cor[i, j] <- fused$value / (n - 1)
    }
  }

  # --- Phase 6: Assemble full correlation matrix ---
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
  mheCleanupDS()
})
