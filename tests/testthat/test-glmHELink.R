# Tests for HE-Link GLM Protocol functions (glmHELinkDS.R)

skip_if_not(mheAvailable(), "MHE tool binary not available")

# =============================================================================
# Test glmHEEncryptEtaDS
# =============================================================================

test_that("glmHEEncryptEtaDS errors without CPK", {
  .mhe_storage$cpk <- NULL
  expect_error(
    glmHEEncryptEtaDS("D", c("x"), beta = c(1.0)),
    "CPK not stored"
  )
})

test_that("glmHEEncryptEtaDS errors with mismatched beta length", {
  # Setup minimal state with CPK
  r0 <- mheInitDS(party_id = 0L, crp = NULL, num_obs = 30L,
                  log_n = 14L, log_scale = 40L)
  combined <- mheCombineDS(
    public_key_shares = c(r0$public_key_share),
    crp = r0$crp, num_obs = 30L, log_n = 14L, log_scale = 40L
  )

  test_data <- data.frame(x1 = rnorm(30), x2 = rnorm(30))
  assign("D_he_test", test_data, envir = .GlobalEnv)

  expect_error(
    glmHEEncryptEtaDS("D_he_test", c("x1", "x2"), beta = c(1.0)),
    "beta length"
  )

  rm("D_he_test", envir = .GlobalEnv)
  mheCleanupDS()
})

test_that("glmHEEncryptEtaDS returns encrypted ciphertext", {
  # Full setup with logN=14 for HE-Link
  r0 <- mheInitDS(party_id = 0L, crp = NULL, num_obs = 30L,
                  log_n = 14L, log_scale = 40L)
  combined <- mheCombineDS(
    public_key_shares = c(r0$public_key_share),
    crp = r0$crp, num_obs = 30L, log_n = 14L, log_scale = 40L
  )

  set.seed(42)
  test_data <- data.frame(x1 = rnorm(30), x2 = rnorm(30))
  assign("D_he_test", test_data, envir = .GlobalEnv)

  result <- glmHEEncryptEtaDS("D_he_test", c("x1", "x2"), beta = c(0.5, -0.3))

  expect_type(result, "list")
  expect_true("encrypted_eta" %in% names(result))
  expect_true("num_obs" %in% names(result))
  expect_equal(result$num_obs, 30)
  expect_type(result$encrypted_eta, "character")
  expect_gt(nchar(result$encrypted_eta), 100)

  rm("D_he_test", envir = .GlobalEnv)
  mheCleanupDS()
})

# =============================================================================
# Test glmHELinkStepDS
# =============================================================================

test_that("glmHELinkStepDS errors without RLK", {
  .mhe_storage$relin_key <- NULL
  expect_error(
    glmHELinkStepDS(from_storage = TRUE, n_parties = 2),
    "Relinearization key not stored"
  )
})

test_that("glmHELinkStepDS errors without blobs", {
  .mhe_storage$relin_key <- "dummy_rlk"
  .mhe_storage$blobs <- NULL
  expect_error(
    glmHELinkStepDS(from_storage = TRUE, n_parties = 2),
    "No blobs stored"
  )
  .mhe_storage$relin_key <- NULL
})

# =============================================================================
# Test glmHEGradientEncDS
# =============================================================================

test_that("glmHEGradientEncDS errors without encrypted mu", {
  .mhe_storage$ct_mu <- NULL
  .mhe_storage$blobs <- NULL
  expect_error(
    glmHEGradientEncDS("D", c("x"), num_obs = 30L, from_storage = FALSE),
    "Encrypted mu not available"
  )
})

test_that("glmHEGradientEncDS errors without encrypted y", {
  .mhe_storage$ct_mu <- "dummy_ct_mu"
  .mhe_storage$enc_y <- NULL
  .mhe_storage$remote_enc_cols <- NULL
  expect_error(
    glmHEGradientEncDS("D", c("x"), num_obs = 30L, from_storage = FALSE),
    "Encrypted y not stored"
  )
  .mhe_storage$ct_mu <- NULL
})

test_that("glmHEGradientEncDS errors without Galois keys", {
  .mhe_storage$ct_mu <- "dummy"
  .mhe_storage$enc_y <- "dummy"
  .mhe_storage$galois_keys <- NULL

  set.seed(42)
  test_data <- data.frame(x = rnorm(30))
  assign("D_gk_test", test_data, envir = .GlobalEnv)

  expect_error(
    glmHEGradientEncDS("D_gk_test", c("x"), num_obs = 30L, from_storage = FALSE),
    "Galois keys not available"
  )

  rm("D_gk_test", envir = .GlobalEnv)
  .mhe_storage$ct_mu <- NULL
  .mhe_storage$enc_y <- NULL
})

# =============================================================================
# Test glmHEBlockUpdateDS
# =============================================================================

test_that("glmHEBlockUpdateDS performs correct GD update", {
  beta <- c(1.0, 2.0)
  gradient <- c(10.0, -5.0)
  alpha <- 0.1
  lambda <- 0.01
  n_obs <- 100L

  result <- glmHEBlockUpdateDS(beta, gradient, alpha = alpha,
                                lambda = lambda, n_obs = n_obs)

  expect_type(result, "list")
  expect_true("beta" %in% names(result))
  expect_length(result$beta, 2)

  # Verify update formula: beta_new = beta_old + alpha * (g/n - lambda * beta_old)
  expected <- beta + alpha * (gradient / n_obs - lambda * beta)
  expect_equal(result$beta, expected)
})

test_that("glmHEBlockUpdateDS errors with mismatched lengths", {
  expect_error(
    glmHEBlockUpdateDS(c(1, 2), c(1, 2, 3), n_obs = 100L),
    "beta_current length"
  )
})

test_that("glmHEBlockUpdateDS scales large coefficients", {
  expect_warning(
    result <- glmHEBlockUpdateDS(c(1e7, -1e7), c(0, 0),
                                  alpha = 1, lambda = 0, n_obs = 1L),
    "Large coefficient update"
  )
  expect_true(all(abs(result$beta) <= 1e2 + 0.01))
})

# =============================================================================
# Test glmHEPrepDevianceDS
# =============================================================================

test_that("glmHEPrepDevianceDS stores eta locally for coordinator", {
  .mhe_storage$glm_eta_label <- NULL
  .mhe_storage$glm_eta_other <- NULL

  set.seed(42)
  test_data <- data.frame(x1 = rnorm(30), x2 = rnorm(30))
  assign("D_dev_test", test_data, envir = .GlobalEnv)

  result <- glmHEPrepDevianceDS("D_dev_test", c("x1", "x2"),
                                 beta = c(0.5, -0.3),
                                 coordinator_pk = NULL)

  expect_null(result$encrypted_eta)
  expect_false(is.null(.mhe_storage$glm_eta_label))
  expect_length(.mhe_storage$glm_eta_label, 30)

  # Verify: eta_label should equal X * beta
  X <- as.matrix(test_data[, c("x1", "x2")])
  expected_eta <- as.vector(X %*% c(0.5, -0.3))
  expect_equal(.mhe_storage$glm_eta_label, expected_eta)

  rm("D_dev_test", envir = .GlobalEnv)
  .mhe_storage$glm_eta_label <- NULL
  .mhe_storage$glm_eta_other <- NULL
})

# =============================================================================
# Test RLK round functions
# =============================================================================

test_that("mheRLKAggregateR1DS errors without blobs", {
  .mhe_storage$blobs <- NULL
  expect_error(
    mheRLKAggregateR1DS(from_storage = TRUE, n_parties = 2),
    "No blobs stored"
  )
})

test_that("mheRLKRound2DS errors without secret key", {
  .mhe_storage$secret_key <- NULL
  expect_error(
    mheRLKRound2DS(),
    "Secret key not stored"
  )
})

test_that("mheRLKRound2DS errors without ephemeral SK", {
  .mhe_storage$secret_key <- "dummy"
  .mhe_storage$rlk_ephemeral_sk <- NULL
  expect_error(
    mheRLKRound2DS(),
    "RLK ephemeral SK not stored"
  )
  .mhe_storage$secret_key <- NULL
})

# =============================================================================
# End-to-end: 2-party HE-Link key setup with RLK generation
# =============================================================================

test_that("Full 2-party RLK generation produces valid relinearization key", {
  save_state <- function() as.list(.mhe_storage)
  restore_state <- function(state) {
    rm(list = ls(.mhe_storage), envir = .mhe_storage)
    for (nm in names(state)) .mhe_storage[[nm]] <- state[[nm]]
  }

  # Party 0: generate keys + RLK round 1
  r0 <- mheInitDS(party_id = 0L, crp = NULL, gkg_seed = NULL,
                  num_obs = 30L, log_n = 14L, log_scale = 40L,
                  generate_rlk = TRUE)
  state0 <- save_state()

  expect_true(!is.null(r0$rlk_round1_share))
  expect_type(r0$rlk_round1_share, "character")
  expect_gt(nchar(r0$rlk_round1_share), 100)

  # Party 1: generate keys + RLK round 1
  r1 <- mheInitDS(party_id = 1L, crp = r0$crp, gkg_seed = r0$gkg_seed,
                  num_obs = 30L, log_n = 14L, log_scale = 40L,
                  generate_rlk = TRUE)
  state1 <- save_state()

  expect_true(!is.null(r1$rlk_round1_share))

  # RLK Round 1 aggregation on party 0 (coordinator)
  restore_state(state0)
  mheStoreBlobDS("rlk_r1_0", r0$rlk_round1_share)
  mheStoreBlobDS("rlk_r1_1", r1$rlk_round1_share)
  agg_r1 <- mheRLKAggregateR1DS(from_storage = TRUE, n_parties = 2L)
  state0 <- save_state()

  expect_type(agg_r1$aggregated_round1, "character")
  expect_gt(nchar(agg_r1$aggregated_round1), 100)

  # RLK Round 2: party 0
  restore_state(state0)
  r2_0 <- mheRLKRound2DS(from_storage = FALSE)
  state0 <- save_state()

  expect_type(r2_0$rlk_round2_share, "character")

  # RLK Round 2: party 1
  restore_state(state1)
  mheStoreBlobDS("rlk_agg_r1", agg_r1$aggregated_round1)
  r2_1 <- mheRLKRound2DS(from_storage = TRUE)
  state1 <- save_state()

  expect_type(r2_1$rlk_round2_share, "character")

  # Combine: party 0 combines all keys including RLK
  restore_state(state0)
  mheStoreBlobDS("pk_0", r0$public_key_share)
  mheStoreBlobDS("pk_1", r1$public_key_share)
  mheStoreBlobDS("crp", r0$crp)
  mheStoreBlobDS("gkg_seed", r0$gkg_seed)
  for (j in seq_along(r0$galois_key_shares)) {
    mheStoreBlobDS(paste0("gkg_0_", j - 1), r0$galois_key_shares[j])
    mheStoreBlobDS(paste0("gkg_1_", j - 1), r1$galois_key_shares[j])
  }
  mheStoreBlobDS("rlk_agg_r1", agg_r1$aggregated_round1)
  mheStoreBlobDS("rlk_r2_0", r2_0$rlk_round2_share)
  mheStoreBlobDS("rlk_r2_1", r2_1$rlk_round2_share)

  combined <- mheCombineDS(
    from_storage = TRUE,
    n_parties = 2L,
    n_gkg_shares = as.integer(length(r0$galois_key_shares)),
    num_obs = 30L, log_n = 14L, log_scale = 40L
  )

  expect_type(combined$collective_public_key, "character")
  expect_true(!is.null(combined$relin_key))
  expect_gt(nchar(combined$relin_key), 100)

  # Verify RLK is stored in .mhe_storage
  expect_true(!is.null(.mhe_storage$relin_key))
  expect_gt(nchar(.mhe_storage$relin_key), 100)

  mheCleanupDS()
})

# Final cleanup
mheCleanupDS()
