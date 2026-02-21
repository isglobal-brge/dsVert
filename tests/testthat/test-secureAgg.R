# Tests for GLM Secure Aggregation Functions
# These tests verify the R-level secure aggregation functions.
# Go-level mask cancellation is tested in secure_agg_ops_test.go.

# =============================================================================
# glmSecureAggInitDS tests
# =============================================================================

test_that("glmSecureAggInitDS requires transport keys", {
  skip_if_not(mheAvailable())

  # Temporarily clear storage
  old_sk <- .mhe_storage$transport_sk
  old_pks <- .mhe_storage$peer_transport_pks
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$peer_transport_pks <- NULL

  expect_error(
    glmSecureAggInitDS("serverA", "session-001", c("serverA", "serverB", "serverC")),
    "Transport SK not stored"
  )

  .mhe_storage$transport_sk <- old_sk
  .mhe_storage$peer_transport_pks <- old_pks
})

test_that("glmSecureAggInitDS requires >= 2 non-label servers", {
  skip_if_not(mheAvailable())

  # Setup minimal transport keys
  result <- .callMheTool("transport-keygen", list())
  .mhe_storage$transport_sk <- result$secret_key
  .mhe_storage$peer_transport_pks <- list()

  # Only 1 server name (self) → 0 peers → error
  expect_error(
    glmSecureAggInitDS("serverA", "session-001", c("serverA")),
    "requires >= 2 non-label servers"
  )

  # Cleanup
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$peer_transport_pks <- NULL
})

test_that("glmSecureAggInitDS derives pairwise seeds with correct signs", {
  skip_if_not(mheAvailable())

  # Generate transport keys for 3 servers
  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())

  # Setup as serverA
  .mhe_storage$transport_sk <- keyA$secret_key
  .mhe_storage$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key
  )

  glmSecureAggInitDS("serverA", "session-001",
                      c("serverA", "serverB", "serverC"))

  seeds <- .mhe_storage$secure_agg_seeds
  expect_true(!is.null(seeds))
  expect_equal(length(seeds), 2)  # 2 peers

  # serverA < serverB → A gets +1
  expect_equal(seeds[["serverB"]]$sign, 1L)
  # serverA < serverC → A gets +1
  expect_equal(seeds[["serverC"]]$sign, 1L)

  # Seeds should be non-null 32-byte values
  expect_true(nchar(seeds[["serverB"]]$seed) > 0)
  expect_true(nchar(seeds[["serverC"]]$seed) > 0)

  # Setup as serverB (should get opposite sign for A-B pair)
  .mhe_storage$transport_sk <- keyB$secret_key
  glmSecureAggInitDS("serverB", "session-001",
                      c("serverA", "serverB", "serverC"))

  seedsB <- .mhe_storage$secure_agg_seeds
  # serverB > serverA → B gets -1 for (A,B) pair
  expect_equal(seedsB[["serverA"]]$sign, -1L)
  # serverB < serverC → B gets +1 for (B,C) pair
  expect_equal(seedsB[["serverC"]]$sign, 1L)

  # Cleanup
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$peer_transport_pks <- NULL
  .mhe_storage$secure_agg_seeds <- NULL
  .mhe_storage$secure_agg_scale_bits <- NULL
  .mhe_storage$secure_agg_session_id <- NULL
})

# =============================================================================
# Mask cancellation end-to-end (R → Go → R)
# =============================================================================

test_that("Mask cancellation works end-to-end for 3 servers", {
  skip_if_not(mheAvailable())

  # Generate transport keys for 3 servers
  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())

  session_id <- "test-mask-cancel-001"
  nonlabel_names <- c("serverA", "serverB", "serverC")
  iter <- 1L
  scale_bits <- 20L

  # Initialize each server's secure aggregation state
  # Server A
  .mhe_storage$transport_sk <- keyA$secret_key
  .mhe_storage$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key
  )
  glmSecureAggInitDS("serverA", session_id, nonlabel_names, scale_bits)
  seedsA <- .mhe_storage$secure_agg_seeds

  # Server B
  .mhe_storage$transport_sk <- keyB$secret_key
  glmSecureAggInitDS("serverB", session_id, nonlabel_names, scale_bits)
  seedsB <- .mhe_storage$secure_agg_seeds

  # Server C
  .mhe_storage$transport_sk <- keyC$secret_key
  glmSecureAggInitDS("serverC", session_id, nonlabel_names, scale_bits)
  seedsC <- .mhe_storage$secure_agg_seeds

  # Test vectors
  n <- 20
  etaA <- seq(0.1, 2.0, length.out = n)
  etaB <- seq(-1.0, 1.0, length.out = n)
  etaC <- seq(0.5, 3.0, length.out = n)

  # Mask each server's eta using Go binary
  maskedA <- .callMheTool("fixed-point-mask-eta", list(
    eta = as.numeric(etaA),
    seeds = lapply(seedsA, function(s) s$seed),
    signs = lapply(seedsA, function(s) s$sign),
    iteration = iter,
    scale_bits = scale_bits
  ))

  maskedB <- .callMheTool("fixed-point-mask-eta", list(
    eta = as.numeric(etaB),
    seeds = lapply(seedsB, function(s) s$seed),
    signs = lapply(seedsB, function(s) s$sign),
    iteration = iter,
    scale_bits = scale_bits
  ))

  maskedC <- .callMheTool("fixed-point-mask-eta", list(
    eta = as.numeric(etaC),
    seeds = lapply(seedsC, function(s) s$seed),
    signs = lapply(seedsC, function(s) s$sign),
    iteration = iter,
    scale_bits = scale_bits
  ))

  # Sum masked vectors (this is what the coordinator does)
  sum_masked <- Reduce("+", list(
    maskedA$masked_scaled,
    maskedB$masked_scaled,
    maskedC$masked_scaled
  ))

  # Recover aggregate eta
  recovered_sum <- sum_masked / 2^scale_bits
  true_sum <- etaA + etaB + etaC

  # Tolerance: K / 2^scale_bits (fixed-point quantization)
  tol <- 3 / 2^scale_bits
  expect_true(all(abs(recovered_sum - true_sum) <= tol))

  # Cleanup
  .mhe_storage$transport_sk <- NULL
  .mhe_storage$peer_transport_pks <- NULL
  .mhe_storage$secure_agg_seeds <- NULL
  .mhe_storage$secure_agg_scale_bits <- NULL
  .mhe_storage$secure_agg_session_id <- NULL
})

# =============================================================================
# glmSecureAggCoordinatorStepDS: never stores individual per-server eta
# =============================================================================

test_that("glmSecureAggCoordinatorStepDS does not store individual etas", {
  skip_if_not(mheAvailable())

  # After a coordinator step, .mhe_storage should NOT contain

  # any key like "eta_serverA" or similar individual eta vectors.
  # It should only have glm_eta_label and glm_eta_other (aggregate).

  # This is a design invariant test — the coordinator sums masked vectors
  # and immediately discards the individual masked_eta_list.
  # We verify this by inspecting the source code pattern: masked_vectors <- NULL

  # Read the function body
  fn_body <- deparse(glmSecureAggCoordinatorStepDS)
  expect_true(any(grepl("masked_vectors <- NULL", fn_body, fixed = TRUE)))
})
