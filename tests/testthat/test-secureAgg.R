# Tests for GLM Secure Aggregation Functions
# These tests verify the R-level secure aggregation functions.
# Go-level mask cancellation is tested in secure_agg_ops_test.go.

# =============================================================================
# glmSecureAggInitDS tests
# =============================================================================

test_that("glmSecureAggInitDS requires transport keys", {
  skip_if_not(mheAvailable())

  sid <- "session-001"
  ss <- dsVert:::.S(sid)

  # Ensure transport keys are absent
  ss$transport_sk <- NULL
  ss$peer_transport_pks <- NULL

  expect_error(
    glmSecureAggInitDS("serverA", sid, c("serverA", "serverB", "serverC")),
    "Transport SK not stored"
  )

  dsVert:::.cleanup_session(sid)
})

test_that("glmSecureAggInitDS requires >= 2 non-label servers", {
  skip_if_not(mheAvailable())

  sid <- "session-001"
  ss <- dsVert:::.S(sid)

  # Setup minimal transport keys in session-scoped storage
  result <- .callMheTool("transport-keygen", list())
  ss$transport_sk <- result$secret_key
  ss$peer_transport_pks <- list()

  # Only 1 server name (self) → 0 peers → error
  expect_error(
    glmSecureAggInitDS("serverA", sid, c("serverA")),
    "requires >= 2 non-label servers"
  )

  # Cleanup
  dsVert:::.cleanup_session(sid)
})

test_that("glmSecureAggInitDS derives pairwise seeds with correct signs", {
  skip_if_not(mheAvailable())

  sid <- "session-001"
  ss <- dsVert:::.S(sid)

  # Generate transport keys for 3 servers
  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())

  # Setup as serverA
  ss$transport_sk <- keyA$secret_key
  ss$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key
  )

  glmSecureAggInitDS("serverA", sid,
                      c("serverA", "serverB", "serverC"))

  seeds <- ss$secure_agg_seeds
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
  ss$transport_sk <- keyB$secret_key
  glmSecureAggInitDS("serverB", sid,
                      c("serverA", "serverB", "serverC"))

  seedsB <- ss$secure_agg_seeds
  # serverB > serverA → B gets -1 for (A,B) pair
  expect_equal(seedsB[["serverA"]]$sign, -1L)
  # serverB < serverC → B gets +1 for (B,C) pair
  expect_equal(seedsB[["serverC"]]$sign, 1L)

  # Cleanup
  dsVert:::.cleanup_session(sid)
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

  # Each server has its own session (as on separate Opal nodes)
  sidA <- "test-mask-cancel-A"
  sidB <- "test-mask-cancel-B"
  sidC <- "test-mask-cancel-C"
  nonlabel_names <- c("serverA", "serverB", "serverC")
  iter <- 1L
  scale_bits <- 20L

  pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key
  )

  # Initialize each server's secure aggregation state
  # Server A
  ssA <- dsVert:::.S(sidA)
  ssA$transport_sk <- keyA$secret_key
  ssA$peer_transport_pks <- pks
  glmSecureAggInitDS("serverA", sidA, nonlabel_names, scale_bits)
  seedsA <- ssA$secure_agg_seeds

  # Server B
  ssB <- dsVert:::.S(sidB)
  ssB$transport_sk <- keyB$secret_key
  ssB$peer_transport_pks <- pks
  glmSecureAggInitDS("serverB", sidB, nonlabel_names, scale_bits)
  seedsB <- ssB$secure_agg_seeds

  # Server C
  ssC <- dsVert:::.S(sidC)
  ssC$transport_sk <- keyC$secret_key
  ssC$peer_transport_pks <- pks
  glmSecureAggInitDS("serverC", sidC, nonlabel_names, scale_bits)
  seedsC <- ssC$secure_agg_seeds

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
  dsVert:::.cleanup_session(sidA)
  dsVert:::.cleanup_session(sidB)
  dsVert:::.cleanup_session(sidC)
})

# =============================================================================
# Ring topology: K=4 derives only 2 seeds per server
# =============================================================================

test_that("Ring topology derives exactly 2 seeds per server for K=4", {
  skip_if_not(mheAvailable())

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())
  keyD <- .callMheTool("transport-keygen", list())

  pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key,
    serverD = keyD$public_key
  )
  nonlabel_names <- c("serverA", "serverB", "serverC", "serverD")

  # Test each server with ring topology
  for (info in list(
    list(name = "serverA", sk = keyA$secret_key),
    list(name = "serverB", sk = keyB$secret_key),
    list(name = "serverC", sk = keyC$secret_key),
    list(name = "serverD", sk = keyD$secret_key)
  )) {
    sid <- paste0("test-ring-", info$name)
    ss <- dsVert:::.S(sid)
    ss$transport_sk <- info$sk
    ss$peer_transport_pks <- pks

    glmSecureAggInitDS(info$name, sid, nonlabel_names,
                        scale_bits = 20L, topology = "ring")

    seeds <- ss$secure_agg_seeds
    # Ring topology: exactly 2 peers (prev + next in sorted circular order)
    expect_equal(length(seeds), 2,
                 label = paste("seed count for", info$name))

    dsVert:::.cleanup_session(sid)
  }
})

test_that("Ring topology mask cancellation works for K=4", {
  skip_if_not(mheAvailable())

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())
  keyD <- .callMheTool("transport-keygen", list())

  pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key,
    serverD = keyD$public_key
  )
  nonlabel_names <- c("serverA", "serverB", "serverC", "serverD")
  iter <- 1L
  scale_bits <- 20L
  n <- 15

  # Initialize all 4 servers with ring topology
  sessions <- list()
  seeds_all <- list()
  keys <- list(serverA = keyA, serverB = keyB, serverC = keyC, serverD = keyD)

  for (name in nonlabel_names) {
    sid <- paste0("test-ring-cancel-", name)
    sessions[[name]] <- sid
    ss <- dsVert:::.S(sid)
    ss$transport_sk <- keys[[name]]$secret_key
    ss$peer_transport_pks <- pks
    glmSecureAggInitDS(name, sid, nonlabel_names, scale_bits, topology = "ring")
    seeds_all[[name]] <- ss$secure_agg_seeds
  }

  # Test vectors
  etas <- list(
    serverA = seq(0.1, 1.5, length.out = n),
    serverB = seq(-1.0, 0.5, length.out = n),
    serverC = seq(0.2, 2.0, length.out = n),
    serverD = seq(-0.5, 1.0, length.out = n)
  )

  # Mask each server's eta
  masked_all <- list()
  for (name in nonlabel_names) {
    seeds <- seeds_all[[name]]
    masked <- .callMheTool("fixed-point-mask-eta", list(
      eta = as.numeric(etas[[name]]),
      seeds = lapply(seeds, function(s) s$seed),
      signs = lapply(seeds, function(s) s$sign),
      iteration = iter,
      scale_bits = scale_bits
    ))
    masked_all[[name]] <- masked$masked_scaled
  }

  # Sum all masked vectors
  sum_masked <- Reduce("+", masked_all)
  recovered_sum <- sum_masked / 2^scale_bits
  true_sum <- Reduce("+", etas)

  # Tolerance: K / 2^scale_bits
  tol <- 4 / 2^scale_bits
  expect_true(all(abs(recovered_sum - true_sum) <= tol))

  # Cleanup
  for (sid in sessions) dsVert:::.cleanup_session(sid)
})

test_that("Ring topology falls back to pairwise for K=3", {
  skip_if_not(mheAvailable())

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())

  pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key
  )

  sid <- "test-ring-k3"
  ss <- dsVert:::.S(sid)
  ss$transport_sk <- keyA$secret_key
  ss$peer_transport_pks <- pks

  # Ring with K=3: ring and pairwise are identical (each server has 2 peers)
  glmSecureAggInitDS("serverA", sid, c("serverA", "serverB", "serverC"),
                      scale_bits = 20L, topology = "ring")

  seeds <- ss$secure_agg_seeds
  # K=3: each server always has 2 peers regardless of topology
  expect_equal(length(seeds), 2)

  dsVert:::.cleanup_session(sid)
})

test_that("Pairwise topology K=4 derives 3 seeds per server", {
  skip_if_not(mheAvailable())

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())
  keyC <- .callMheTool("transport-keygen", list())
  keyD <- .callMheTool("transport-keygen", list())

  pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key,
    serverC = keyC$public_key,
    serverD = keyD$public_key
  )

  sid <- "test-pairwise-k4"
  ss <- dsVert:::.S(sid)
  ss$transport_sk <- keyA$secret_key
  ss$peer_transport_pks <- pks

  glmSecureAggInitDS("serverA", sid,
                      c("serverA", "serverB", "serverC", "serverD"),
                      scale_bits = 20L, topology = "pairwise")

  seeds <- ss$secure_agg_seeds
  # Pairwise K=4: 3 peers per server
  expect_equal(length(seeds), 3)

  dsVert:::.cleanup_session(sid)
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
