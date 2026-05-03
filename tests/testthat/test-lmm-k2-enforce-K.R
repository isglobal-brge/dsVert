# Tests for the .k2_enforce_K guards on LMM K=2 entry points
# (worker2-lmm-k2-guards-2026-04-28). The LMM closed-form GLS
# driver requires exactly K=2 servers (ds.vertLMM.closed_form.R:17,
# 53), so each LMM DS function below is a K=2-specific entry point
# and must refuse cross-K calls per the same defense-in-depth pattern
# applied to ord_joint / mnl_joint / NB / Cox K=2 / GLM K=2 in
# Q4(B+) commit dsVert 566c938.
#
# Pattern: stub a fresh session via .S(), set
# ss$peer_transport_pks to a list of length 2 (= K=3) or 1 (= K=2),
# call the function, expect stop on K mismatch.

library(testthat)

.mk_session <- function(K) {
  sid <- paste0("test-lmm-k2enforceK-", K, "-",
                  format(Sys.time(), "%H%M%OS3"),
                  "-", sample.int(1e6, 1L))
  ss <- dsVert:::.S(sid)
  if (K >= 2L) {
    ss$peer_transport_pks <- as.list(seq_len(K - 1L))
  }
  list(sid = sid, ss = ss)
}

# --- ClusterBroadcast family ---
test_that("dsvertLMMBroadcastClusterIDsDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMBroadcastClusterIDsDS(
      data_name = "fake", cluster_col = "cluster",
      peer_pk = "pk", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMReceiveClusterIDsDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMReceiveClusterIDsDS(session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMPerClusterSumDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMPerClusterSumDS(
      share_key = "fake", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("LMM cluster broadcast fails closed below privacyLevel", {
  old_opt <- getOption("datashield.privacyLevel", 5L)
  options(datashield.privacyLevel = 5L)
  on.exit(options(datashield.privacyLevel = old_opt), add = TRUE)
  s <- .mk_session(2L)
  D <- data.frame(cluster = c(1L, 1L, rep(2L, 5L)))
  expect_error(
    dsVert::dsvertLMMBroadcastClusterIDsDS(
      data_name = "D", cluster_col = "cluster",
      peer_pk = "not-needed", session_id = s$sid),
    "cluster size below datashield\\.privacyLevel")
})

test_that("LMM per-cluster sums fail closed below privacyLevel", {
  old_opt <- getOption("datashield.privacyLevel", 5L)
  options(datashield.privacyLevel = 5L)
  on.exit(options(datashield.privacyLevel = old_opt), add = TRUE)
  s <- .mk_session(2L)
  s$ss$k2_lmm_cluster_ids <- c(1L, 1L, rep(2L, 5L))
  s$ss$dummy_share <- "unused-because-privacy-guard-runs-first"
  expect_error(
    dsVert::dsvertLMMPerClusterSumDS(
      share_key = "dummy_share", session_id = s$sid),
    "cluster size below datashield\\.privacyLevel")
})

test_that("stored LMM X covariance avoids client-supplied cluster vector", {
  old_opt <- getOption("datashield.privacyLevel", 5L)
  options(datashield.privacyLevel = 5L)
  on.exit(options(datashield.privacyLevel = old_opt), add = TRUE)
  s <- .mk_session(2L)
  D <- data.frame(
    x = c(1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
    z = c(2, 1, 3, 5, 4, 7, 6, 8, 10, 9))
  cid <- rep(1:2, each = 5L)
  s$ss$dsvert_cluster_ids <- cid
  stored <- dsVert::dsvertLMMXCovarianceWithinStoredDS(
    data_name = "D", x_vars = c("x", "z"), session_id = s$sid)
  legacy <- dsVert::dsvertLMMXCovarianceWithinDS(
    data_name = "D", x_vars = c("x", "z"), cluster_id_vector = cid)
  expect_equal(stored$SX2_within, legacy$SX2_within)
  expect_equal(stored$df_within, legacy$df_within)
})

test_that("dsvertLMMGlobalSumDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMGlobalSumDS(
      share_key = "fake", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- ExactDS family ---
test_that("dsvertLMMPeerFittedShareDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMPeerFittedShareDS(
      data_name = "fake", x_names = "x", betahat = 0.0,
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMCoordResidualShareDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMCoordResidualShareDS(
      data_name = "fake", y_var = "y", x_names = "x",
      betahat_local = 0.0, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMPeerResidualFinaliseDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMPeerResidualFinaliseDS(
      n = 10L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMExactClusterR2DS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMExactClusterR2DS(
      data_name = "fake", cluster_col = "cluster",
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- GLSTransform family ---
test_that("dsvertLMMGLSTransformDS permits K=3 session arity", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMGLSTransformDS(
      data_name = "fake", columns = "x",
      lambda_per_cluster = c(0.5, 0.5),
      session_id = s$sid),
    "object 'fake' not found")
})

test_that("dsvertLMMGLSAggregatesDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMGLSAggregatesDS(
      data_name = "fake", columns = "x",
      lambda_per_cluster = c(0.5, 0.5),
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- GramDS family ---
test_that("dsvertLMMLocalGramDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMLocalGramDS(
      data_name = "fake", columns = "x",
      lambda_per_cluster = c(0.5, 0.5),
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMReceiveGramSharesDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMReceiveGramSharesDS(session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMGramR1DS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMGramR1DS(
      peer_pk = "pk", x_col = "x", y_col = "y",
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertLMMGramR2DS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertLMMGramR2DS(
      is_party0 = TRUE, x_col = "x", y_col = "y",
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- Negative control: K=2 session does NOT trigger K-guard ---
test_that("dsvertLMMReceiveClusterIDsDS does NOT fire K-guard when K=2", {
  s <- .mk_session(2L)
  err <- tryCatch(
    dsVert::dsvertLMMReceiveClusterIDsDS(session_id = s$sid),
    error = function(e) conditionMessage(e))
  expect_false(grepl("K mismatch", err))
})

test_that("dsvertLMMGramR1DS does NOT fire K-guard when K=2", {
  s <- .mk_session(2L)
  err <- tryCatch(
    dsVert::dsvertLMMGramR1DS(
      peer_pk = "pk", x_col = "x", y_col = "y",
      session_id = s$sid),
    error = function(e) conditionMessage(e))
  expect_false(grepl("K mismatch", err))
})
