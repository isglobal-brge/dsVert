# Tests for the .k2_enforce_K server-side K-arity guard (Q4 of B+
# directive 2026-04-27). Covers:
#   1. Unit semantics of .k2_enforce_K itself (NULL bypass, match, mismatch).
#   2. Integration coverage: each of the 20 K-specific entry-point *DS
#      functions catalogued in docs/error_bounds/strict_rd_ranking_2026-04-27.md
#      §10 rejects a stubbed K=3 session with the standard message.
#
# Pattern: stub a fresh session via .S(), set
# ss$peer_transport_pks to a list of length 2 (= K=3) or 1 (= K=2),
# call the function, expect stop on mismatch.
#
# All 20 functions invoke `.k2_enforce_K(ss, 2L, "fnName")` very early,
# so the mismatch fires BEFORE any expensive setup or .callMpcTool
# round-trip. This keeps the test cheap (no MPC tool, no data frames
# beyond what the function's pre-guard validation insists on).

library(testthat)

# --- helper: build a fresh session with a configured K -----------------
.mk_session <- function(K) {
  sid <- paste0("test-k2enforceK-", K, "-",
                  format(Sys.time(), "%H%M%OS3"),
                  "-", sample.int(1e6, 1L))
  ss <- dsVert:::.S(sid)
  if (K >= 2L) {
    # peer_transport_pks length = K - 1 (this server + K-1 peers)
    ss$peer_transport_pks <- as.list(seq_len(K - 1L))
  }
  list(sid = sid, ss = ss)
}

# =====================================================================
# 1. .k2_enforce_K unit semantics
# =====================================================================

test_that(".k2_enforce_K bypasses silently when peer_transport_pks NULL", {
  ss <- new.env(parent = emptyenv())  # no peer_transport_pks slot
  expect_silent(dsVert:::.k2_enforce_K(ss, 2L, "fnX"))
  expect_silent(dsVert:::.k2_enforce_K(ss, 3L, "fnX"))
})

test_that(".k2_enforce_K passes when K matches", {
  ss <- new.env(parent = emptyenv())
  ss$peer_transport_pks <- list("pk_peer1")  # length 1 → K=2
  expect_silent(dsVert:::.k2_enforce_K(ss, 2L, "fnX"))

  ss$peer_transport_pks <- list("pk_peer1", "pk_peer2")  # length 2 → K=3
  expect_silent(dsVert:::.k2_enforce_K(ss, 3L, "fnX"))
})

test_that(".k2_enforce_K stops on K mismatch", {
  ss <- new.env(parent = emptyenv())
  ss$peer_transport_pks <- list("pk_peer1", "pk_peer2")  # K=3
  expect_error(dsVert:::.k2_enforce_K(ss, 2L, "fnX"),
                "K mismatch.*expected K=2.*got K=3", class = "simpleError")

  ss$peer_transport_pks <- list("pk_peer1")  # K=2
  expect_error(dsVert:::.k2_enforce_K(ss, 3L, "fnX"),
                "K mismatch.*expected K=3.*got K=2", class = "simpleError")
})

test_that(".k2_enforce_K embeds fn_name in error message", {
  ss <- new.env(parent = emptyenv())
  ss$peer_transport_pks <- list("pk_peer1", "pk_peer2", "pk_peer3")  # K=4
  expect_error(dsVert:::.k2_enforce_K(ss, 2L, "myFunc"),
                "myFunc.*expected K=2.*got K=4")
})

test_that(".k2_enforce_K omits fn_name when NULL", {
  ss <- new.env(parent = emptyenv())
  ss$peer_transport_pks <- list("pk_peer1", "pk_peer2")
  err <- tryCatch(dsVert:::.k2_enforce_K(ss, 2L, NULL),
                   error = function(e) conditionMessage(e))
  expect_match(err, "K mismatch")
  expect_false(grepl("\\bNULL\\b", err))
})

# =====================================================================
# 2. Integration coverage: representative entry-points reject K=3
# =====================================================================
# Every guarded function follows the pattern:
#   ss <- .S(session_id)
#   .k2_enforce_K(ss, 2L, "fnName")
# so the guard fires before any data-resolution / MPC-tool side
# effects, even with otherwise-invalid arguments.

# --- ord_joint family ---
test_that("dsvertOrdinalSealEtaDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertOrdinalSealEtaDS(
      data_name = "fake_table", x_vars = "age",
      beta_values = 0.0, target_pk = "fake_pk",
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertOrdinalPatientDiffsDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertOrdinalPatientDiffsDS(
      output_key = "out", n = 10L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertOrdinalSealFkSharesDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertOrdinalSealFkSharesDS(
      F_keys = c("k1"), target_pk = "pk", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertOrdinalReceiveBetaWeightsDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertOrdinalReceiveBetaWeightsDS(
      W_blob_key = "wblob", output_key = "out",
      n = 10L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("ordinal joint patient-level helpers are diagnostic-only by default", {
  old_opt <- getOption("dsvert.allow_patient_level_ordinal_joint", NULL)
  old_env <- Sys.getenv("DSVERT_ALLOW_PATIENT_LEVEL_ORDINAL_JOINT", unset = NA)
  on.exit({
    if (is.null(old_opt)) {
      options(dsvert.allow_patient_level_ordinal_joint = NULL)
    } else {
      options(dsvert.allow_patient_level_ordinal_joint = old_opt)
    }
    if (is.na(old_env)) {
      Sys.unsetenv("DSVERT_ALLOW_PATIENT_LEVEL_ORDINAL_JOINT")
    } else {
      Sys.setenv(DSVERT_ALLOW_PATIENT_LEVEL_ORDINAL_JOINT = old_env)
    }
  }, add = TRUE)
  options(dsvert.allow_patient_level_ordinal_joint = FALSE)
  Sys.unsetenv("DSVERT_ALLOW_PATIENT_LEVEL_ORDINAL_JOINT")

  s <- .mk_session(2L)

  expect_error(
    dsVert::dsvertOrdinalSealFkSharesDS(
      F_keys = "k1", target_pk = "pk", session_id = s$sid),
    "disabled under strict non-disclosure")

  expect_error(
    dsVert::dsvertOrdinalSealEtaDS(
      data_name = "fake_table", x_vars = "age",
      beta_values = 0.0, target_pk = "fake_pk",
      session_id = s$sid),
    "disabled under strict non-disclosure")

  expect_error(
    dsVert::dsvertOrdinalPatientDiffsDS(
      output_key = "out", n = 10L, session_id = s$sid),
    "disabled under strict non-disclosure")
})

test_that("dsvertOrdinalExtractXColumnDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertOrdinalExtractXColumnDS(
      matrix_key = "m", n = 10L, p = 3L, col_idx = 1L,
      output_key = "out", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- mnl_joint family ---
test_that("dsvertPrepareMultinomGradDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertPrepareMultinomGradDS(
      residual_key = "rkey", is_outcome_server = TRUE,
      n = 10L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertSoftmaxDenominatorDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertSoftmaxDenominatorDS(
      exp_eta_keys = "k1", output_key = "out",
      is_party0 = TRUE, n = 10L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- NB family ---
test_that("dsvertNBEtaSealDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertNBEtaSealDS(
      data_name = "fake", x_vars = "age",
      beta_values = 0.0, target_pk = "pk",
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertNBFullScoreDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertNBFullScoreDS(
      data_name = "fake", y_var = "y",
      x_vars_label = "age", beta_values_label = 0.0,
      beta_intercept = 0.0,
      peer_eta_key = "ek", theta = 1.0,
      session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- Cox K=2 non-disclosive family ---
test_that("dsvertCoxDiscreteShareMaskDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertCoxDiscreteShareMaskDS(
      data_name = "fake", time_var = "time", status_var = "status",
      J = 5L, bin_breaks = c(0, 1, 2, 3, 4, 5),
      mask_output_key = "m", y_output_key = "y",
      target_pk = "pk", session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertCoxDiscreteReceiveSharesDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertCoxDiscreteReceiveSharesDS(
      mask_blob_key = "mb", y_blob_key = "yb",
      mask_output_key = "mo", y_output_key = "yo",
      n_pp = 50L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

test_that("dsvertCoxDiscreteExpandXDS rejects K=3 session", {
  s <- .mk_session(3L)
  expect_error(
    dsVert::dsvertCoxDiscreteExpandXDS(
      data_name = "fake", new_data_name = "fake2",
      x_vars = "age", J = 5L, session_id = s$sid),
    "K mismatch.*expected K=2.*got K=3")
})

# --- k2 input/gradient family + k2 wide-spline phases ---
#
# Tests for K=3-rejection on the eight shared-infra primitives
# (k2ShareInputDS, k2ComputeEtaShareDS, k2GradientR{1,2}DS,
# k2WideSplinePhase{1,2,3,4}DS) were INTENTIONALLY removed at
# commit b497cee ("fix(k3): lift K=2-only guards from shared-infra
# primitives"). These primitives are reused by the K=3 GLM path —
# ds.vertGLM.k3ring63 designates 2-of-3 servers as DCF parties and
# runs the K=2-style Beaver pipeline between them — so the previous
# `.k2_enforce_K(ss, 2L, ...)` guard, which counted the FULL 3-peer
# pool from `peer_transport_pks`, was rejecting legitimate K=3
# traffic and blocking glm K=3, multinom_warm K=3, ordinal_warm K=3,
# lasso K=3, cox K=3, and lmm K=3.
#
# Guards REMAIN on K=2-only-by-algorithm primitives where the algebra
# genuinely depends on a 2-party additive split (multinomJointDS,
# dsvertLMMGramDS / GLSTransformDS / ClusterBroadcastDS, nbFullRegShareDS,
# coxDiscreteShareDS, ordinalJointScoreDS); those tests above remain
# in place and exercise the guard correctly.

# =====================================================================
# 3. Negative control: K=2 session reaches downstream code
# =====================================================================
# When K=2 is matched, the guard should NOT block; the function then
# fails (or proceeds) on its own internal logic (e.g., missing fake
# data frame, missing session keys). The point is just that the
# K-guard itself does not fire.

test_that("k2GradientR1DS does NOT fire K-guard when K=2", {
  s <- .mk_session(2L)
  # k2GradientR1DS will fail later because no input shares are set up,
  # but the failure must NOT be the K-guard.
  err <- tryCatch(
    dsVert::k2GradientR1DS(peer_pk = "pk", session_id = s$sid),
    error = function(e) conditionMessage(e))
  expect_false(grepl("K mismatch", err))
})

test_that("dsvertOrdinalExtractXColumnDS does NOT fire K-guard when K=2", {
  s <- .mk_session(2L)
  err <- tryCatch(
    dsVert::dsvertOrdinalExtractXColumnDS(
      matrix_key = "m", n = 10L, p = 3L, col_idx = 1L,
      output_key = "out", session_id = s$sid),
    error = function(e) conditionMessage(e))
  expect_false(grepl("K mismatch", err))
})
