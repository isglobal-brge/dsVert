test_that("formal GLM Phase-1.5 DSI binding is pinned and purpose-bound", {
  hashes <- lapply(0:5, function(index)
    paste(rep(as.character(index), 64L), collapse = ""))
  peer_ids <- c(
    alpha = paste0("dsv1_", paste(rep("b", 64L), collapse = "")),
    beta = paste0("dsv1_", paste(rep("a", 64L), collapse = "")))
  make_binding <- function(ids = peer_ids, transcript = hashes[[3L]]) {
    .dsvert_formal_glm_phase15_dsi_binding(
      plan_sha256 = hashes[[1L]],
      final_receipt_pair_sha256 = hashes[[2L]],
      execution_transcript_sha256 = transcript,
      bridge_sha256 = hashes[[4L]], snapshot_sha256 = hashes[[5L]],
      pinset_sha256 = hashes[[6L]], peer_ids = ids)
  }
  binding <- make_binding()
  expect_invisible(
    .dsvert_formal_glm_phase15_dsi_binding_validate(binding))
  expect_identical(binding$garbler_peer_name, "beta")
  expect_identical(binding$evaluator_peer_name, "alpha")
  expect_identical(binding$analyst_selected_roles, FALSE)
  expect_identical(binding$opening,
                   "none_sealed_bridge_shares_only_v1")
  expect_identical(binding$registered_remote_method, FALSE)
  expect_identical(binding$production_ready, FALSE)

  # DSI result order cannot change roles or the operation identity.
  expect_identical(make_binding(rev(peer_ids)), binding)
  changed <- make_binding(transcript = paste(rep("f", 64L), collapse = ""))
  expect_false(identical(changed$binding_sha256, binding$binding_sha256))
  expect_false(identical(changed$purpose, binding$purpose))

  tampered <- binding
  tampered$execution_transcript_sha256 <- paste(rep("e", 64L), collapse = "")
  expect_error(
    .dsvert_formal_glm_phase15_dsi_binding_validate(tampered),
    "modified")
  self_consistent_tamper <- binding
  self_consistent_tamper$purpose <- paste0(
    "formal-glm/phase15-internal/", paste(rep("0", 64L), collapse = ""))
  self_consistent_tamper$binding_sha256 <-
    .dsvert_formal_glm_phase15_hash(
      self_consistent_tamper[setdiff(
        names(self_consistent_tamper), "binding_sha256")])
  expect_error(
    .dsvert_formal_glm_phase15_dsi_binding_validate(self_consistent_tamper),
    "not canonical")
  expect_error(make_binding(c(alpha = peer_ids[[1L]],
                              beta = peer_ids[[1L]])),
               "Invalid pinned")
})

test_that("formal GLM Phase-1.5 has no public material or premature opening", {
  public_formals <- names(formals(.dsvert_formal_glm_phase15_dsi_binding))
  expect_false(any(c(
    "source_share", "private_seed", "beta", "gradient", "patient_data") %in%
      public_formals))

  hashes <- vapply(letters[1:6], function(value)
    digest::digest(value, algo = "sha256", serialize = FALSE), character(1L))
  peer_ids <- c(
    left = paste0("dsv1_", paste(rep("1", 64L), collapse = "")),
    right = paste0("dsv1_", paste(rep("2", 64L), collapse = "")))
  binding <- .dsvert_formal_glm_phase15_dsi_binding(
    hashes[[1L]], hashes[[2L]], hashes[[3L]], hashes[[4L]], hashes[[5L]],
    hashes[[6L]], peer_ids)
  error <- tryCatch(
    .dsvert_formal_glm_phase15_dp_release_compile(binding),
    error = identity)
  expect_s3_class(error, "dsvert_formal_glm_dp_release_unavailable")
  expect_identical(error$code,
    "formal_glm_productive_joint_dp_release_lifecycle_unavailable")
  expect_length(error$missing, 2L)
  expect_true(any(grepl(
    "Phase-1.9 private-output handoff", error$missing, fixed = TRUE)))
  expect_false(any(grepl(
    "manifest/materializer admission", error$missing, fixed = TRUE)))
  expect_identical(error$openings_performed, 0L)
  expect_identical(error$production_ready, FALSE)
  expect_false(any(grepl("share|seed", names(binding))))

  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  aggregate <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  exports <- sub("^export\\((.*)\\)$", "\\1", grep(
    "^export\\(", readLines(.dsvert_test_package_file("NAMESPACE")),
    value = TRUE))
  expect_false(any(grepl("formalGLMPhase15", c(aggregate, exports),
                         fixed = TRUE)))
})
