.dp_transcript_condition <- function(class, message, code = NULL) {
  structure(
    list(message = message, call = NULL, code = code),
    class = c(class, "error", "condition"))
}

test_that("protected failures have one relay-visible representation", {
  failures <- list(
    simpleError("patient-derived admission detail"),
    .dp_transcript_condition(
      "dsvert_capsule_source_snapshot_changed",
      "private snapshot binding changed", "snapshot_changed"),
    .dp_transcript_condition(
      "dsvert_dp_capsule_coordinate_range_error",
      "coordinate 17 exceeded a patient-derived bound", "range"))

  visible <- lapply(failures, function(error) {
    tryCatch(.dsvert_dp_transcript_stop(error), error = identity)
  })
  expect_true(all(vapply(
    visible, inherits, logical(1L), "dsvert_dp_public_failure")))
  expect_length(unique(vapply(visible, conditionMessage, character(1L))), 1L)
  expect_identical(
    conditionMessage(visible[[1L]]),
    "[dsvert_dp_public_failure:v1] Protected capsule operation failed.")
  transcript <- paste(vapply(visible, conditionMessage, character(1L)),
                      collapse = "|")
  expect_false(grepl("patient|snapshot|coordinate|17", transcript,
                     ignore.case = TRUE))
})

test_that("phase misses are typed and canonicalized without details", {
  condition <- .dsvert_phase_not_ready_condition()
  expect_s3_class(condition, "dsvert_phase_not_ready")
  expect_identical(conditionMessage(condition),
                   "[dsvert_phase_not_ready:v1]")
  expect_identical(condition$code, "phase_not_ready")
  expect_identical(condition$retryable, FALSE)
  expect_setequal(names(condition),
                  c("message", "call", "code", "retryable"))

  hostile <- structure(
    list(
      message = paste(
        "[dsvert_phase_not_ready:v1] private phase and patient detail"),
      call = NULL, code = "secret_code", retryable = TRUE,
      phase = "private_result_phase", patient_coordinate = 17L),
    class = c("dsvert_phase_not_ready", "error", "condition"))
  observed <- tryCatch(
    .dsvert_dp_transcript_stop(hostile), error = identity)
  expect_s3_class(observed, "dsvert_phase_not_ready")
  expect_identical(conditionMessage(observed),
                   "[dsvert_phase_not_ready:v1]")
  expect_identical(observed$code, "phase_not_ready")
  expect_identical(observed$retryable, FALSE)
  expect_setequal(names(observed),
                  c("message", "call", "code", "retryable"))
  expect_false(grepl(
    "private|patient|coordinate|17|secret",
    paste(unlist(observed, use.names = FALSE), collapse = "|"),
    ignore.case = TRUE))
})

test_that("lifetime-budget exhaustion is typed and detail-free", {
  condition <- .dsvert_dp_lifetime_budget_exhausted_condition()
  expect_s3_class(condition, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(
    conditionMessage(condition),
    "[dsvert_dp_lifetime_budget_exhausted:v1]")
  expect_identical(condition$code, "dp_lifetime_budget_exhausted")
  expect_identical(condition$retryable, FALSE)
  expect_setequal(names(condition),
                  c("message", "call", "code", "retryable"))

  hostile <- structure(
    list(
      message = paste(
        "[dsvert_dp_lifetime_budget_exhausted:v1]",
        "capsule 17 exhausted patient cohort alpha"),
      call = NULL, code = "secret_code", retryable = TRUE,
      capsule_id = strrep("a", 64L), remaining = 0L),
    class = c(
      "dsvert_dp_lifetime_budget_exhausted", "error", "condition"))
  observed <- tryCatch(
    .dsvert_dp_transcript_stop(hostile), error = identity)
  expect_s3_class(observed, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(
    conditionMessage(observed),
    "[dsvert_dp_lifetime_budget_exhausted:v1]")
  expect_identical(observed$code, "dp_lifetime_budget_exhausted")
  expect_identical(observed$retryable, FALSE)
  expect_setequal(names(observed),
                  c("message", "call", "code", "retryable"))
  expect_false(grepl(
    "capsule|patient|cohort|alpha|remaining|secret|17",
    paste(unlist(observed, use.names = FALSE), collapse = "|"),
    ignore.case = TRUE))
})

test_that("source and vector public boundaries use the common failure token", {
  source <- tryCatch(
    .dsvert_dp_capsule_source_public(
      "protected source phase", stop("SOURCE_SECRET_42", call. = FALSE)),
    error = identity)
  vector <- tryCatch(
    .dsvert_joint_dp_vector_public(
      "protected vector phase", stop("VECTOR_SECRET_99", call. = FALSE)),
    error = identity)
  allocation <- tryCatch(
    .dsvert_joint_dp_vector_allocation_public(
      "protected allocation phase",
      stop("ALLOCATION_SECRET_77", call. = FALSE)),
    error = identity)
  categorical <- tryCatch(
    dsvertDPCategoricalCrossPrepareDS("analysis", "invalid-session"),
    error = identity)
  gaussian <- tryCatch(
    dsvertDPGaussianCrossPrepareDS(
      "analysis", "xtx", 1L, "invalid-session"),
    error = identity)
  alignment <- tryCatch(
    dsvertDPAlignmentMaskStoreDS(
      .dsvert_dsi_text_encode("{}"),
      "op_11111111111111111111111111111111",
      "op_22222222222222222222222222222222", 1L, 1L,
      "invalid-session"),
    error = identity)
  expect_s3_class(source, "dsvert_dp_public_failure")
  expect_s3_class(vector, "dsvert_dp_public_failure")
  expect_s3_class(allocation, "dsvert_dp_public_failure")
  expect_s3_class(categorical, "dsvert_dp_public_failure")
  expect_s3_class(gaussian, "dsvert_dp_public_failure")
  expect_s3_class(alignment, "dsvert_dp_public_failure")
  messages <- vapply(
    list(source, vector, allocation, categorical, gaussian, alignment),
    conditionMessage, character(1L))
  expect_length(unique(messages), 1L)
  expect_false(grepl(
    paste0(
      "SOURCE_SECRET|VECTOR_SECRET|ALLOCATION_SECRET|source phase|",
      "vector phase|allocation phase|invalid-session"),
    paste(messages, collapse = "|"),
    ignore.case = TRUE))
})

test_that("public recovery and resource conditions keep their typed contract", {
  preserved <- list(
    .dp_transcript_condition(
      "dsvert_resource_backpressure", "public resource backpressure",
      "resource_backpressure"),
    .dp_transcript_condition(
      "dsvert_resource_oversize", "public payload is oversized",
      "resource_oversize"),
    .dp_transcript_condition(
      "dsvert_peer_not_recognized", "public peer fingerprint changed",
      "peer_not_recognized"),
    .dp_transcript_condition(
      "dsvert_dp_release_retry_current_instance",
      "refresh public release roots", "retry_current_instance"),
    .dp_transcript_condition(
      "dsvert_noise_root_not_independent",
      "public noise-root identifiers collide", "noise_root_not_independent"))

  for (condition in preserved) {
    observed <- tryCatch(
      .dsvert_dp_transcript_stop(condition), error = identity)
    expect_identical(observed, condition)
  }
})

test_that("capsule transcript geometry is a function of public contract only", {
  expected <- list(
    `2` = c(source_ticket = 2, source_prepare = 2,
            source_fetch = 6, recipient_accept = 12,
            vector_prepare = 2, vector_result_lookup = 2,
            vector_start = 6, vector_result_commit = 2,
            vector_release_lookup = 2, final_share = 6,
            vector_release_commit = 2, replay = 6, finalize_ack = 2),
    `3` = c(source_ticket = 2, source_prepare = 3,
            source_fetch = 9, recipient_accept = 18,
            vector_prepare = 2, vector_result_lookup = 2,
            vector_start = 6, vector_result_commit = 2,
            vector_release_lookup = 2, final_share = 6,
            vector_release_commit = 2, replay = 6, finalize_ack = 3),
    `5` = c(source_ticket = 2, source_prepare = 5,
            source_fetch = 15, recipient_accept = 30,
            vector_prepare = 2, vector_result_lookup = 2,
            vector_start = 6, vector_result_commit = 2,
            vector_release_lookup = 2, final_share = 6,
            vector_release_commit = 2, replay = 6, finalize_ack = 5))
  expected_totals <- c(`2` = 52, `3` = 63, `5` = 85)
  expected_round_totals <- c(`2` = 29, `3` = 35, `5` = 47)
  expected_base_totals <- c(`2` = 70, `3` = 85, `5` = 115)
  expected_base_round_totals <- c(`2` = 39, `3` = 45, `5` = 57)

  for (peer_count in c(2L, 3L, 5L)) {
    shape <- .dsvert_dp_transcript_public_shape(
      custodian_peer_count = peer_count,
      source_peer_count = peer_count,
      coordinate_count = 16385L,
      chunk_coordinates = 8192L)
    expect_identical(shape$chunk_count, 3L)
    expect_identical(shape$chunk_geometry, list(
      full_chunk_count = 2,
      full_chunk_coordinates = 8192,
      final_chunk_coordinates = 1))
    expect_identical(unlist(shape$calls, use.names = TRUE),
                     expected[[as.character(peer_count)]])
    expect_identical(
      sum(unlist(shape$calls, use.names = FALSE)),
      unname(expected_totals[[as.character(peer_count)]]))
    expect_identical(
      sum(unlist(shape$dependency_rounds, use.names = FALSE)),
      unname(expected_round_totals[[as.character(peer_count)]]))
    expect_identical(
      shape$base_cold_calls_with_status,
      unname(expected_base_totals[[as.character(peer_count)]]))
    expect_identical(
      shape$base_cold_dependency_rounds_with_status,
      unname(expected_base_round_totals[[as.character(peer_count)]]))
    expect_identical(shape$private_inputs_in_geometry, FALSE)
    expect_identical(shape$request_limit, FALSE)
    expect_identical(shape$privacy_budget_gate, TRUE)
    expect_identical(shape$operation_limit, TRUE)
    expect_identical(shape$history_can_deny_new_release, TRUE)
  }
})

test_that("public shape uses compact geometry at the admitted integer limit", {
  shape <- .dsvert_dp_transcript_public_shape(
    custodian_peer_count = 2^20,
    source_peer_count = 2^20,
    coordinate_count = 2^31 - 1,
    chunk_coordinates = 1)
  expect_identical(shape$chunk_count, .Machine$integer.max)
  expect_identical(length(shape$chunk_geometry), 3L)
  expect_identical(
    shape$chunk_geometry$full_chunk_count,
    as.numeric(.Machine$integer.max) - 1)
  expect_true(all(is.finite(unlist(shape$calls, use.names = FALSE))))
  expect_lte(
    max(unlist(shape$calls, use.names = FALSE)),
    2^53 - 1)
})

test_that("successful-transcript claim excludes R timing and availability", {
  contract <- .dsvert_dp_transcript_claim()
  expect_identical(
    contract$policy_value,
    paste0(
      "successful_release_semantic_messages_public_shape_or_dp_",
      "postprocessing_v1_physical_timing_availability_excluded"))
  expect_identical(
    contract$semantic_message_count_from_public_contract, TRUE)
  expect_identical(
    contract$semantic_message_size_from_public_contract_or_dp_output, TRUE)
  expect_identical(
    contract$transport_poll_and_retransmission_count_in_scope, FALSE)
  expect_identical(contract$cache_replay_identity_public, TRUE)
  expect_identical(contract$pre_release_error_content_uniform, TRUE)
  expect_identical(contract$pre_release_error_occurrence_in_scope, FALSE)
  expect_identical(contract$r_host_constant_time_claim, FALSE)
  expect_identical(contract$traffic_flow_dp_claim, FALSE)
})
