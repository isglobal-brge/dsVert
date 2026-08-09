# Relay-visible transcript boundary for the one biomedical DP capsule flow.
#
# This file does not add a DataSHIELD method.  It centralises two deliberately
# small contracts: protected pre-release failures have one public encoding,
# and the successful cold-path message geometry is derived only from the
# signed public capsule dimensions.  It does not claim constant-time R, DSI
# traffic-flow privacy, or data-independent availability.

.DSVERT_DP_TRANSCRIPT_POLICY_VALUE <- paste0(
  "successful_release_semantic_messages_public_shape_or_dp_",
  "postprocessing_v1_physical_timing_availability_excluded")
.DSVERT_DP_PUBLIC_FAILURE_MESSAGE <-
  "[dsvert_dp_public_failure:v1] Protected capsule operation failed."
.DSVERT_PHASE_NOT_READY_MESSAGE <- "[dsvert_phase_not_ready:v1]"
# Legacy wire name for one opaque terminal lifetime-policy denial. It covers
# either global capsule exhaustion or a capsule that cannot safely advance the
# requested release instance because its irrevocable instance claim/publication
# binding already exists; it does not attest that the public
# remaining-distinct-capsules value is zero or disclose which cause occurred.
.DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE <-
  "[dsvert_dp_lifetime_budget_exhausted:v1]"

.dsvert_phase_not_ready_condition <- function() {
  structure(
    list(
      message = .DSVERT_PHASE_NOT_READY_MESSAGE,
      call = NULL,
      code = "phase_not_ready",
      retryable = FALSE),
    class = c("dsvert_phase_not_ready", "error", "condition"))
}

.dsvert_dp_lifetime_budget_exhausted_condition <- function() {
  structure(
    list(
      message = .DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE,
      call = NULL,
      code = "dp_lifetime_budget_exhausted",
      retryable = FALSE),
    class = c(
      "dsvert_dp_lifetime_budget_exhausted", "error", "condition"))
}

.dsvert_dp_transcript_claim <- function() {
  list(
    version = "dsvert-dp-transcript-boundary-v1",
    policy_value = .DSVERT_DP_TRANSCRIPT_POLICY_VALUE,
    successful_release_only = TRUE,
    semantic_message_count_from_public_contract = TRUE,
    semantic_message_size_from_public_contract_or_dp_output = TRUE,
    transport_poll_and_retransmission_count_in_scope = FALSE,
    cache_replay_identity_public = TRUE,
    pre_release_error_content_uniform = TRUE,
    pre_release_error_occurrence_in_scope = FALSE,
    r_host_constant_time_claim = FALSE,
    traffic_flow_dp_claim = FALSE)
}

.dsvert_dp_transcript_stop <- function(error) {
  if (!inherits(error, "condition")) {
    error <- simpleError("invalid protected capsule failure")
  }
  if (inherits(error, "dsvert_phase_not_ready")) {
    # Never forward a caller-supplied message or fields from a condition that
    # merely claims this class.  The relay sees one detail-free miss token.
    stop(.dsvert_phase_not_ready_condition())
  }
  if (inherits(error, "dsvert_dp_lifetime_budget_exhausted")) {
    # Budget exhaustion is public policy state, but caller-supplied details
    # must never cross the transcript boundary.
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  public_classes <- c(
    "dsvert_resource_backpressure",
    "dsvert_resource_oversize",
    "dsvert_peer_not_recognized",
    "dsvert_dp_release_retry_current_instance",
    "dsvert_release_instance_retry",
    "dsvert_noise_root_not_independent")
  if (any(vapply(
        public_classes, function(class) inherits(error, class),
        logical(1L)))) {
    stop(error)
  }
  stop(structure(
    list(
      message = .DSVERT_DP_PUBLIC_FAILURE_MESSAGE,
      call = NULL,
      code = "dp_protected_operation_failed"),
    class = c("dsvert_dp_public_failure", "error", "condition")))
}

.dsvert_dp_transcript_public_integer <- function(
    value, what, minimum, maximum) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < minimum ||
      value > maximum) {
    stop("Invalid public capsule transcript ", what, ".", call. = FALSE)
  }
  as.integer(value)
}

.dsvert_dp_transcript_public_shape <- function(
    custodian_peer_count, source_peer_count, coordinate_count,
    chunk_coordinates) {
  custodians <- .dsvert_dp_transcript_public_integer(
    custodian_peer_count, "custodian-peer count", 2, 2^20)
  sources <- .dsvert_dp_transcript_public_integer(
    source_peer_count, "source-peer count", 1, custodians)
  coordinates <- .dsvert_dp_transcript_public_integer(
    coordinate_count, "coordinate count", 1, 2^31 - 1)
  chunk_capacity <- .dsvert_dp_transcript_public_integer(
    chunk_coordinates, "chunk capacity", 1, 2^31 - 1)
  chunks <- as.integer(ceiling(coordinates / chunk_capacity))
  final_chunk_coordinates <- as.integer(
    coordinates - as.double(chunks - 1L) * chunk_capacity)

  # Exactly two designated noise/compute peers are selected from the complete
  # K-peer public pinset. Source peers and every dimension below are committed
  # by the signed server manifest before protected source access.
  calls <- list(
    source_ticket = 2,
    source_prepare = as.numeric(sources),
    source_fetch = as.numeric(sources) * chunks,
    recipient_accept = 2 * as.numeric(sources) * chunks,
    vector_prepare = 2,
    vector_result_lookup = 2,
    vector_start = 2 * as.numeric(chunks),
    vector_result_commit = 2,
    vector_release_lookup = 2,
    final_share = 2 * as.numeric(chunks),
    vector_release_commit = 2,
    replay = 2 * as.numeric(chunks),
    finalize_ack = as.numeric(custodians))
  dependency_rounds <- list(
    source_ticket = 1,
    source_prepare = 1,
    source_fetch_and_recipient_accept = 2 * as.numeric(sources) * chunks,
    vector_prepare = 1,
    vector_result_lookup = 1,
    vector_start = as.numeric(chunks),
    vector_result_commit = 1,
    vector_release_lookup = 1,
    final_share = as.numeric(chunks),
    vector_release_commit = 1,
    replay = as.numeric(chunks),
    finalize_ack = 1)
  preceding_calls <- list(
    status_handshake = as.numeric(custodians),
    manifest_draft_sign_build = 3 * as.numeric(custodians),
    allocation_cold = 10)
  preceding_rounds <- list(
    status_handshake = 1,
    manifest_draft_sign_build = 3,
    allocation_cold = 6)
  list(
    version = "dsvert-biomedical-capsule-public-transcript-shape-v2",
    scope = paste0(
      "post_manifest_post_allocation_source_and_vector_control_plane_",
      "excluding_cross_exact_gc_typed_blob_and_physical_transport"),
    call_unit = "remote_site_invocation",
    round_unit = "sequential_semantic_dependency_round",
    custodian_peer_count = custodians,
    designated_noise_peer_count = 2L,
    source_peer_count = sources,
    coordinate_count = coordinates,
    chunk_coordinates = chunk_capacity,
    chunk_count = chunks,
    chunk_geometry = list(
      full_chunk_count = as.numeric(chunks - 1L),
      full_chunk_coordinates = as.numeric(chunk_capacity),
      final_chunk_coordinates = as.numeric(final_chunk_coordinates)),
    calls = calls,
    dependency_rounds = dependency_rounds,
    preceding_public_calls = preceding_calls,
    preceding_public_dependency_rounds = preceding_rounds,
    base_cold_calls_with_status =
      sum(unlist(c(preceding_calls, calls), use.names = FALSE)),
    base_cold_dependency_rounds_with_status =
      sum(unlist(c(preceding_rounds, dependency_rounds), use.names = FALSE)),
    excluded_from_core_geometry = c(
      "status_handshake", "manifest_construction", "allocation",
      "cross_artifact_protocol", "exact_gc_inner_protocol",
      "typed_blob_frame_pumps", "dsi_polling_and_retransmission"),
    private_inputs_in_geometry = FALSE,
    request_limit = FALSE,
    privacy_budget_gate = TRUE,
    operation_limit = TRUE,
    history_can_deny_new_release = TRUE,
    replay_may_skip_cold_path = TRUE,
    replay_skip_key = "public_release_instance_id_and_capsule_id")
}
