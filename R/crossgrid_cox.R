# Additive observed-time Breslow contract. Registration describes the integration
# boundary; it does not authorize a producer or open a protected plaintext loss.
.DSVERT_DP_COX_GRID_CROSS_SPEC_VERSION <- "cox_grid_cross_v1"
.DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION <-
  "bounded-cox-breslow-observed-cross-grid-v1"
.DSVERT_DP_COX_GRID_CROSS_CONTRACT_VERSION <-
  "dsvert-cox-cross-owner-grid-signed-contract-v1"
.DSVERT_DP_COX_GRID_CROSS_SIGNING_DOMAIN <-
  "dsVert/cox-cross-owner-grid-contract/v1|"

.dsvert_dp_cox_grid_cross_fail <- function() {
  .dsvert_dp_transcript_stop(simpleError("Invalid Cox cross-grid contract."))
}

# All operations here are exact binary64 integer arithmetic. For y in [0,1/3],
# log((1+y)/(1-y)) = 2 sum(y^(2r+1)/(2r+1)); the r>=16 tail is < 2^-24.
# Upward rounding each retained term preserves the upper bound. Products are
# below 2^48, and denominators below 2^24, so no wide product enters R.
.dsvert_dp_cox_grid_cross_log_upper_q24 <- function(n) {
  n <- .dsvert_dp_glm_grid_cross_integer(n, 1, 10000)
  q <- 2^24
  series <- function(numerator, denominator) {
    y <- ceiling(q * numerator / denominator)
    yy <- ceiling(y * y / q)
    power <- y
    total <- 0
    for (r in 0:15) {
      total <- total + ceiling(power / (2 * r + 1))
      power <- ceiling(power * yy / q)
    }
    2 * total + 1
  }
  k <- 0
  while (2^(k + 1) <= n) k <- k + 1
  k * series(1, 3) + series(n - 2^k, n + 2^k)
}

.dsvert_dp_cox_grid_cross_beta <- function(beta, predictors = NULL) {
  if (is.list(beta) && is.null(names(beta)) && all(vapply(beta, function(x) {
      is.numeric(x) && length(x) == 1L
    }, logical(1L)))) beta <- unlist(beta, use.names = FALSE)
  if (!is.numeric(beta) || !is.null(names(beta)) || !length(beta) ||
      length(beta) > 16L || (!is.null(predictors) && length(beta) != predictors) ||
      anyNA(beta) || any(!is.finite(beta)) || any(abs(beta) > 4) ||
      !.dsvert_dp_glm_grid_cross_beta_l1_valid(c(beta, 8))) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  beta
}

# The range argument bounds replacement by U as well. Retain the existing
# conservative factor two convention for replace-one adjacency explicitly.
.dsvert_dp_cox_grid_cross_sensitivity <- function(
    beta_grid, grid_bits, capacity, adjacency) {
  grid_bits <- .dsvert_dp_glm_grid_cross_integer(grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(capacity, 2, 10000)
  if (!is.character(adjacency) || length(adjacency) != 1L || is.na(adjacency) ||
      !adjacency %in% c("add_remove_patient", "replace_one_fixed_cohort") ||
      !is.list(beta_grid) || !is.null(names(beta_grid)) ||
      !length(beta_grid) || length(beta_grid) > 128L) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  log_upper <- .dsvert_dp_cox_grid_cross_log_upper_q24(capacity)
  bounds <- lapply(beta_grid, function(beta) {
    beta <- .dsvert_dp_cox_grid_cross_beta(beta)
    radius <- sum(ceiling(abs(beta) * 2^24))
    error <- 2^18 # certified per-event 1/64, represented at q24
    numerator <- capacity * (log_upper + 2 * radius + error)
    cap <- ceiling(numerator / 2^(24 - grid_bits))
    list(eta_lower = sum(pmin(beta, 0)), eta_upper = sum(pmax(beta, 0)),
         absolute_eta_bound_upper_q24 = radius,
         log_capacity_upper_q24 = log_upper,
         per_event_error_upper_q24 = error,
         whole_cohort_cap = cap)
  })
  caps <- vapply(bounds, `[[`, numeric(1L), "whole_cohort_cap")
  multiplier <- if (identical(adjacency, "add_remove_patient")) 1 else 2
  l1 <- multiplier * sum(caps)
  # 128 positive products/addends plus one sqrt: 512 binary64 eps dominates
  # the standard forward-error bound. R's long-double sum can only improve it.
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 512 * .Machine$double.eps)
  if (any(!is.finite(c(caps, l1, l2))) || any(c(caps, l1, l2) > 2^53 - 1)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  list(candidate_bounds = bounds, maximum_coordinates = as.list(caps),
       rounding_unit = "whole_cohort_once_v1",
       adjacency_multiplier = multiplier, raw_l1_sensitivity = l1,
       raw_l2_sensitivity = l2, natural_l1_sensitivity = l1 / 2^grid_bits,
       natural_l2_sensitivity = l2 / 2^grid_bits)
}

.dsvert_dp_cox_grid_cross_numeric <- function() {
  profile_hash <- "3ec6e885ddcf37c0471299b7b1745c80b18f8aa18dbec6ce56f865b1fda1c483"
  certificate_hash <- "27c6aa5a74f03c4ee2516e026fdaeaf3ce248d40451e8bbdb5c1ed421a542fe9"
  path <- system.file("cross-cox-v1", "numeric_cox_profile_v1.json", package = "dsVert")
  if (!nzchar(path)) .dsvert_dp_cox_grid_cross_fail()
  profile <- jsonlite::fromJSON(path, simplifyVector = FALSE)
  if (!identical(profile$profile_sha256, profile_hash) ||
      !identical(.dsvert_joint_dp_hash(profile$profile), profile_hash) ||
      !identical(profile$certificate_sha256, certificate_hash) ||
      !identical(.dsvert_joint_dp_hash(profile$certificate), certificate_hash)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  list(version = "cox-piecewise-linear-exp-log-v1",
       profile_sha256 = profile_hash, certificate_sha256 = certificate_hash,
       input_fraction_bits = 50, partial_predictor_fraction_bits = 100,
       eta_fraction_bits = 16, nonlinear_fraction_bits = 20,
       scalar_word_bits = 32, scalar_pieces = 64,
       compiler_profile = "mpcl-c911bbd029d1-prune-array128-v1",
       eta_rounding = "one_rne_after_owner_sum_v1",
       interpolation_rounding = "floor_v1",
       log_normalization_rounding = "floor_v1",
       quantization = "whole_cohort_rne_then_integer_clamp_v1",
       certified_per_event_error = "1/64",
       error_budget_q24 = 2^18,
       loss_orientation = "negative_partial_log_likelihood",
       transcendental_route = "certified_piecewise_linear_only_v1")
}

.dsvert_dp_cox_grid_cross_spec <- function(raw, policy, schema) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(raw, c(
      "version", "analysis_id", "dataset", "time", "event",
      "predictor_order", "beta_grid", "alignment"))
    if (!identical(raw$version, .DSVERT_DP_COX_GRID_CROSS_SPEC_VERSION)) {
      .dsvert_dp_cox_grid_cross_fail()
    }
    for (field in c("analysis_id", "dataset")) {
      if (!is.character(raw[[field]]) || length(raw[[field]]) != 1L ||
          length(.dsvert_dp_glm_grid_cross_strings(raw[[field]])) != 1L) {
        .dsvert_dp_cox_grid_cross_fail()
      }
    }
    for (field in c("time", "event")) {
      if (!is.character(raw[[field]]) || length(raw[[field]]) != 1L ||
          length(.dsvert_dp_glm_grid_cross_references(raw[[field]])) != 1L) {
        .dsvert_dp_cox_grid_cross_fail()
      }
    }
    predictors <- .dsvert_dp_glm_grid_cross_references(raw$predictor_order)
    variables <- c(predictors, raw$time, raw$event)
    if (length(predictors) > 16L || anyDuplicated(variables) ||
        !identical(predictors, sort(predictors, method = "radix"))) {
      .dsvert_dp_cox_grid_cross_fail()
    }
    dataset <- schema$unsigned$datasets[[raw$dataset]]
    if (is.null(dataset)) .dsvert_dp_cox_grid_cross_fail()
    descriptors <- lapply(variables, function(variable) {
      owner <- sub("\\$.*$", "", variable)
      physical <- sub("^[^$]+\\$", "", variable)
      matches <- vapply(names(dataset$columns), function(name) {
        identical(sub("^[^$]+\\$", "", name), physical) &&
          identical(dataset$columns[[name]]$owner_peer, owner)
      }, logical(1L))
      if (sum(matches) != 1L) .dsvert_dp_cox_grid_cross_fail()
      column <- .dsvert_dp_capsule_column(
        dataset$columns[[which(matches)]], names(policy$peer_pinset))
      if (!identical(column$kind, "numeric")) .dsvert_dp_cox_grid_cross_fail()
      list(reference = variable, dataset = raw$dataset, owner_peer = owner,
           column = physical, lower = column$lower, upper = column$upper)
    })
    names(descriptors) <- variables
    participants <- sort(unique(vapply(
      descriptors, `[[`, character(1L), "owner_peer")), method = "radix")
    compute <- sort(unname(policy$designated_noise_peers), method = "radix")
    if (length(participants) != 2L || length(compute) != 2L ||
        anyDuplicated(compute) || !identical(compute, participants) ||
        !setequal(names(policy$peer_pinset), participants) ||
        !identical(descriptors[[raw$time]]$owner_peer,
                   descriptors[[raw$event]]$owner_peer) ||
        descriptors[[raw$event]]$lower != 0 ||
        descriptors[[raw$event]]$upper != 1) .dsvert_dp_cox_grid_cross_fail()
    .dsvert_dp_glm_grid_cross_fields(raw$alignment, c(
      "version", "method", "alignment_group", "public_alignment_contract_sha256",
      "public_patient_dependent_hash"))
    alignment <- list(
      version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1",
      alignment_group = dataset$alignment_group,
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = schema$unsigned$logical_snapshot,
        alignment_group = dataset$alignment_group,
        method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE)
    .dsvert_dp_glm_grid_cross_equal(raw$alignment, alignment)
    if (!is.list(raw$beta_grid) || !is.null(names(raw$beta_grid)) ||
        !length(raw$beta_grid) || length(raw$beta_grid) > 128L) {
      .dsvert_dp_cox_grid_cross_fail()
    }
    beta <- lapply(raw$beta_grid, function(row) {
      as.list(.dsvert_dp_cox_grid_cross_beta(row, length(predictors)))
    })
    keys <- vapply(beta, .dsvert_dp_canonical_json, character(1L))
    encoded <- lapply(beta, function(row) as.list(vapply(row, function(value) {
      integer <- round(value * 2^50)
      if (integer == 0) integer <- 0
      sprintf("%.0f", integer)
    }, character(1L))))
    if (anyDuplicated(keys) || !identical(keys, sort(keys, method = "radix")) ||
        anyDuplicated(vapply(encoded, .dsvert_dp_canonical_json, character(1L)))) {
      .dsvert_dp_cox_grid_cross_fail()
    }
    bits <- .dsvert_dp_glm_grid_cross_integer(policy$numeric_grid_bits, 8, 18)
    capacity <- .dsvert_dp_glm_grid_cross_integer(policy$unit_capacity, 2, 10000)
    list(version = raw$version, family = "cox", analysis_id = raw$analysis_id,
      dataset = raw$dataset, schema_sha256 = schema$sha256,
      logical_snapshot = schema$unsigned$logical_snapshot,
      peer_pinset_sha256 = schema$unsigned$peer_pinset_sha256,
      time = descriptors[[raw$time]], event = descriptors[[raw$event]],
      predictors = descriptors[predictors],
      owner_peer = descriptors[[raw$time]]$owner_peer,
      participating_peers = as.list(participants), computation_peers = as.list(compute),
      predictor_order = as.list(predictors), input_variable_order = as.list(variables),
      design_terms = as.list(predictors), intercept = FALSE,
      beta_grid = beta, beta_encoded = encoded,
      candidate_order = as.list(vapply(beta, .dsvert_joint_dp_hash, character(1L))),
      resource_admission = .dsvert_dp_cox_grid_cross_admission(capacity, length(beta)),
      observation_capacity = capacity, padded_capacity = 2^ceiling(log2(capacity)),
      numeric_grid_bits = bits, adjacency = policy$adjacency, alignment = alignment,
      ties = "breslow", time_semantics = "bounded_observed_binary64_v1",
      repeated_records = "reject_snapshot_v1",
      preprocessing = "clip_finite_record_reject_repeated_patient_v1",
      predictor_normalization = "exact_binary64_rational_to_f50_rne_v1",
      complete_case = "all_owned_input_validity_bits_and_private_alignment_v1",
      numeric_contract = .dsvert_dp_cox_grid_cross_numeric(),
      sensitivity = .dsvert_dp_cox_grid_cross_sensitivity(
        beta, bits, capacity, policy$adjacency))
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_cox_grid_cross_spec_validate <- function(value, policy, schema) {
  tryCatch({
    raw <- value[c("version", "analysis_id", "dataset", "predictor_order",
                   "beta_grid", "alignment")]
    raw$time <- value$time$reference
    raw$event <- value$event$reference
    expected <- .dsvert_dp_cox_grid_cross_spec(raw, policy, schema)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_cox_grid_cross_layout <- function(spec) {
  m <- spec$padded_capacity
  log_m <- as.integer(log2(m))
  list(version = "dsvert-cox-cross-private-source-layout-v1",
    ring_bits = 128, release_coordinate_count = length(spec$beta_grid),
    padded_units = m, partial_predictor_fraction_bits = 100,
    release_prefix_source_rule = "all_zero_until_authenticated_result_injection_v1",
    partial_predictors = "two_owners_exact_f100_additive_ring128_v1",
    validity = "private_alignment_and_all_input_validity_v1",
    event = "private_outcome_owner_bit_v1",
    permutation = "private_descending_time_benes_controls_v1",
    permutation_switch_count = (m / 2) * (2 * log_m - 1),
    tie_end = "private_outcome_owner_sorted_tie_end_bits_v1",
    invalid_time_order = "terminal_sentinel_then_aligned_slot_index_v1",
    signed_zero = "canonical_positive_zero_v1",
    padding = "always_invalid_zero_eta_zero_event_v1",
    intermediate_output = "private_share_state_with_authenticated_chunk_receipts_v2")
}

.dsvert_dp_cox_grid_cross_artifact <- function(spec) {
  list(version = .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION,
    spec_version = spec$version, spec_sha256 = .dsvert_joint_dp_hash(spec),
    analysis_id = spec$analysis_id, owner_peer = spec$owner_peer,
    participating_peers = spec$participating_peers, computation_peers = spec$computation_peers,
    candidate_order = spec$candidate_order, coordinate_count = length(spec$beta_grid),
    numeric_grid_bits = spec$numeric_grid_bits,
    source_coordinate_scaling = "all_coordinates_already_on_common_numeric_lattice_v1",
    sensitivity = spec$sensitivity,
    numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    private_layout_sha256 = .dsvert_joint_dp_hash(.dsvert_dp_cox_grid_cross_layout(spec)),
    transcript = list(version = "dsvert-cox-cross-fixed-transcript-v2",
      operation = "dp.cox-grid-cross.v1", padded_units = spec$padded_capacity,
      candidate_count = length(spec$beta_grid), row_batch_size = 32,
      permutation_count = 1, packed_columns = length(spec$beta_grid) + 2,
      ot_word_batch_size = 4096,
      candidate_batch_size = 1,
      traversal = "packed_permute_then_candidate_exp_share_prefix_ot_ties_log_share_sum_finalize_v2",
      schedule_version = "cox-packed-ot-prefix-shares-v2",
      boundary_state = "ring64_prefix_tie_loss_shares_with_keyed_receipts_v2",
      framing = "fixed-topology-framing-v1",
      ot_mode = "two_checked_streaming_extensions_per_connection_v1",
      receipt_mode = "private_keyed_state_commitments_v1",
      event_count_oblivious = TRUE,
      log_rows = "all_public_padded_slots_private_event_mask_v2",
      output = "two_authority_additive_candidate_sum_shares_only_v1"),
    result_evidence_required = TRUE,
    implementation_state = "cross_owner_exact_gc_contract_only",
    cross_owner_state = "exact_gc_to_joint_dp_vector_pending_v1",
    required_result_states = list(implementation_state = "cross_owner_exact_gc_materialized",
      cross_owner_state = "exact_gc_to_joint_dp_vector_v1"),
    runtime_enabled = FALSE)
}

.dsvert_dp_cox_grid_cross_artifact_validate <- function(value, spec) {
  tryCatch({
    expected <- .dsvert_dp_cox_grid_cross_artifact(spec)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_cox_grid_cross_source_contract <- function(spec, artifact) {
  list(version = "dsvert-cox-cross-owner-source-contract-v1",
    purpose = "cox_breslow_observed_inputs_and_release_shares_only_v1",
    spec_sha256 = .dsvert_joint_dp_hash(spec), artifact_sha256 = .dsvert_joint_dp_hash(artifact),
    schema_sha256 = spec$schema_sha256, logical_snapshot = spec$logical_snapshot,
    peer_pinset_sha256 = spec$peer_pinset_sha256,
    source_peers = spec$participating_peers, recipients = spec$computation_peers,
    alignment = spec$alignment, alignment_sharing = "recipient_specific_xor_share_exact_gc_gate_v1",
    numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    private_layout = .dsvert_dp_cox_grid_cross_layout(spec))
}

.dsvert_dp_cox_grid_cross_message <- function(unsigned) {
  charToRaw(paste0(.DSVERT_DP_COX_GRID_CROSS_SIGNING_DOMAIN,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_cox_grid_cross_contract_validate <- function(
    value, policy, schema_manifest, .verifier = .dsvert_relay_verify_message) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(value, c(
      "version", "spec", "artifact", "source_contract", "signatures"))
    if (!identical(value$version, .DSVERT_DP_COX_GRID_CROSS_CONTRACT_VERSION) ||
        length(policy$peer_pinset) != 2L) .dsvert_dp_cox_grid_cross_fail()
    schema <- .dsvert_dp_capsule_schema(
      policy, schema_manifest$logical_snapshot, schema_manifest, .verifier)
    spec <- .dsvert_dp_cox_grid_cross_spec_validate(value$spec, policy, schema)
    artifact <- .dsvert_dp_cox_grid_cross_artifact_validate(value$artifact, spec)
    .dsvert_dp_glm_grid_cross_equal(value$source_contract,
      .dsvert_dp_cox_grid_cross_source_contract(spec, artifact))
    pins <- policy$peer_pinset
    .dsvert_dp_glm_grid_cross_fields(value$signatures, names(pins))
    message <- .dsvert_dp_cox_grid_cross_message(value[setdiff(names(value), "signatures")])
    verified <- vapply(names(pins), function(peer) {
      signature <- value$signatures[[peer]]
      is.character(signature) && length(signature) == 1L && !is.na(signature) &&
        grepl("^[A-Za-z0-9_-]{86}$", signature) &&
        isTRUE(.verifier(message, unname(pins[[peer]]), signature))
    }, logical(1L))
    if (!all(verified)) .dsvert_dp_cox_grid_cross_fail()
    .dsvert_dp_canonical_query_value(value)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_cox_grid_cross_register <- function() {
  list(family = "cox", version = .DSVERT_DP_COX_GRID_CROSS_SPEC_VERSION,
    artifact_version = .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION,
    spec = .dsvert_dp_cox_grid_cross_spec,
    validate = .dsvert_dp_cox_grid_cross_contract_validate,
    artifact = .dsvert_dp_cox_grid_cross_artifact,
    source_contract = .dsvert_dp_cox_grid_cross_source_contract,
    sensitivity = .dsvert_dp_cox_grid_cross_sensitivity,
    implementation_state = "cross_owner_exact_gc_contract_only",
    cross_owner_state = "exact_gc_to_joint_dp_vector_pending_v1",
    required_result_states = list(implementation_state = "cross_owner_exact_gc_materialized",
      cross_owner_state = "exact_gc_to_joint_dp_vector_v1"),
    runtime_enabled = FALSE,
    produce = function(...) .dsvert_dp_cox_grid_cross_fail())
}
