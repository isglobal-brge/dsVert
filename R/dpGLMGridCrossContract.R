# Frozen public contract only. No producer, remote method or release route is
# enabled by these helpers. Existing same-owner specifications are untouched.
.DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS <- c(
  binomial = "binomial_grid_cross_v1", poisson = "poisson_grid_cross_v1")
.DSVERT_DP_GLM_GRID_CROSS_ARTIFACT_VERSIONS <- c(
  binomial = "bounded-binomial-cross-likelihood-grid-v1",
  poisson = "bounded-poisson-cross-likelihood-grid-v1")
.DSVERT_DP_GLM_GRID_CROSS_CONTRACT_VERSION <-
  "dsvert-cross-owner-grid-signed-contract-v1"
.DSVERT_DP_GLM_GRID_CROSS_SIGNING_DOMAIN <-
  "dsVert/cross-owner-grid-contract/v1|"
.DSVERT_DP_GLM_GRID_CROSS_SOURCE_VERSION <-
  "dsvert-biomedical-capsule-source-contract-v6-cross-grid-xor-alignment"
.DSVERT_DP_GLM_GRID_CROSS_SOURCE_PURPOSE <-
  "biomedical_capsule_ring128_cross_grid_inputs_and_release_shares_only"
.DSVERT_DP_GLM_GRID_CROSS_LAYOUT_VERSION <-
  "dsvert-cross-grid-private-source-layout-v1"
.DSVERT_DP_GLM_GRID_CROSS_IMPLEMENTATION_STATE <-
  "cross_owner_exact_gc_materialized"
.DSVERT_DP_GLM_GRID_CROSS_STATE <- "exact_gc_to_joint_dp_vector_v1"
.DSVERT_DP_GLM_GRID_CROSS_PROFILE_SHA256 <-
  "748900bb7f0d4d1026ba5e9b162bfb16e45e306033851dfc203c2461a6a78e4f"
.DSVERT_DP_GLM_GRID_CROSS_CERTIFICATE_SHA256 <-
  "887fdf3eb38528bde7497580ba90b13d187bee94da54d67fd2c55e813565e1d8"
.DSVERT_DP_GLM_GRID_CROSS_NUMERIC_SHA256 <- c(
  binomial = "80f2fdbb6892dd0aaabb0eab2aea6f4d13341a502d8336050ea6d7ee8006cd1c",
  poisson = "25ef48b66f919e2b8c5d9474829e1496d36a5eb4c45c1c778731648d7f3df797")

.dsvert_dp_glm_grid_cross_fail <- function() {
  .dsvert_dp_transcript_stop(simpleError("Invalid cross-grid contract."))
}

.dsvert_dp_glm_grid_cross_fields <- function(value, fields) {
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  invisible(TRUE)
}

.dsvert_dp_glm_grid_cross_equal <- function(value, expected) {
  if (!identical(.dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)),
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(expected)))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  invisible(TRUE)
}

.dsvert_dp_glm_grid_cross_integer <- function(value, lower, upper) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < lower ||
      value > upper) .dsvert_dp_glm_grid_cross_fail()
  as.numeric(value)
}

.dsvert_dp_glm_grid_cross_strings <- function(value, minimum = 1L) {
  if (is.list(value) && is.null(names(value)) && all(vapply(
      value, function(item) is.character(item) && length(item) == 1L,
      logical(1L)))) value <- unlist(value, use.names = FALSE)
  if (!is.character(value) || !is.null(names(value)) || anyNA(value) ||
      length(value) < minimum || anyDuplicated(value) ||
      any(!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  value
}

.dsvert_dp_glm_grid_cross_numeric <- function(family) {
  if (!family %in% names(.DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS) ||
      length(family) != 1L) .dsvert_dp_glm_grid_cross_fail()
  path <- system.file("cross-grid-v1", "numeric_profile_v1.json",
                      package = "dsVert")
  if (!nzchar(path)) .dsvert_dp_glm_grid_cross_fail()
  value <- jsonlite::fromJSON(path, simplifyVector = FALSE)
  if (!identical(value$profile_sha256,
                 .DSVERT_DP_GLM_GRID_CROSS_PROFILE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$profile),
                 .DSVERT_DP_GLM_GRID_CROSS_PROFILE_SHA256) ||
      !identical(value$numeric_contract[[family]]$profile_sha256,
                 .DSVERT_DP_GLM_GRID_CROSS_PROFILE_SHA256) ||
      !identical(value$certificate_sha256,
                 .DSVERT_DP_GLM_GRID_CROSS_CERTIFICATE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$certificate),
                 .DSVERT_DP_GLM_GRID_CROSS_CERTIFICATE_SHA256) ||
      !identical(value$numeric_contract[[family]]$certificate_sha256,
                 .DSVERT_DP_GLM_GRID_CROSS_CERTIFICATE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$numeric_contract[[family]]),
                 unname(.DSVERT_DP_GLM_GRID_CROSS_NUMERIC_SHA256[[family]]))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  value$numeric_contract[[family]]
}

.dsvert_dp_glm_grid_cross_references <- function(value) {
  if (is.list(value) && is.null(names(value)) && all(vapply(
      value, function(item) is.character(item) && length(item) == 1L,
      logical(1L)))) value <- unlist(value, use.names = FALSE)
  if (!is.character(value) || !is.null(names(value)) || !length(value) ||
      anyNA(value) || anyDuplicated(value) || any(!grepl(
        "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\\$[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        value))) .dsvert_dp_glm_grid_cross_fail()
  value
}

.dsvert_dp_glm_grid_cross_numeric_validate <- function(value, family) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_equal(
      value, .dsvert_dp_glm_grid_cross_numeric(family))
    value
  }, error = .dsvert_dp_transcript_stop)
}

# Public bounds agree with the existing grid builders. All transported and
# released integer coordinates remain exactly representable in R.
.dsvert_dp_glm_grid_cross_sensitivity <- function(
    beta_grid, family, max_outcome, grid_bits, capacity, adjacency) {
  grid_bits <- .dsvert_dp_glm_grid_cross_integer(grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(capacity, 1, 2^31 - 1)
  if (!family %in% c("binomial", "poisson") ||
      !adjacency %in% c("add_remove_patient", "replace_one_fixed_cohort")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  maximum <- .dsvert_dp_glm_grid_cross_integer(max_outcome, 1, 1024)
  if (identical(family, "binomial") && maximum != 1) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  bounds <- lapply(beta_grid, function(beta) {
    beta <- unlist(beta, use.names = FALSE)
    radius <- sum(abs(beta))
    loss <- if (identical(family, "binomial")) {
      radius + log1p(exp(-radius))
    } else {
      max(outer(0:maximum, c(-radius, radius), function(y, eta) {
        exp(eta) - y * eta + lgamma(y + 1)
      }))
    }
    list(eta_lower = beta[[1L]] + sum(pmin(beta[-1L], 0)),
         eta_upper = beta[[1L]] + sum(pmax(beta[-1L], 0)),
         absolute_eta_bound = radius, loss_bound = max(0, loss),
         per_patient_cap = ceiling(2^grid_bits * max(0, loss)))
  })
  caps <- vapply(bounds, `[[`, numeric(1L), "per_patient_cap")
  multiplier <- if (identical(adjacency, "add_remove_patient")) 1 else 2
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * (sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps))
  maxima <- capacity * caps
  if (!length(caps) || any(!is.finite(c(caps, maxima, l1, l2))) ||
      any(c(caps, maxima, l1, l2) > 2^53 - 1)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  list(candidate_bounds = bounds, maximum_coordinates = as.list(maxima),
       adjacency_multiplier = multiplier, raw_l1_sensitivity = l1,
       raw_l2_sensitivity = l2, natural_l1_sensitivity = l1 / 2^grid_bits,
       natural_l2_sensitivity = l2 / 2^grid_bits)
}

# raw retains explicit coefficient-column association. Neither columns nor
# candidate rows are silently permuted after signatures have been formed.
.dsvert_dp_glm_grid_cross_spec <- function(raw, policy, schema) {
  .dsvert_dp_glm_grid_cross_fields(raw, c(
    "version", "analysis_id", "dataset", "outcome", "predictor_order",
    "beta_grid", "max_outcome", "alignment"))
  family <- names(.DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS)[
    .DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS == raw$version]
  if (length(family) != 1L) .dsvert_dp_glm_grid_cross_fail()
  for (field in c("analysis_id", "dataset")) {
    if (length(.dsvert_dp_glm_grid_cross_strings(raw[[field]])) != 1L) {
      .dsvert_dp_glm_grid_cross_fail()
    }
  }
  if (length(.dsvert_dp_glm_grid_cross_references(raw$outcome)) != 1L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  predictors <- .dsvert_dp_glm_grid_cross_references(raw$predictor_order)
  if (length(predictors) > 16L || raw$outcome %in% predictors ||
      !identical(predictors, sort(predictors, method = "radix"))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  dataset <- schema$unsigned$datasets[[raw$dataset]]
  if (is.null(dataset)) .dsvert_dp_glm_grid_cross_fail()
  variables <- c(predictors, raw$outcome)
  descriptors <- lapply(variables, function(variable) {
    owner <- sub("\\$.*$", "", variable)
    physical <- sub("^[^$]+\\$", "", variable)
    matches <- vapply(names(dataset$columns), function(name) {
      identical(sub("^[^$]+\\$", "", name), physical) &&
        identical(dataset$columns[[name]]$owner_peer, owner)
    }, logical(1L))
    if (sum(matches) != 1L) .dsvert_dp_glm_grid_cross_fail()
    column <- dataset$columns[[which(matches)]]
    if (!is.list(column) || !identical(column$kind, "numeric")) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    list(reference = variable, dataset = raw$dataset,
         owner_peer = column$owner_peer,
         column = physical,
         lower = column$lower, upper = column$upper)
  })
  names(descriptors) <- variables
  participants <- sort(unique(vapply(
    descriptors, `[[`, character(1L), "owner_peer")), method = "radix")
  compute <- sort(unname(policy$designated_noise_peers), method = "radix")
  if (length(participants) < 2L || length(compute) != 2L ||
      anyDuplicated(compute) || !all(compute %in% names(policy$peer_pinset))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  maximum <- .dsvert_dp_glm_grid_cross_integer(raw$max_outcome, 1, 1024)
  outcome <- descriptors[[raw$outcome]]
  if (outcome$lower != 0 || outcome$upper != maximum ||
      (identical(family, "binomial") && maximum != 1)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
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
  beta_grid <- raw$beta_grid
  if (!is.list(beta_grid) || !is.null(names(beta_grid)) ||
      !length(beta_grid) || length(beta_grid) > 256L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  beta_grid <- lapply(beta_grid, function(beta) {
    if (is.list(beta) && is.null(names(beta))) {
      if (!all(vapply(beta, function(x) is.numeric(x) && length(x) == 1L,
                      logical(1L)))) .dsvert_dp_glm_grid_cross_fail()
      beta <- unlist(beta, use.names = FALSE)
    }
    if (!is.numeric(beta) || !is.null(names(beta)) || anyNA(beta) ||
        any(!is.finite(beta)) || length(beta) != 1L + length(predictors) ||
        any(abs(beta) > 8) || sum(abs(beta)) > 16) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    as.list(as.numeric(beta))
  })
  keys <- vapply(beta_grid, .dsvert_dp_canonical_json, character(1L))
  if (anyDuplicated(keys) || !identical(keys, sort(keys, method = "radix"))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  bits <- .dsvert_dp_glm_grid_cross_integer(policy$numeric_grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(
    policy$unit_capacity, 1, 2^31 - 1)
  numeric <- .dsvert_dp_glm_grid_cross_numeric(family)
  sensitivity <- .dsvert_dp_glm_grid_cross_sensitivity(
    beta_grid, family, maximum, bits, capacity, policy$adjacency)
  list(
    version = unname(.DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS[[family]]),
    family = family, analysis_id = raw$analysis_id, dataset = raw$dataset,
    schema_sha256 = schema$sha256,
    logical_snapshot = schema$unsigned$logical_snapshot,
    peer_pinset_sha256 = schema$unsigned$peer_pinset_sha256,
    outcome = outcome, predictors = descriptors[predictors],
    owner_peer = outcome$owner_peer, participating_peers = as.list(participants),
    computation_peers = as.list(compute), predictor_order = as.list(predictors),
    input_variable_order = as.list(variables),
    design_terms = as.list(c("(Intercept)", predictors)), intercept = TRUE,
    beta_grid = beta_grid,
    beta_encoded = lapply(beta_grid, function(beta) as.list(vapply(
      beta, function(value) sprintf("%.0f", round(value * 2^50)),
      character(1L)))),
    candidate_order = as.list(vapply(beta_grid, .dsvert_joint_dp_hash,
                                     character(1L))),
    max_outcome = maximum, observation_capacity = capacity,
    numeric_grid_bits = bits, adjacency = policy$adjacency,
    alignment = alignment, numeric_contract = numeric,
    preprocessing =
      "clip_each_finite_record_then_patient_mean_then_require_integer_outcome_v1",
    predictor_normalization = "bounded_patient_mean_to_unit_interval_v1",
    complete_case = "all_owned_input_validity_bits_and_private_alignment_v1",
    sensitivity = sensitivity)
}

.dsvert_dp_glm_grid_cross_spec_validate <- function(value, policy, schema) {
  tryCatch({
    raw <- value[c("version", "analysis_id", "dataset", "predictor_order",
                   "beta_grid", "max_outcome", "alignment")]
    raw$outcome <- value$outcome$reference
    expected <- .dsvert_dp_glm_grid_cross_spec(raw, policy, schema)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_glm_grid_cross_layout <- function(spec) {
  capacity <- spec$observation_capacity
  count <- length(spec$beta_grid)
  start <- ceiling(count / 8192) * 8192 + 1
  cursor <- start
  variables <- unlist(spec$input_variable_order, use.names = FALSE)
  blocks <- lapply(variables, function(variable) {
    outcome <- identical(variable, spec$outcome$reference)
    descriptor <- if (outcome) spec$outcome else spec$predictors[[variable]]
    result <- list(
      reference = variable, owner_peer = descriptor$owner_peer,
      value_start = cursor, validity_start = cursor + capacity,
      length = capacity, value_fraction_bits = if (outcome) 0 else 50,
      value_encoding = if (outcome) "bounded_unsigned_integer_v1" else
        "normalized_unsigned_fixed_point_v1",
      value_maximum = if (outcome) spec$max_outcome else 2^50,
      validity_fraction_bits = 0, validity_maximum = 1)
    cursor <<- cursor + 2 * capacity
    result
  })
  if (cursor - 1 > 64 * 1024^2) .dsvert_dp_glm_grid_cross_fail()
  list(
    version = .DSVERT_DP_GLM_GRID_CROSS_LAYOUT_VERSION,
    ring_bits = 128, record_bytes = 16, release_coordinate_count = count,
    release_prefix_source_rule = "all_zero_until_authenticated_result_injection_v1",
    private_start = start, padding_coordinates = start - count - 1,
    padding_rule = "zero_to_next_source_chunk_boundary_v1",
    padded_units = capacity, padding_value = 0, padding_validity = 0,
    block_order = "predictors_then_outcome_each_values_then_validity_v1",
    blocks = blocks, transport_coordinate_count = cursor - 1)
}

.dsvert_dp_glm_grid_cross_artifact <- function(spec) {
  list(
    version = unname(.DSVERT_DP_GLM_GRID_CROSS_ARTIFACT_VERSIONS[[spec$family]]),
    spec_version = spec$version, spec_sha256 = .dsvert_joint_dp_hash(spec),
    analysis_id = spec$analysis_id, owner_peer = spec$owner_peer,
    participating_peers = spec$participating_peers,
    computation_peers = spec$computation_peers,
    candidate_order = spec$candidate_order,
    coordinate_count = length(spec$beta_grid),
    numeric_grid_bits = spec$numeric_grid_bits,
    source_coordinate_scaling =
      "all_coordinates_already_on_common_numeric_lattice_v1",
    sensitivity = spec$sensitivity,
    numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    private_layout_sha256 = .dsvert_joint_dp_hash(
      .dsvert_dp_glm_grid_cross_layout(spec)),
    transcript = list(
      version = "dsvert-cross-grid-fixed-transcript-v1",
      operation = paste0("dp.", spec$family, "-grid-cross.v1"),
      padded_units = spec$observation_capacity,
      candidate_count = length(spec$beta_grid),
      row_batch_size = min(32, spec$observation_capacity),
      candidate_batch_size = min(8, length(spec$beta_grid)),
      traversal = "row_batch_then_candidate_batch_v1",
      output = "two_authority_additive_candidate_sum_shares_only_v1"),
    result_evidence_required = TRUE,
    implementation_state = .DSVERT_DP_GLM_GRID_CROSS_IMPLEMENTATION_STATE,
    cross_owner_state = .DSVERT_DP_GLM_GRID_CROSS_STATE)
}

.dsvert_dp_glm_grid_cross_artifact_validate <- function(value, spec) {
  tryCatch({
    expected <- .dsvert_dp_glm_grid_cross_artifact(spec)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_glm_grid_cross_source_contract <- function(spec, artifact) {
  list(
    version = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_VERSION,
    purpose = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_PURPOSE,
    spec_sha256 = .dsvert_joint_dp_hash(spec),
    artifact_sha256 = .dsvert_joint_dp_hash(artifact),
    schema_sha256 = spec$schema_sha256,
    logical_snapshot = spec$logical_snapshot,
    peer_pinset_sha256 = spec$peer_pinset_sha256,
    source_peers = spec$participating_peers,
    recipients = spec$computation_peers,
    alignment = spec$alignment,
    alignment_sharing = "recipient_specific_xor_share_exact_gc_gate_v1",
    numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    private_layout = .dsvert_dp_glm_grid_cross_layout(spec))
}

.dsvert_dp_glm_grid_cross_source_contract_validate <- function(
    value, spec, artifact) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_artifact_validate(artifact, spec)
    expected <- .dsvert_dp_glm_grid_cross_source_contract(spec, artifact)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_glm_grid_cross_message <- function(unsigned) {
  charToRaw(paste0(.DSVERT_DP_GLM_GRID_CROSS_SIGNING_DOMAIN,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_glm_grid_cross_contract_validate <- function(
    value, policy, schema_manifest,
    .verifier = .dsvert_relay_verify_message) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(value, c(
      "version", "spec", "artifact", "source_contract", "signatures"))
    if (!identical(value$version, .DSVERT_DP_GLM_GRID_CROSS_CONTRACT_VERSION)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    schema <- .dsvert_dp_capsule_schema(
      policy, schema_manifest$logical_snapshot, schema_manifest, .verifier)
    spec <- .dsvert_dp_glm_grid_cross_spec_validate(value$spec, policy, schema)
    artifact <- .dsvert_dp_glm_grid_cross_artifact_validate(value$artifact, spec)
    .dsvert_dp_glm_grid_cross_source_contract_validate(
      value$source_contract, spec, artifact)
    pins <- policy$peer_pinset
    .dsvert_dp_glm_grid_cross_fields(value$signatures, names(pins))
    unsigned <- value[setdiff(names(value), "signatures")]
    message <- .dsvert_dp_glm_grid_cross_message(unsigned)
    verified <- vapply(names(pins), function(peer) {
      signature <- value$signatures[[peer]]
      is.character(signature) && length(signature) == 1L &&
        !is.na(signature) && grepl("^[A-Za-z0-9_-]{86}$", signature) &&
        isTRUE(.verifier(message, unname(pins[[peer]]), signature))
    }, logical(1L))
    if (!all(verified)) .dsvert_dp_glm_grid_cross_fail()
    .dsvert_dp_canonical_query_value(value)
  }, error = .dsvert_dp_transcript_stop)
}
