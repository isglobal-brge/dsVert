# Isolated NB2 extension of the frozen cross-owner source ABI. These functions
# validate public plans only; registration does not authorize a production release.

.DSVERT_DP_NB_GRID_CROSS_PROFILE_SHA256 <- "36771f85ecc4edf240dc49a8fc2d49345f314ec5c8e758f4a918532902b3da17"
.DSVERT_DP_NB_GRID_CROSS_CERTIFICATE_SHA256 <- "1b21c0b8fe91b0f2f280c273469aaf0bad6a4deae176e3db2559ee83beea7dfd"
.DSVERT_DP_NB_GRID_CROSS_NUMERIC_SHA256 <- "369f10da36d7f4c12dd1989f3d838a90a8f1638ff80ace7cfbd4aef848d94ac1"

.dsvert_dp_nb_grid_cross_theta <- function(value, count) {
  if (is.list(value) && is.null(names(value)) && all(vapply(value, function(x) {
    is.numeric(x) && length(x) == 1L
  }, logical(1L)))) value <- unlist(value, use.names = FALSE)
  if (!is.numeric(value) || !is.null(names(value)) || length(value) != count ||
      anyNA(value) || any(!is.finite(value)) || any(!value %in% 2^(-3:7))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  as.numeric(value)
}

.dsvert_dp_nb_grid_cross_profile <- function() {
  path <- system.file("cross-grid-nb", "numeric_profile_nb_v1.json", package = "dsVert")
  if (!nzchar(path)) .dsvert_dp_glm_grid_cross_fail()
  value <- jsonlite::fromJSON(path, simplifyVector = FALSE)
  if (!identical(value$profile_sha256, .DSVERT_DP_NB_GRID_CROSS_PROFILE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$profile), .DSVERT_DP_NB_GRID_CROSS_PROFILE_SHA256) ||
      !identical(value$certificate_sha256, .DSVERT_DP_NB_GRID_CROSS_CERTIFICATE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$certificate), .DSVERT_DP_NB_GRID_CROSS_CERTIFICATE_SHA256) ||
      !identical(.dsvert_joint_dp_hash(value$numeric_contract), .DSVERT_DP_NB_GRID_CROSS_NUMERIC_SHA256)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  value
}

.dsvert_dp_nb_grid_cross_numeric <- function() {
  .dsvert_dp_nb_grid_cross_profile()$numeric_contract
}

# Correct NB2 negative log-PMF, in stable softplus form. All arguments here are
# public cap metadata or synthetic references, never an MPC substitute.
.dsvert_dp_nb_grid_cross_loss <- function(y, eta, theta) {
  z <- eta - log(theta)
  lgamma(theta) + lgamma(y + 1) - lgamma(y + theta) + y * log(theta) +
    (y + theta) * (pmax(z, 0) + log1p(exp(-abs(z)))) - y * eta
}

# Public cap arithmetic only. All q16 products below are integers < 2^53;
# division by a power of two and R ties-even rounding are exact here. This is
# never a protected-data evaluation callback.
.dsvert_dp_nb_grid_cross_public_softplus <- function(z, profile) {
  x <- round(z * 2^16)
  a <- abs(x)
  residual <- 0
  if (a < 16 * 2^16) {
    piece <- floor(a / 2^14) + 1L
    r <- a %% 2^14
    coefficients <- as.numeric(unlist(profile$softplus_quadratic_q16[[piece]],
                                      use.names = FALSE))
    residual <- coefficients[1L] + round((coefficients[2L] +
      round(coefficients[3L] * r / 2^16)) * r / 2^16)
  }
  (max(x, 0) + residual) / 2^16
}

# Exact upward conversion of a public signed decimal q64 integer to q16.
# Long division never exceeds 655359, including for the largest NB constants.
.dsvert_dp_nb_grid_cross_constant_upper <- function(value) {
  negative <- startsWith(value, "-")
  digits <- utf8ToInt(sub("^-", "", value)) - 48L
  remainder_nonzero <- FALSE
  for (shift in seq_len(3L)) {
    remainder <- 0
    for (i in seq_along(digits)) {
      next_digit <- remainder * 10 + digits[i]
      digits[i] <- floor(next_digit / 65536)
      remainder <- next_digit %% 65536
    }
    remainder_nonzero <- remainder_nonzero || remainder != 0
  }
  result <- 0
  for (digit in digits) result <- 10 * result + digit
  if (negative) -result / 2^16 else (result + remainder_nonzero) / 2^16
}

.dsvert_dp_nb_grid_cross_error <- function(maximum, theta) {
  (maximum + theta) * 0.00003936 + 1024 * 0.000000000000014655 + 2^-63
}

.dsvert_dp_nb_grid_cross_sensitivity <- function(
    beta_grid, theta_grid, max_outcome, grid_bits, capacity, adjacency) {
  grid_bits <- .dsvert_dp_glm_grid_cross_integer(grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(capacity, 1, 2^31 - 1)
  maximum <- .dsvert_dp_glm_grid_cross_integer(max_outcome, 1, 1024)
  if (!is.character(adjacency) || length(adjacency) != 1L ||
      !adjacency %in% c("add_remove_patient", "replace_one_fixed_cohort") ||
      !is.list(beta_grid) || !length(beta_grid) || length(beta_grid) > 256L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  theta_grid <- .dsvert_dp_nb_grid_cross_theta(theta_grid, length(beta_grid))
  profile <- .dsvert_dp_nb_grid_cross_profile()$profile
  public_tables <- lapply(unique(theta_grid), function(theta) {
    table <- profile$theta[[as.integer(log2(theta)) + 4L]]
    list(constants = vapply(table$constant_q64[seq_len(maximum + 1L)],
                           .dsvert_dp_nb_grid_cross_constant_upper, numeric(1L)),
         log_theta = as.numeric(table$log_theta_q64) / 2^64)
  })
  bounds <- Map(function(beta, theta) {
    beta <- unlist(beta, use.names = FALSE)
    if (!is.numeric(beta) || length(beta) < 2L || length(beta) > 17L ||
        anyNA(beta) || any(!is.finite(beta)) || any(abs(beta) > 8) ||
        !.dsvert_dp_glm_grid_cross_beta_l1_valid(beta)) .dsvert_dp_glm_grid_cross_fail()
    radius <- sum(abs(beta))
    table <- public_tables[[match(theta, unique(theta_grid))]]
    constants <- table$constants
    log_theta <- table$log_theta
    # Convexity locates the exact NB loss maximum at +/- A for each y.
    # The public profile endpoint approximation plus E_endpoint encloses it;
    # add 2 E_row so U/S >= max(profile loss) + E_row, before output rounding.
    endpoint <- vapply(c(-radius, radius), function(eta) {
      soft <- .dsvert_dp_nb_grid_cross_public_softplus(eta - log_theta, profile)
      max(constants + (0:maximum + theta) * soft - (0:maximum) * eta)
    }, numeric(1L))
    error <- .dsvert_dp_nb_grid_cross_error(maximum, theta)
    endpoint_error <- (maximum + theta) * (0.00003936 + 2^-16) + 2^-20
    loss <- max(0, endpoint) + endpoint_error + 2 * error
    list(eta_lower = beta[[1L]] + sum(pmin(beta[-1L], 0)),
         eta_upper = beta[[1L]] + sum(pmax(beta[-1L], 0)),
         absolute_eta_bound = radius, loss_bound = loss,
         certified_row_error = error, endpoint_error = endpoint_error,
         per_patient_cap = ceiling(2^grid_bits * loss))
  }, beta_grid, theta_grid)
  caps <- vapply(bounds, `[[`, numeric(1L), "per_patient_cap")
  multiplier <- if (identical(adjacency, "add_remove_patient")) 1 else 2
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps)
  maxima <- capacity * caps
  if (any(!is.finite(c(caps, maxima, l1, l2))) ||
      any(c(caps, maxima, l1, l2) > 2^53 - 1)) .dsvert_dp_glm_grid_cross_fail()
  list(candidate_bounds = bounds, maximum_coordinates = as.list(maxima),
       adjacency_multiplier = multiplier, raw_l1_sensitivity = l1,
       raw_l2_sensitivity = l2, natural_l1_sensitivity = l1 / 2^grid_bits,
       natural_l2_sensitivity = l2 / 2^grid_bits)
}

.dsvert_dp_nb_grid_cross_spec <- function(raw, policy, schema) {
  .dsvert_dp_glm_grid_cross_fields(raw, c(
    "version", "analysis_id", "dataset", "outcome", "predictor_order",
    "beta_grid", "theta_grid", "max_outcome", "alignment"))
  family <- "nb"
  if (!identical(raw$version, "nb_grid_cross_v1")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  for (field in c("analysis_id", "dataset")) {
    if (!is.character(raw[[field]]) || length(raw[[field]]) != 1L ||
        length(.dsvert_dp_glm_grid_cross_strings(raw[[field]])) != 1L) {
      .dsvert_dp_glm_grid_cross_fail()
    }
  }
  if (!is.character(raw$outcome) || length(raw$outcome) != 1L ||
      length(.dsvert_dp_glm_grid_cross_references(raw$outcome)) != 1L) {
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
  if (outcome$lower != 0 || outcome$upper != maximum) {
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
        any(abs(beta) > 8) || !.dsvert_dp_glm_grid_cross_beta_l1_valid(beta)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    as.list(as.numeric(beta))
  })
  theta_grid <- .dsvert_dp_nb_grid_cross_theta(raw$theta_grid, length(beta_grid))
  candidates <- Map(function(beta, theta) list(beta = beta, theta = theta),
                    beta_grid, theta_grid)
  keys <- vapply(candidates, .dsvert_dp_canonical_json, character(1L))
  if (anyDuplicated(keys) || !identical(keys, sort(keys, method = "radix"))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  bits <- .dsvert_dp_glm_grid_cross_integer(policy$numeric_grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(
    policy$unit_capacity, 1, 2^31 - 1)
  numeric <- .dsvert_dp_nb_grid_cross_numeric()
  sensitivity <- .dsvert_dp_nb_grid_cross_sensitivity(
    beta_grid, theta_grid, maximum, bits, capacity, policy$adjacency)
  result <- list(
    version = "nb_grid_cross_v1",
    family = family, analysis_id = raw$analysis_id, dataset = raw$dataset,
    schema_sha256 = schema$sha256,
    logical_snapshot = schema$unsigned$logical_snapshot,
    peer_pinset_sha256 = schema$unsigned$peer_pinset_sha256,
    outcome = outcome, predictors = descriptors[predictors],
    owner_peer = outcome$owner_peer, participating_peers = as.list(participants),
    computation_peers = as.list(compute), predictor_order = as.list(predictors),
    input_variable_order = as.list(variables),
    design_terms = as.list(c("(Intercept)", predictors)), intercept = TRUE,
    beta_grid = beta_grid, theta_grid = as.list(theta_grid),
    beta_encoded = lapply(beta_grid, function(beta) as.list(vapply(
      beta, function(value) {
        encoded <- round(value * 2^50)
        if (encoded == 0) encoded <- 0
        sprintf("%.0f", encoded)
      },
      character(1L)))),
    candidate_order = as.list(vapply(candidates, .dsvert_joint_dp_hash,
                                     character(1L))),
    max_outcome = maximum, observation_capacity = capacity,
    numeric_grid_bits = bits, adjacency = policy$adjacency,
    alignment = alignment, numeric_contract = numeric,
    preprocessing =
      "clip_each_finite_record_then_patient_mean_then_require_integer_outcome_v1",
    predictor_normalization = "bounded_patient_mean_to_unit_interval_v1",
    complete_case = "all_owned_input_validity_bits_and_private_alignment_v1",
    sensitivity = sensitivity)
  encoded_keys <- vapply(Map(function(beta, theta) list(beta = beta, theta = theta),
    result$beta_encoded, result$theta_grid), .dsvert_dp_canonical_json, character(1L))
  if (anyDuplicated(encoded_keys)) .dsvert_dp_glm_grid_cross_fail()
  result
}

.dsvert_dp_nb_grid_cross_spec_validate <- function(value, policy, schema) {
  tryCatch({
    raw <- value[c("version", "analysis_id", "dataset", "predictor_order",
                   "beta_grid", "theta_grid", "max_outcome", "alignment")]
    raw$outcome <- value$outcome$reference
    expected <- .dsvert_dp_nb_grid_cross_spec(raw, policy, schema)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_nb_grid_cross_artifact <- function(spec) {
  list(
    version = "bounded-negative-binomial-cross-likelihood-grid-v1",
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

.dsvert_dp_nb_grid_cross_artifact_validate <- function(value, spec) {
  tryCatch({
    expected <- .dsvert_dp_nb_grid_cross_artifact(spec)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_nb_grid_cross_source_contract <- function(spec, artifact) {
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

.dsvert_dp_nb_grid_cross_source_contract_validate <- function(
    value, spec, artifact) {
  tryCatch({
    .dsvert_dp_nb_grid_cross_artifact_validate(artifact, spec)
    expected <- .dsvert_dp_nb_grid_cross_source_contract(spec, artifact)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_nb_grid_cross_contract_validate <- function(
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
    spec <- .dsvert_dp_nb_grid_cross_spec_validate(value$spec, policy, schema)
    artifact <- .dsvert_dp_nb_grid_cross_artifact_validate(value$artifact, spec)
    .dsvert_dp_nb_grid_cross_source_contract_validate(
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

# Single integration seam. Register these callbacks with the fused producer;
# do not register a reference evaluator as a protected-data implementation.
.dsvert_dp_nb_grid_cross_register <- function() {
  list(family = "nb", spec_version = "nb_grid_cross_v1",
       artifact_version = "bounded-negative-binomial-cross-likelihood-grid-v1",
       build_spec = .dsvert_dp_nb_grid_cross_spec,
       validate_spec = .dsvert_dp_nb_grid_cross_spec_validate,
       build_artifact = .dsvert_dp_nb_grid_cross_artifact,
       validate_artifact = .dsvert_dp_nb_grid_cross_artifact_validate,
       build_source_contract = .dsvert_dp_nb_grid_cross_source_contract,
       validate_contract = .dsvert_dp_nb_grid_cross_contract_validate,
       sensitivity = .dsvert_dp_nb_grid_cross_sensitivity,
       production_release_registered = FALSE)
}
