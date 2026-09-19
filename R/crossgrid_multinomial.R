# Categorical cross-owner finite-grid contracts. Registration is deliberately
# separate from the shared producer/release dispatcher: a validated contract
# is not evidence that MPC or the two-authority noise protocol completed.
.dsvert_dp_categorical_grid_cross_numeric <- function(family) {
  if (!family %in% c("multinomial", "ordinal")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  list(version = paste0("cross-grid-", family, "-piecewise-q16-v1"),
    base_profile_sha256 = .DSVERT_DP_GLM_GRID_CROSS_PROFILE_SHA256,
    base_certificate_sha256 = .DSVERT_DP_GLM_GRID_CROSS_CERTIFICATE_SHA256,
    profile_sha256 = "fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef",
    certificate_sha256 = "b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67",
    certified_uniform_error = if (family == "multinomial") "0.0011" else "0.00012",
    input_fraction_bits = 50, coefficient_fraction_bits = 50,
    nonlinear_fraction_bits = 16, arithmetic_width_bits = 32,
    dot_product_width_bits = 192, profile_pieces = 64, profile_degree = 2,
    output_grid_bits_min = 8, output_grid_bits_max = 18,
    rounding_rule = "nearest_ties_to_even_v1",
    dot_product = "complete_f100_sum_then_one_q16_round_v1",
    exponential = "max_shift_then_piecewise_exp_negative16_zero_tail_v1",
    logarithm = "normalize_q16_to_one_two_then_piecewise_log_v1",
    log2_q16 = 45426,
    log_sigmoid = "piecewise_softminus_absolute_argument_plus_positive_part_v1",
    public_gap = "exp32_log24_q64_signed_public_thresholds_only_then_q16_v1",
    output_rounding_error = "zero_for_g_ge_16_else_2_pow_minus_g_minus_one_v1",
    class_count_min = 2, class_count_max = 8,
    predictor_count_max = 16, coefficient_absolute_maximum = 8,
    class_beta_l1_maximum = if (family == "multinomial") 16 else 8,
    ordinal_threshold_absolute_maximum = 8,
    ordinal_threshold_gap_minimum = 1 / 16,
    ordinal_intercept = "exact_zero_identifiability_constraint_v1",
    outcome_encoding = "signed_class_order_zero_based_integer_v1",
    output_rule = "mask_clamp_to_signed_patient_cap_then_round_then_sum_v1")
}

.dsvert_dp_categorical_grid_cross_vector <- function(value, count = NULL) {
  if (is.list(value) && is.null(names(value)) && all(vapply(value,
      function(x) is.numeric(x) && length(x) == 1L, logical(1L)))) {
    value <- unlist(value, use.names = FALSE)
  }
  if (!is.numeric(value) || !is.null(names(value)) || !length(value) ||
      anyNA(value) || any(!is.finite(value)) ||
      (!is.null(count) && length(value) != count)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  as.numeric(value)
}

.dsvert_dp_categorical_grid_cross_levels <- function(value) {
  if (is.list(value) && is.null(names(value)) && all(vapply(value,
      function(x) is.character(x) && length(x) == 1L, logical(1L)))) {
    value <- unlist(value, use.names = FALSE)
  }
  if (!is.character(value) || !is.null(names(value)) || anyNA(value) ||
      length(value) < 2L || length(value) > 8L || anyDuplicated(value) ||
      any(!nzchar(trimws(value)))) .dsvert_dp_glm_grid_cross_fail()
  value
}

.dsvert_dp_categorical_grid_cross_encode <- function(value) {
  as.list(vapply(value, function(x) {
    integer <- round(x * 2^50)
    if (integer == 0) integer <- 0
    sprintf("%.0f", integer)
  }, character(1L)))
}

.dsvert_dp_categorical_grid_cross_gap_valid <- function(lower, upper) {
  expansion <- numeric()
  for (value in c(lower, 1 / 16, -upper)) {
    next_expansion <- numeric()
    total <- value
    for (component in expansion) {
      next_total <- total + component
      virtual <- next_total - total
      remainder <- (total - (next_total - virtual)) + (component - virtual)
      if (remainder != 0) next_expansion <- c(next_expansion, remainder)
      total <- next_total
    }
    if (total != 0) next_expansion <- c(next_expansion, total)
    expansion <- next_expansion
  }
  !length(expansion) || tail(expansion, 1L) < 0
}

.dsvert_dp_categorical_grid_cross_candidates <- function(raw, family, p, k) {
  candidates <- if (family == "multinomial") raw$beta_grid else raw$candidate_grid
  if (!is.list(candidates) || !is.null(names(candidates)) ||
      !length(candidates) || length(candidates) > 256L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  candidates <- lapply(candidates, function(candidate) {
    if (family == "multinomial") {
      beta <- .dsvert_dp_categorical_grid_cross_vector(candidate, (p + 1L) * (k - 1L))
      columns <- split(beta, rep(seq_len(k - 1L), each = p + 1L))
      if (any(abs(beta) > 8) || !all(vapply(columns,
          .dsvert_dp_glm_grid_cross_beta_l1_valid, logical(1L)))) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      return(as.list(beta))
    }
    .dsvert_dp_glm_grid_cross_fields(candidate, c("beta", "thresholds"))
    beta <- .dsvert_dp_categorical_grid_cross_vector(candidate$beta, p + 1L)
    thresholds <- .dsvert_dp_categorical_grid_cross_vector(candidate$thresholds, k - 1L)
    # Scaling by two uses the frozen exact binary64 L1 comparison with 16.
    if (beta[1L] != 0 || any(abs(beta) > 8) ||
        !.dsvert_dp_glm_grid_cross_beta_l1_valid(2 * beta) ||
        any(abs(thresholds) > 8) || any(diff(thresholds) < 1 / 16)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    encoded_thresholds <- round(thresholds * 2^50)
    if (any(diff(encoded_thresholds) < 2^46)) .dsvert_dp_glm_grid_cross_fail()
    if (length(thresholds) > 1L && !all(vapply(seq_len(length(thresholds) - 1L),
        function(i) .dsvert_dp_categorical_grid_cross_gap_valid(
          thresholds[i], thresholds[i + 1L]), logical(1L)))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    list(beta = as.list(beta), thresholds = as.list(thresholds))
  })
  keys <- vapply(candidates, .dsvert_dp_canonical_json, character(1L))
  encoded <- lapply(candidates, function(candidate) {
    if (family == "multinomial") return(.dsvert_dp_categorical_grid_cross_encode(candidate))
    list(beta = .dsvert_dp_categorical_grid_cross_encode(candidate$beta),
         thresholds = .dsvert_dp_categorical_grid_cross_encode(candidate$thresholds))
  })
  encoded_keys <- vapply(encoded, .dsvert_dp_canonical_json, character(1L))
  if (anyDuplicated(keys) || anyDuplicated(encoded_keys) ||
      !identical(keys, sort(keys, method = "radix"))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  list(candidates = candidates, encoded = encoded)
}

.dsvert_dp_categorical_grid_cross_sensitivity <- function(
    candidates, family, class_count, predictor_count, grid_bits, capacity,
    adjacency) {
  if (length(family) != 1L || !family %in% c("multinomial", "ordinal")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  grid_bits <- .dsvert_dp_glm_grid_cross_integer(grid_bits, 8, 18)
  capacity <- .dsvert_dp_glm_grid_cross_integer(capacity, 1, 2^31 - 1)
  class_count <- .dsvert_dp_glm_grid_cross_integer(class_count, 2, 8)
  predictor_count <- .dsvert_dp_glm_grid_cross_integer(predictor_count, 1, 16)
  if (length(adjacency) != 1L || !adjacency %in%
      c("add_remove_patient", "replace_one_fixed_cohort")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  raw <- if (family == "multinomial") list(beta_grid = candidates) else
    list(candidate_grid = candidates)
  candidates <- .dsvert_dp_categorical_grid_cross_candidates(
    raw, family, predictor_count, class_count)$candidates
  error <- as.numeric(.dsvert_dp_categorical_grid_cross_numeric(family)$certified_uniform_error)
  output_error <- if (grid_bits < 16) 2^(-grid_bits - 1) else 0
  # The profile is within error of the real loss. Reserve a second error
  # allowance so U/S encloses the rounded profile contribution plus error.
  cap_bound <- function(loss) {
    (loss + 2 * error + output_error) * (1 + 64 * .Machine$double.eps)
  }
  bounds <- lapply(candidates, function(candidate) {
    if (family == "multinomial") {
      beta <- matrix(unlist(candidate), nrow = predictor_count + 1L)
      radii <- colSums(abs(beta))
      radius <- max(radii)
      loss <- 2 * radius + log(class_count)
      return(list(class_absolute_eta_bounds = as.list(radii),
        absolute_eta_bound = radius, exact_loss_bound = loss,
        profile_error_bound = error, output_rounding_error_bound = output_error,
        loss_bound = cap_bound(loss),
        per_patient_cap = ceiling(2^grid_bits * cap_bound(loss))))
    }
    radius <- sum(abs(unlist(candidate$beta)))
    thresholds <- unlist(candidate$thresholds)
    tail <- max(abs(thresholds)) + radius
    endpoint_loss <- tail + log1p(exp(-tail))
    gap <- if (length(thresholds) > 1L) min(diff(thresholds)) else NULL
    loss <- if (is.null(gap)) endpoint_loss else max(endpoint_loss,
      tail + 2 * log1p(exp(-tail)) - log(gap))
    list(absolute_eta_bound = radius, absolute_threshold_argument_bound = tail,
      minimum_threshold_gap = gap, probability_lower_bound = exp(-loss),
      exact_loss_bound = loss, profile_error_bound = error,
      output_rounding_error_bound = output_error, loss_bound = cap_bound(loss),
      per_patient_cap = ceiling(2^grid_bits * cap_bound(loss)))
  })
  caps <- vapply(bounds, `[[`, numeric(1L), "per_patient_cap")
  multiplier <- if (adjacency == "add_remove_patient") 1 else 2
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps)
  maxima <- capacity * caps
  if (any(!is.finite(c(caps, maxima, l1, l2))) ||
      any(c(caps, maxima, l1, l2) > 2^53 - 1)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  list(candidate_bounds = bounds, maximum_coordinates = as.list(maxima),
    adjacency_multiplier = multiplier, raw_l1_sensitivity = l1,
    raw_l2_sensitivity = l2, natural_l1_sensitivity = l1 / 2^grid_bits,
    natural_l2_sensitivity = l2 / 2^grid_bits)
}

.dsvert_dp_categorical_grid_cross_spec <- function(raw, policy, schema, family) {
  tryCatch({
    fields <- c("version", "analysis_id", "dataset", "outcome", "predictor_order",
      "alignment", if (family == "multinomial") c("beta_grid", "levels", "reference")
      else c("candidate_grid", "ordered_levels"))
    .dsvert_dp_glm_grid_cross_fields(raw, fields)
    if (!identical(raw$version, paste0(family, "_grid_cross_v1"))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    for (field in c("analysis_id", "dataset")) {
      if (!is.character(raw[[field]]) || length(raw[[field]]) != 1L) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      .dsvert_dp_glm_grid_cross_strings(raw[[field]])
    }
    if (!is.character(raw$outcome) || length(raw$outcome) != 1L) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    .dsvert_dp_glm_grid_cross_references(raw$outcome)
    predictors <- .dsvert_dp_glm_grid_cross_references(raw$predictor_order)
    if (length(predictors) > 16L || raw$outcome %in% predictors ||
        !identical(predictors, sort(predictors, method = "radix"))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    levels <- .dsvert_dp_categorical_grid_cross_levels(
      if (family == "multinomial") raw$levels else raw$ordered_levels)
    if (family == "multinomial" &&
        (!identical(levels, sort(levels, method = "radix")) ||
         !is.character(raw$reference) || length(raw$reference) != 1L ||
         is.na(raw$reference) || !raw$reference %in% levels)) {
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
      outcome <- identical(variable, raw$outcome)
      if (!identical(column$kind, if (outcome) "categorical" else "numeric")) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      result <- list(reference = variable, dataset = raw$dataset,
        owner_peer = column$owner_peer, column = physical)
      if (outcome) {
        if (!setequal(unlist(column$levels), levels)) .dsvert_dp_glm_grid_cross_fail()
        result$levels <- as.list(levels)
      } else {
        result$lower <- column$lower
        result$upper <- column$upper
      }
      result
    })
    names(descriptors) <- variables
    participants <- sort(unique(vapply(descriptors, `[[`, character(1L),
      "owner_peer")), method = "radix")
    compute <- sort(unname(policy$designated_noise_peers), method = "radix")
    if (length(participants) != 2L || length(compute) != 2L ||
        !identical(participants, compute) ||
        anyDuplicated(compute) || !all(compute %in% names(policy$peer_pinset))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    alignment <- list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = dataset$alignment_group,
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = schema$unsigned$logical_snapshot,
        alignment_group = dataset$alignment_group,
        method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE)
    .dsvert_dp_glm_grid_cross_equal(raw$alignment, alignment)
    candidates <- .dsvert_dp_categorical_grid_cross_candidates(
      raw, family, length(predictors), length(levels))
    bits <- .dsvert_dp_glm_grid_cross_integer(policy$numeric_grid_bits, 8, 18)
    capacity <- .dsvert_dp_glm_grid_cross_integer(policy$unit_capacity, 1, 2^31 - 1)
    value <- list(version = raw$version, family = family, analysis_id = raw$analysis_id,
      dataset = raw$dataset, schema_sha256 = schema$sha256,
      logical_snapshot = schema$unsigned$logical_snapshot,
      peer_pinset_sha256 = schema$unsigned$peer_pinset_sha256,
      outcome = descriptors[[raw$outcome]], predictors = descriptors[predictors],
      owner_peer = descriptors[[raw$outcome]]$owner_peer,
      participating_peers = as.list(participants), computation_peers = as.list(compute),
      predictor_order = as.list(predictors), input_variable_order = as.list(variables),
      design_terms = as.list(c("(Intercept)", predictors)), intercept = TRUE,
      class_order = as.list(levels), class_count = length(levels),
      max_outcome = length(levels) - 1L,
      observation_capacity = capacity, numeric_grid_bits = bits, adjacency = policy$adjacency,
      alignment = alignment, numeric_contract = .dsvert_dp_categorical_grid_cross_numeric(family),
      preprocessing = "require_one_signed_categorical_outcome_clip_numeric_records_then_patient_mean_v1",
      predictor_normalization = "bounded_patient_mean_to_unit_interval_v1",
      complete_case = "all_owned_input_validity_bits_and_private_alignment_v1",
      sensitivity = .dsvert_dp_categorical_grid_cross_sensitivity(
        candidates$candidates, family, length(levels), length(predictors), bits,
        capacity, policy$adjacency))
    if (family == "multinomial") {
      value$reference <- raw$reference
      value$non_reference_order <- as.list(setdiff(levels, raw$reference))
      value$class_order <- as.list(c(raw$reference, setdiff(levels, raw$reference)))
      value$outcome$levels <- value$class_order
      value$beta_grid <- candidates$candidates
      value$beta_encoded <- candidates$encoded
      value$coefficient_order <- "class_major_then_intercept_then_predictor_order_v1"
    } else {
      value$candidate_grid <- candidates$candidates
      value$candidate_encoded <- candidates$encoded
      value$beta_grid <- lapply(candidates$candidates, `[[`, "beta")
      value$beta_encoded <- lapply(candidates$encoded, `[[`, "beta")
      value$coefficient_order <- "zero_intercept_then_predictor_order_v1"
    }
    value$candidate_order <- as.list(vapply(candidates$candidates,
      .dsvert_joint_dp_hash, character(1L)))
    # Validate source memory before any protected snapshot can be resolved.
    .dsvert_dp_glm_grid_cross_layout(value)
    value
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_categorical_grid_cross_spec_validate <- function(value, policy, schema, family) {
  tryCatch({
    raw <- value[c("version", "analysis_id", "dataset", "predictor_order", "alignment")]
    raw$outcome <- value$outcome$reference
    if (family == "multinomial") {
      raw$levels <- sort(unlist(value$class_order, use.names = FALSE), method = "radix")
      raw$reference <- value$reference
      raw$beta_grid <- value$beta_grid
    } else {
      raw$ordered_levels <- value$class_order
      raw$candidate_grid <- value$candidate_grid
    }
    expected <- .dsvert_dp_categorical_grid_cross_spec(raw, policy, schema, family)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_categorical_grid_cross_artifact <- function(spec) {
  list(version = paste0("bounded-", spec$family, "-cross-likelihood-grid-v1"),
    spec_version = spec$version, spec_sha256 = .dsvert_joint_dp_hash(spec),
    analysis_id = spec$analysis_id, owner_peer = spec$owner_peer,
    participating_peers = spec$participating_peers, computation_peers = spec$computation_peers,
    candidate_order = spec$candidate_order, coordinate_count = length(spec$beta_grid),
    numeric_grid_bits = spec$numeric_grid_bits,
    source_coordinate_scaling = "all_coordinates_already_on_common_numeric_lattice_v1",
    sensitivity = spec$sensitivity,
    numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    private_layout_sha256 = .dsvert_joint_dp_hash(.dsvert_dp_glm_grid_cross_layout(spec)),
    transcript = list(version = "dsvert-cross-grid-fixed-transcript-v1",
      operation = paste0("dp.", spec$family, "-grid-cross.v1"),
      padded_units = spec$observation_capacity, candidate_count = length(spec$beta_grid),
      class_count = spec$class_count,
      row_batch_size = min(32, spec$observation_capacity),
      candidate_batch_size = min(8, length(spec$beta_grid)),
      traversal = "row_batch_then_candidate_batch_v1",
      output = "two_authority_additive_candidate_sum_shares_only_v1"),
    result_evidence_required = TRUE,
    implementation_state = "cross_owner_exact_gc_materialized",
    cross_owner_state = "exact_gc_to_joint_dp_vector_v1")
}

.dsvert_dp_categorical_grid_cross_contract_validate <- function(
    value, policy, schema_manifest, family, .verifier = .dsvert_relay_verify_message) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(value, c("version", "spec", "artifact",
      "source_contract", "signatures"))
    if (!identical(value$version, .DSVERT_DP_GLM_GRID_CROSS_CONTRACT_VERSION)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    # JSON arrays and atomic R vectors have the same signed canonical message.
    # The inherited categorical schema parser expects atomic label vectors.
    schema_manifest$datasets <- lapply(schema_manifest$datasets, function(dataset) {
      dataset$columns <- lapply(dataset$columns, function(column) {
        if (identical(column$kind, "categorical") && is.list(column$levels) &&
            is.null(names(column$levels)) && all(vapply(column$levels,
              function(x) is.character(x) && length(x) == 1L, logical(1L)))) {
          column$levels <- unlist(column$levels, use.names = FALSE)
        }
        column
      })
      dataset
    })
    schema <- .dsvert_dp_capsule_schema(policy, schema_manifest$logical_snapshot,
      schema_manifest, .verifier)
    spec <- .dsvert_dp_categorical_grid_cross_spec_validate(value$spec, policy, schema, family)
    artifact <- .dsvert_dp_categorical_grid_cross_artifact(spec)
    .dsvert_dp_glm_grid_cross_equal(value$artifact, artifact)
    .dsvert_dp_glm_grid_cross_equal(value$source_contract,
      .dsvert_dp_glm_grid_cross_source_contract(spec, artifact))
    pins <- policy$peer_pinset
    .dsvert_dp_glm_grid_cross_fields(value$signatures, names(pins))
    message <- .dsvert_dp_glm_grid_cross_message(value[setdiff(names(value), "signatures")])
    verified <- vapply(names(pins), function(peer) {
      signature <- value$signatures[[peer]]
      is.character(signature) && length(signature) == 1L && !is.na(signature) &&
        grepl("^[A-Za-z0-9_-]{86}$", signature) &&
        isTRUE(.verifier(message, unname(pins[[peer]]), signature))
    }, logical(1L))
    if (!all(verified)) .dsvert_dp_glm_grid_cross_fail()
    .dsvert_dp_canonical_query_value(value)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_multinomial_grid_cross_spec <- function(raw, policy, schema) {
  .dsvert_dp_categorical_grid_cross_spec(raw, policy, schema, "multinomial")
}
.dsvert_dp_multinomial_grid_cross_spec_validate <- function(value, policy, schema) {
  .dsvert_dp_categorical_grid_cross_spec_validate(value, policy, schema, "multinomial")
}
.dsvert_dp_multinomial_grid_cross_contract_validate <- function(
    value, policy, schema_manifest, .verifier = .dsvert_relay_verify_message) {
  .dsvert_dp_categorical_grid_cross_contract_validate(value, policy,
    schema_manifest, "multinomial", .verifier)
}
.dsvert_dp_multinomial_grid_cross_register <- function() {
  list(family = "multinomial", spec_version = "multinomial_grid_cross_v1",
    operation = "dp.multinomial-grid-cross.v1", release_enabled = FALSE,
    spec = .dsvert_dp_multinomial_grid_cross_spec,
    validate = .dsvert_dp_multinomial_grid_cross_contract_validate,
    artifact = .dsvert_dp_categorical_grid_cross_artifact,
    source_contract = .dsvert_dp_glm_grid_cross_source_contract,
    release = function(...) .dsvert_dp_glm_grid_cross_fail())
}
