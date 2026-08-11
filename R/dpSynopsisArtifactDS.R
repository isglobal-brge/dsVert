# Data-free physical plan and semantic identity for the sticky synopsis.
# This layer creates no receipts, authorization, state, seed or execution.

.DSVERT_DP_SYNOPSIS_PHYSICAL_PLAN_VERSION <-
  "dsvert-stateless-catalog-synopsis-physical-plan-v1"
.DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/draw-law/v1|"

.DSVERT_DP_SYNOPSIS_LAPLACE_DRAW_FIELDS <- c(
  "version", "sampler", "stop_bits", "stop_numerator", "uniform_bits",
  "binary_geometric_bits", "bernoulli_thresholds", "sensitivity_steps",
  "total_coordinate_count", "epsilon_effective_upper_numerator",
  "epsilon_effective_upper_denominator", "one_geometric_tv_numerator",
  "one_geometric_tv_denominator", "tail_upper_numerator",
  "tail_upper_denominator", "rounding_upper_numerator",
  "rounding_upper_denominator", "implementation_delta_numerator",
  "implementation_delta_denominator", "maximum_noise_magnitude")

.DSVERT_DP_SYNOPSIS_CONVOLUTION_DRAW_FIELDS <- c(
  .DSVERT_DP_SYNOPSIS_LAPLACE_DRAW_FIELDS,
  "independent_noise_peer_count", "complete_epsilon_per_peer",
  "epsilon_divided_by_peer_count",
  "geometric_variables_per_peer_per_coordinate",
  "geometric_variables_total_per_coordinate",
  "per_peer_implementation_delta_numerator",
  "per_peer_implementation_delta_denominator",
  "release_implementation_delta_aggregation",
  "two_peer_ideal_transfer_delta_numerator",
  "two_peer_ideal_transfer_delta_denominator")

.DSVERT_DP_SYNOPSIS_GAUSSIAN_DRAW_FIELDS <- c(
  "version", "mechanism", "sampler", "reference",
  "total_coordinate_count", "request_binding_sha256",
  "epsilon_numerator", "epsilon_denominator",
  "allocated_delta_numerator", "allocated_delta_denominator",
  "core_delta_numerator", "core_delta_denominator",
  "tail_delta_numerator", "tail_delta_denominator",
  "l2_sensitivity_numerator", "l2_sensitivity_denominator",
  "rho_numerator", "rho_denominator", "zcdp_log_upper_integer",
  "zcdp_conversion_exponent_numerator",
  "zcdp_conversion_exponent_denominator", "sigma_squared_numerator",
  "sigma_squared_denominator", "proposal_scale",
  "maximum_noise_magnitude_per_peer",
  "maximum_noise_magnitude_two_peers",
  "tail_proof_exponent_numerator", "tail_proof_exponent_denominator",
  "tail_proof_target_numerator", "tail_proof_target_denominator",
  "vector_tail_tv_upper_numerator", "vector_tail_tv_upper_denominator",
  "vector_sampler_tv_upper_numerator",
  "vector_sampler_tv_upper_denominator",
  "vector_total_tv_upper_numerator", "vector_total_tv_upper_denominator",
  "per_peer_implementation_delta_numerator",
  "per_peer_implementation_delta_denominator",
  "sampler_candidate_count", "sampler_random_bits_per_coordinate",
  "sampler_table_precision_bits", "sampler_magnitude_count",
  "independent_noise_peer_count", "complete_epsilon_per_peer",
  "epsilon_divided_by_peer_count", "release_delta_aggregation",
  "nominal_variance_multiplier", "nominal_standard_deviation_factor",
  "at_least_one_honest_noise_peer", "maximum_colluding_noise_peers",
  "exact_rational_sampler", "finite_support_transfer_charged",
  "fixed_work_sampler", "sampler_branches_on_protected_values",
  "sampler_branches_on_private_randomness", "transcript_dp_claim",
  "logical_transcript_fixed_shape")

.dsvert_dp_synopsis_artifact_hash_v1 <- function(domain, value) {
  digest::digest(
    charToRaw(paste0(
      domain, .dsvert_dp_canonical_json(
        .dsvert_dp_analysis_canonical_value_v1(value)))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_draw_fields_v1 <- function(profile) {
  if (isTRUE(profile$gaussian)) {
    .DSVERT_DP_SYNOPSIS_GAUSSIAN_DRAW_FIELDS
  } else if (isTRUE(profile$exact_gc)) {
    .DSVERT_DP_SYNOPSIS_LAPLACE_DRAW_FIELDS
  } else {
    .DSVERT_DP_SYNOPSIS_CONVOLUTION_DRAW_FIELDS
  }
}

.dsvert_dp_synopsis_draw_law_v1 <- function(plan, profile) {
  fields <- .dsvert_dp_synopsis_draw_fields_v1(profile)
  if (!is.list(plan) || is.null(names(plan)) || anyNA(names(plan)) ||
      anyDuplicated(names(plan)) || !all(fields %in% names(plan))) {
    stop("The synopsis physical plan has no complete draw law.",
         call. = FALSE)
  }
  draw_law <- plan[fields]
  if ("bernoulli_thresholds" %in% fields) {
    thresholds <- unlist(draw_law$bernoulli_thresholds, use.names = FALSE)
    if (!is.character(thresholds)) {
      stop("The synopsis physical plan has invalid Bernoulli thresholds.",
           call. = FALSE)
    }
    draw_law$bernoulli_thresholds <- as.list(unname(thresholds))
  }
  .dsvert_dp_analysis_canonical_value_v1(draw_law)
}

.dsvert_dp_synopsis_profile_v1 <- function(mechanism, backend) {
  profile <- .dsvert_joint_dp_vector_profile(mechanism, backend)
  adversary_model <- if (isTRUE(profile$exact_gc)) {
    "analyst_plus_at_most_one_exact_gc_authority_v1"
  } else {
    "analyst_plus_at_most_one_of_two_noncolluding_noise_authorities_v1"
  }
  .dsvert_dp_analysis_canonical_value_v1(list(
    version = "dsvert-stateless-catalog-synopsis-backend-profile-v1",
    mechanism = mechanism, backend = profile$backend,
    plan_version = profile$plan_version, sampler = profile$sampler,
    release_mechanism = profile$release_mechanism,
    draw_count = if (isTRUE(profile$exact_gc)) 1L else 2L,
    complete_epsilon_per_draw = TRUE,
    delta_aggregation = profile$delta_aggregation,
    adversary_model = adversary_model,
    output_transform = profile$postprocessing,
    commitment_purpose = profile$commitment_purpose))
}

.dsvert_dp_synopsis_backend_selection_v1 <- function(profile, dimension) {
  if (isTRUE(profile$gaussian)) {
    return(.dsvert_dp_analysis_canonical_value_v1(list(
      version = "dsvert-stateless-catalog-synopsis-backend-selection-v1",
      rule = "manifest_certified_fixed_work_gaussian_v1",
      total_coordinate_count = as.integer(dimension),
      backend = profile$backend,
      selected_before_private_material = TRUE,
      retry_may_change_backend = FALSE)))
  }
  choice <- .dsvert_joint_dp_vector_public_backend_choice(dimension)
  .dsvert_dp_analysis_canonical_value_v1(c(list(
    version = "dsvert-stateless-catalog-synopsis-backend-selection-v1",
    rule = "public_coordinate_ceiling_v1",
    selected_before_private_material = TRUE,
    retry_may_change_backend = FALSE), choice))
}

.dsvert_dp_synopsis_lattice_v1 <- function(
    projection, validated, lattice) {
  dimension <- as.integer(validated$layout$coordinate_count)
  if (!identical(as.numeric(projection$catalog$coordinate_count),
                 as.numeric(dimension)) ||
      !identical(projection$catalog$coordinate_order_sha256,
                 validated$layout$sha256)) {
    stop("The synopsis lattice disagrees with its catalog.", call. = FALSE)
  }
  .dsvert_dp_analysis_canonical_value_v1(list(
    version = "dsvert-stateless-catalog-synopsis-lattice-v1",
    coordinate_count = dimension,
    coordinate_order_sha256 = validated$layout$sha256,
    clipping_sha256 = projection$catalog$clipping_sha256,
    transform_sha256 = lattice$transform_sha256,
    output_lattice_bits = lattice$output_lattice_bits,
    output_lattice_scale = lattice$output_lattice_scale,
    sensitivity_norm = lattice$sensitivity_norm,
    sensitivity_steps = lattice$sensitivity_steps,
    ring_bits = 128L, fractional_bits = 0L))
}

.dsvert_dp_synopsis_plan_contract_v1 <- function(
    manifest, mechanism, dimension, lattice, profile, plan) {
  list(
    mechanism = mechanism, coordinate_count = dimension,
    sensitivity_steps = lattice$sensitivity_steps,
    chunk_coordinates = if (isTRUE(profile$exact_gc)) {
      as.integer(plan$maximum_chunk_coordinates)
    } else {
      as.integer(min(.DSVERT_JOINT_DP_VECTOR_CHUNK_COORDINATES, dimension))
    },
    profile = profile,
    manifest_sha256 = .dsvert_joint_dp_hash(manifest))
}

.dsvert_dp_synopsis_declared_decimal_v1 <- function(
    value, what, maximum, open_maximum = FALSE) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value <= 0 ||
      (isTRUE(open_maximum) && value >= maximum) ||
      (!isTRUE(open_maximum) && value > maximum)) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  formatC(as.numeric(value), digits = 18L, format = "e", decimal.mark = ".")
}

.dsvert_dp_synopsis_fraction_leq_decimal_v1 <- function(
    numerator, denominator, bound) {
  numerator <- .dsvert_dp_analysis_frequency_uint_v1(numerator)
  denominator <- .dsvert_dp_analysis_frequency_uint_v1(denominator, TRUE)
  bound <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(bound)
  numerator * bound$denominator <= denominator * bound$numerator
}

.dsvert_dp_synopsis_fraction_equal_decimal_v1 <- function(
    numerator, denominator, bound) {
  numerator <- .dsvert_dp_analysis_frequency_uint_v1(numerator)
  denominator <- .dsvert_dp_analysis_frequency_uint_v1(denominator, TRUE)
  bound <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(bound)
  identical(
    as.character(numerator * bound$denominator),
    as.character(denominator * bound$numerator))
}

.dsvert_dp_synopsis_physical_plan_v1 <- function(
    policy, manifest, .planner = NULL) {
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(policy, manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  dimension <- as.integer(validated$layout$coordinate_count)
  lattice_identity <- .dsvert_dp_synopsis_lattice_v1(
    projection, validated, lattice)
  declared_epsilon <- .dsvert_dp_synopsis_declared_decimal_v1(
    policy$global_total_epsilon, "epsilon", 8)
  declared_delta <- .dsvert_dp_synopsis_declared_decimal_v1(
    policy$global_total_delta, "delta", 1, open_maximum = TRUE)
  mechanism <- validated$manifest$workload$capsule_mechanism$mechanism
  gaussian <- identical(mechanism, .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)
  request <- if (gaussian) {
    .dsvert_dp_capsule_exact_gaussian_request(
      as.numeric(declared_epsilon), as.numeric(declared_delta),
      as.numeric(lattice$l2_sensitivity_steps), dimension)
  } else {
    list(
      epsilon = declared_epsilon, delta = declared_delta,
      sensitivity_steps = lattice$l1_sensitivity_steps,
      total_coordinate_count = dimension)
  }
  choice <- if (gaussian) NULL else
    .dsvert_joint_dp_vector_public_backend_choice(dimension)
  profile <- .dsvert_joint_dp_vector_profile(
    mechanism, if (gaussian) NULL else choice$backend)
  plan <- .dsvert_joint_dp_vector_call_planner(
    .planner, profile$plan_command, request)
  contract <- .dsvert_dp_synopsis_plan_contract_v1(
    manifest, mechanism, dimension, lattice, profile, plan)
  .dsvert_joint_dp_vector_plan_validate(plan, contract, request)
  full_plan_sha256 <- .dsvert_joint_dp_hash(plan)
  if (gaussian) {
    selection <- validated$manifest$workload$mechanism_selection
    if (!identical(
          .dsvert_dp_canonical_query_value(
            selection$gaussian_calibration_request),
          .dsvert_dp_canonical_query_value(request)) ||
        !identical(selection$gaussian_plan_sha256, full_plan_sha256)) {
      stop("The synopsis Gaussian plan is not certified by its manifest.",
           call. = FALSE)
    }
  }
  draw_law <- .dsvert_dp_synopsis_draw_law_v1(plan, profile)
  identity <- .dsvert_dp_synopsis_physical_identity_validate_v1(list(
    version = .DSVERT_DP_SYNOPSIS_PHYSICAL_PLAN_VERSION,
    request = .dsvert_dp_analysis_canonical_value_v1(request),
    profile = .dsvert_dp_synopsis_profile_v1(mechanism, profile$backend),
    lattice = lattice_identity,
    backend_selection = .dsvert_dp_synopsis_backend_selection_v1(
      profile, dimension),
    draw_law = draw_law,
    draw_law_sha256 = .dsvert_dp_synopsis_artifact_hash_v1(
      .DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN, draw_law)), projection)
  c(identity, list(
    full_plan = .dsvert_dp_analysis_canonical_value_v1(plan),
    full_plan_sha256 = full_plan_sha256))
}

.dsvert_dp_synopsis_decimal_v1 <- function(
    value, what, maximum, open_maximum = FALSE) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") > 64L ||
      !grepl("^[0-9](?:\\.[0-9]+)?e[+-][0-9]{2,3}$", value)) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  number <- suppressWarnings(as.numeric(value))
  if (!is.finite(number) || number <= 0 ||
      (isTRUE(open_maximum) && number >= maximum) ||
      (!isTRUE(open_maximum) && number > maximum)) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  canonical <- .dsvert_dp_synopsis_declared_decimal_v1(
    number, what, maximum, open_maximum = open_maximum)
  if (!identical(value, canonical)) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  canonical
}

.dsvert_dp_synopsis_uint_text_v1 <- function(
    value, positive = FALSE, maximum_bytes = 16384L) {
  is.character(value) && length(value) == 1L && !is.na(value) &&
    nchar(value, type = "bytes") <= maximum_bytes &&
    grepl("^(0|[1-9][0-9]*)$", value) &&
    (!isTRUE(positive) || !identical(value, "0"))
}

.dsvert_dp_synopsis_integer_v1 <- function(value, minimum, maximum) {
  is.numeric(value) && length(value) == 1L && !is.na(value) &&
    is.finite(value) && value == floor(value) &&
    value >= minimum && value <= maximum
}

.dsvert_dp_synopsis_fraction_reduced_v1 <- function(
    numerator, denominator) {
  if (!.dsvert_dp_synopsis_uint_text_v1(numerator) ||
      !.dsvert_dp_synopsis_uint_text_v1(denominator, TRUE)) return(FALSE)
  left <- openssl::bignum(numerator)
  right <- openssl::bignum(denominator)
  while (!identical(as.character(right), "0")) {
    remainder <- left %% right
    left <- right
    right <- remainder
  }
  identical(as.character(left), "1")
}

.dsvert_dp_synopsis_draw_law_validate_v1 <- function(
    draw_law, profile, request) {
  fields <- .dsvert_dp_synopsis_draw_fields_v1(profile)
  if (!is.list(draw_law) || is.null(names(draw_law)) ||
      !setequal(names(draw_law), fields)) {
    stop("Invalid synopsis draw law.", call. = FALSE)
  }
  if (isTRUE(profile$gaussian)) {
    integer_fields <- grep(
      "(_numerator|_denominator)$", names(draw_law), value = TRUE)
    integer_fields <- c(integer_fields, "zcdp_log_upper_integer",
                        "proposal_scale", "maximum_noise_magnitude_per_peer",
                        "maximum_noise_magnitude_two_peers")
    denominators <- grep("_denominator$", integer_fields, value = TRUE)
    fraction_prefixes <- sub(
      "_numerator$", "", grep("_numerator$", names(draw_law), value = TRUE))
    fraction_prefixes <- fraction_prefixes[
      paste0(fraction_prefixes, "_denominator") %in% names(draw_law)]
    integers_valid <- all(vapply(integer_fields, function(field) {
      .dsvert_dp_synopsis_uint_text_v1(
        draw_law[[field]], field %in% denominators)
    }, logical(1L))) && all(vapply(fraction_prefixes, function(prefix) {
      .dsvert_dp_synopsis_fraction_reduced_v1(
        draw_law[[paste0(prefix, "_numerator")]],
        draw_law[[paste0(prefix, "_denominator")]])
    }, logical(1L)))
    fixed_valid <-
      .dsvert_dp_synopsis_integer_v1(
        draw_law$independent_noise_peer_count, 2, 2) &&
      identical(draw_law$complete_epsilon_per_peer, TRUE) &&
      identical(draw_law$epsilon_divided_by_peer_count, FALSE) &&
      identical(draw_law$release_delta_aggregation,
                profile$delta_aggregation) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$nominal_variance_multiplier, 2, 2) &&
      identical(draw_law$nominal_standard_deviation_factor,
                "sqrt(2)_relative_to_one_full_draw") &&
      identical(draw_law$at_least_one_honest_noise_peer, TRUE) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$maximum_colluding_noise_peers, 1, 1) &&
      identical(draw_law$exact_rational_sampler, FALSE) &&
      identical(draw_law$finite_support_transfer_charged, TRUE) &&
      identical(draw_law$fixed_work_sampler, TRUE) &&
      identical(draw_law$sampler_branches_on_protected_values, FALSE) &&
      identical(draw_law$sampler_branches_on_private_randomness, FALSE) &&
      identical(draw_law$transcript_dp_claim, TRUE) &&
      identical(draw_law$logical_transcript_fixed_shape, TRUE) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$sampler_candidate_count, 1, 1) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$sampler_random_bits_per_coordinate, 128, 16384) &&
      draw_law$sampler_random_bits_per_coordinate %% 8 == 0 &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$sampler_table_precision_bits, 128, 16474) &&
      draw_law$sampler_table_precision_bits >=
        draw_law$sampler_random_bits_per_coordinate &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$sampler_magnitude_count, 1, 2^20 + 1) &&
      .dsvert_dp_synopsis_fraction_equal_decimal_v1(
        draw_law$epsilon_numerator, draw_law$epsilon_denominator,
        request$epsilon) &&
      .dsvert_dp_synopsis_fraction_equal_decimal_v1(
        draw_law$allocated_delta_numerator,
        draw_law$allocated_delta_denominator, request$delta) &&
      .dsvert_dp_synopsis_fraction_equal_decimal_v1(
        draw_law$l2_sensitivity_numerator,
        draw_law$l2_sensitivity_denominator,
        request$l2_sensitivity_steps)
    if (!isTRUE(integers_valid) || !isTRUE(fixed_valid)) {
      stop("Invalid synopsis Gaussian draw law.", call. = FALSE)
    }
    return(.dsvert_dp_analysis_canonical_value_v1(draw_law))
  }

  integer_fields <- setdiff(
    .DSVERT_DP_SYNOPSIS_LAPLACE_DRAW_FIELDS,
    c("version", "sampler", "stop_bits", "uniform_bits",
      "binary_geometric_bits", "bernoulli_thresholds",
      "total_coordinate_count"))
  denominators <- grep("_denominator$", integer_fields, value = TRUE)
  fraction_prefixes <- sub(
    "_numerator$", "", grep("_numerator$", names(draw_law), value = TRUE))
  fraction_prefixes <- fraction_prefixes[
    paste0(fraction_prefixes, "_denominator") %in% names(draw_law)]
  thresholds <- unlist(draw_law$bernoulli_thresholds, use.names = FALSE)
  valid <- all(vapply(integer_fields, function(field) {
    .dsvert_dp_synopsis_uint_text_v1(
      draw_law[[field]], field %in% denominators, 512L)
  }, logical(1L))) && all(vapply(fraction_prefixes, function(prefix) {
    .dsvert_dp_synopsis_fraction_reduced_v1(
      draw_law[[paste0(prefix, "_numerator")]],
      draw_law[[paste0(prefix, "_denominator")]])
  }, logical(1L))) &&
    .dsvert_dp_synopsis_integer_v1(draw_law$stop_bits, 128, 128) &&
    .dsvert_dp_synopsis_integer_v1(draw_law$uniform_bits, 128, 256) &&
    draw_law$uniform_bits %in% c(128, 256) &&
    .dsvert_dp_synopsis_integer_v1(
      draw_law$binary_geometric_bits, 1, 63) &&
    is.character(thresholds) &&
    length(thresholds) == as.numeric(draw_law$binary_geometric_bits) &&
    all(vapply(thresholds, .dsvert_dp_synopsis_uint_text_v1, logical(1L))) &&
    isTRUE(tryCatch(
      .dsvert_dp_synopsis_fraction_leq_decimal_v1(
        draw_law$epsilon_effective_upper_numerator,
        draw_law$epsilon_effective_upper_denominator, request$epsilon),
      error = function(error) FALSE)) &&
    isTRUE(tryCatch(
      .dsvert_dp_synopsis_fraction_leq_decimal_v1(
        draw_law$implementation_delta_numerator,
        draw_law$implementation_delta_denominator, request$delta),
      error = function(error) FALSE))
  if (!isTRUE(profile$exact_gc)) {
    valid <- valid &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$independent_noise_peer_count, 2, 2) &&
      identical(draw_law$complete_epsilon_per_peer, TRUE) &&
      identical(draw_law$epsilon_divided_by_peer_count, FALSE) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$geometric_variables_per_peer_per_coordinate, 2, 2) &&
      .dsvert_dp_synopsis_integer_v1(
        draw_law$geometric_variables_total_per_coordinate, 4, 4) &&
      identical(draw_law$implementation_delta_numerator,
                draw_law$per_peer_implementation_delta_numerator) &&
      identical(draw_law$implementation_delta_denominator,
                draw_law$per_peer_implementation_delta_denominator) &&
      identical(draw_law$release_implementation_delta_aggregation,
                profile$delta_aggregation)
  }
  if (!isTRUE(valid)) {
    stop("Invalid synopsis Laplace calibration or draw law.", call. = FALSE)
  }
  .dsvert_dp_analysis_canonical_value_v1(draw_law)
}

.dsvert_dp_synopsis_physical_identity_validate_v1 <- function(
    value, projection) {
  value <- .dsvert_dp_analysis_canonical_value_v1(value)
  fields <- c(
    "version", "request", "profile", "lattice", "backend_selection",
    "draw_law", "draw_law_sha256")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_SYNOPSIS_PHYSICAL_PLAN_VERSION)) {
    stop("Invalid synopsis physical identity.", call. = FALSE)
  }
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(
    projection)
  lattice <- value$lattice
  catalog_lattice <- projection$catalog$release_lattice
  catalog_sensitivity <- projection$catalog$sensitivity
  lattice_fields <- c(
    "version", "coordinate_count", "coordinate_order_sha256",
    "clipping_sha256", "transform_sha256", "output_lattice_bits",
    "output_lattice_scale", "sensitivity_norm", "sensitivity_steps",
    "ring_bits", "fractional_bits")
  dimension <- tryCatch(.dsvert_dp_analysis_positive_integer(
    lattice$coordinate_count, "synopsis coordinate count"),
    error = function(error) NA_real_)
  catalog_lattice_fields <- c(
    "version", "transform_rule", "output_lattice_bits",
    "output_lattice_scale", "natural_l1_sensitivity",
    "integer_l1_sensitivity_steps", "natural_l2_sensitivity",
    "integer_l2_sensitivity_steps")
  catalog_lattice_valid <- is.list(catalog_lattice) &&
    !is.null(names(catalog_lattice)) &&
    setequal(names(catalog_lattice), catalog_lattice_fields) &&
    identical(catalog_lattice$version,
              "biomedical-capsule-common-lattice-v1") &&
    is.numeric(catalog_lattice$output_lattice_bits) &&
    length(catalog_lattice$output_lattice_bits) == 1L &&
    is.finite(catalog_lattice$output_lattice_bits) &&
    catalog_lattice$output_lattice_bits >= 1 &&
    catalog_lattice$output_lattice_bits <= 62 &&
    catalog_lattice$output_lattice_bits ==
      floor(catalog_lattice$output_lattice_bits) &&
    identical(as.numeric(catalog_lattice$output_lattice_scale),
              2^as.numeric(catalog_lattice$output_lattice_bits)) &&
    is.list(catalog_sensitivity) &&
    identical(as.numeric(catalog_sensitivity$l1),
              as.numeric(catalog_lattice$integer_l1_sensitivity_steps)) &&
    identical(as.numeric(catalog_sensitivity$l2),
              as.numeric(catalog_lattice$integer_l2_sensitivity_steps))
  selected_catalog_steps <- if (identical(lattice$sensitivity_norm, "l2")) {
    format(as.numeric(catalog_lattice$integer_l2_sensitivity_steps),
           scientific = TRUE, trim = TRUE, digits = 17L)
  } else {
    format(as.numeric(catalog_lattice$integer_l1_sensitivity_steps),
           scientific = FALSE, trim = TRUE, digits = 22L)
  }
  lattice_valid <- is.list(lattice) && !is.null(names(lattice)) &&
    isTRUE(catalog_lattice_valid) &&
    setequal(names(lattice), lattice_fields) &&
    identical(lattice$version,
              "dsvert-stateless-catalog-synopsis-lattice-v1") &&
    is.finite(dimension) &&
    identical(as.numeric(dimension),
              as.numeric(projection$catalog$coordinate_count)) &&
    identical(lattice$coordinate_order_sha256,
              projection$catalog$coordinate_order_sha256) &&
    identical(lattice$clipping_sha256,
              projection$catalog$clipping_sha256) &&
    .dsvert_dp_synopsis_integer_v1(
      lattice$output_lattice_bits, 1, 62) &&
    .dsvert_dp_synopsis_integer_v1(
      lattice$output_lattice_scale, 2, 2^62) &&
    identical(as.numeric(lattice$output_lattice_bits),
              as.numeric(catalog_lattice$output_lattice_bits)) &&
    identical(as.numeric(lattice$output_lattice_scale),
              as.numeric(catalog_lattice$output_lattice_scale)) &&
    .dsvert_dp_synopsis_integer_v1(lattice$ring_bits, 128, 128) &&
    .dsvert_dp_synopsis_integer_v1(lattice$fractional_bits, 0, 0) &&
    lattice$sensitivity_norm %in% c("l1", "l2") &&
    is.character(lattice$sensitivity_steps) &&
    length(lattice$sensitivity_steps) == 1L &&
    identical(lattice$sensitivity_steps, selected_catalog_steps) &&
    .dsvert_dp_analysis_frequency_hex_v1(lattice$transform_sha256)
  if (!isTRUE(lattice_valid)) {
    stop("Invalid synopsis lattice identity.", call. = FALSE)
  }
  profile <- value$profile
  if (!is.list(profile) || is.null(names(profile)) ||
      !all(c("mechanism", "backend") %in% names(profile))) {
    stop("Invalid synopsis backend profile.", call. = FALSE)
  }
  expected_raw <- .dsvert_joint_dp_vector_profile(
    profile$mechanism, profile$backend)
  expected_norm <- if (isTRUE(expected_raw$gaussian)) "l2" else "l1"
  if (!identical(lattice$sensitivity_norm, expected_norm)) {
    stop("Invalid synopsis lattice identity.", call. = FALSE)
  }
  if (!identical(profile, .dsvert_dp_synopsis_profile_v1(
      profile$mechanism, profile$backend)) ||
      !identical(value$backend_selection,
        .dsvert_dp_synopsis_backend_selection_v1(expected_raw, dimension))) {
    stop("Invalid synopsis backend selection.", call. = FALSE)
  }
  request <- value$request
  expected_request_fields <- if (isTRUE(expected_raw$gaussian)) {
    c("epsilon", "delta", "l2_sensitivity_steps",
      "total_coordinate_count")
  } else {
    c("epsilon", "delta", "sensitivity_steps", "total_coordinate_count")
  }
  if (!is.list(request) || is.null(names(request)) ||
      !setequal(names(request), expected_request_fields) ||
      !.dsvert_dp_synopsis_integer_v1(
        request$total_coordinate_count, 1, .DSVERT_DP_MAX_COORDINATES) ||
      !identical(as.numeric(request$total_coordinate_count), dimension) ||
      (!isTRUE(expected_raw$gaussian) &&
       !identical(request$sensitivity_steps, lattice$sensitivity_steps))) {
    stop("Invalid synopsis planner request.", call. = FALSE)
  }
  expected_draw_fields <- .dsvert_dp_synopsis_draw_fields_v1(expected_raw)
  if (!is.list(value$draw_law) || is.null(names(value$draw_law)) ||
      !setequal(names(value$draw_law), expected_draw_fields)) {
    stop("Invalid synopsis draw law.", call. = FALSE)
  }
  draw_law <- .dsvert_dp_synopsis_draw_law_validate_v1(
    .dsvert_dp_synopsis_draw_law_v1(value$draw_law, expected_raw),
    expected_raw, request)
  if (!setequal(names(draw_law), expected_draw_fields) ||
      !identical(draw_law$version, profile$plan_version) ||
      !identical(draw_law$sampler, profile$sampler) ||
      !.dsvert_dp_synopsis_integer_v1(
        draw_law$total_coordinate_count, 1, .DSVERT_DP_MAX_COORDINATES) ||
      !identical(as.numeric(draw_law$total_coordinate_count), dimension) ||
      (!isTRUE(expected_raw$gaussian) &&
       !identical(draw_law$sensitivity_steps,
                  lattice$sensitivity_steps)) ||
      !identical(value$draw_law_sha256,
        .dsvert_dp_synopsis_artifact_hash_v1(
          .DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN, draw_law))) {
    stop("Invalid synopsis draw law.", call. = FALSE)
  }
  if (isTRUE(expected_raw$gaussian) && !identical(
      draw_law$request_binding_sha256,
      .dsvert_dp_capsule_exact_gaussian_request_binding(
        draw_law, request))) {
    stop("Invalid synopsis Gaussian request binding.", call. = FALSE)
  }
  value$draw_law <- draw_law
  value
}

.dsvert_dp_analysis_synopsis_semantic_validate_v1 <- function(value) {
  value <- .dsvert_dp_canonical_query_value(value)
  fields <- c(
    "version", "catalog_projection", "source_claim_set_sha256",
    "noise_authority_roles", "privacy", "release", "public_shape")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_DP_ANALYSIS_SYNOPSIS_SEMANTIC_VERSION)) {
    stop("Invalid synopsis semantic contract.", call. = FALSE)
  }
  .dsvert_dp_analysis_reject_operational_fields(value)
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(
    value$catalog_projection)
  claim_set_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$source_claim_set_sha256, "source Claim-set hash")
  roles <- value$noise_authority_roles
  role_ids <- tryCatch(vapply(
    roles$authority_ids, .dsvert_dp_analysis_identity_pk, character(1L),
    what = "synopsis noise authority"),
    error = function(error) character())
  if (!is.list(roles) || is.null(names(roles)) ||
      !setequal(names(roles), c("version", "role_order", "authority_ids")) ||
      !identical(roles$version,
                 "dsvert-synopsis-noise-authority-roles-v1") ||
      !identical(roles$role_order, list(
        "primary_noise_authority", "secondary_noise_authority")) ||
      !is.list(roles$authority_ids) || !is.null(names(roles$authority_ids)) ||
      length(role_ids) != 2L || anyDuplicated(role_ids)) {
    stop("Invalid synopsis noise-authority roles.", call. = FALSE)
  }
  roles$authority_ids <- as.list(unname(role_ids))
  release <- .dsvert_dp_synopsis_physical_identity_validate_v1(
    value$release, projection)
  privacy <- value$privacy
  mechanism <- if (is.list(privacy)) privacy$mechanism else NULL
  randomness <- if (is.list(mechanism)) mechanism$randomness else NULL
  lane <- if (is.list(randomness) && is.list(randomness$lanes)) {
    randomness$lanes$final_noise
  } else NULL
  profile <- release$profile
  family <- if (identical(profile$mechanism,
                          .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)) {
    "gaussian"
  } else {
    "discrete_laplace"
  }
  sensitivity_steps <- if (identical(family, "gaussian")) {
    release$request$l2_sensitivity_steps
  } else {
    release$lattice$sensitivity_steps
  }
  privacy_valid <- is.list(privacy) && !is.null(names(privacy)) &&
    setequal(names(privacy), c(
      "version", "adjacency", "privacy_unit", "epsilon", "delta",
      "mechanism")) &&
    identical(privacy$version, "dsvert-per-synopsis-dp-v1") &&
    identical(privacy$privacy_unit, "patient") &&
    identical(privacy$adjacency, projection$catalog$admission$adjacency) &&
    identical(.dsvert_dp_synopsis_decimal_v1(
      privacy$epsilon, "epsilon", 8), privacy$epsilon) &&
    identical(.dsvert_dp_synopsis_decimal_v1(
      privacy$delta, "delta", 1, open_maximum = TRUE), privacy$delta) &&
    is.list(mechanism) && !is.null(names(mechanism)) &&
    setequal(names(mechanism), c(
      "version", "family", "sensitivity", "randomness")) &&
    identical(mechanism$version, profile$release_mechanism) &&
    identical(mechanism$family, family) &&
    identical(mechanism$sensitivity, .dsvert_dp_canonical_query_value(list(
      version = "dsvert-sensitivity-v1",
      norm = release$lattice$sensitivity_norm,
      steps = sensitivity_steps))) &&
    is.list(randomness) && !is.null(names(randomness)) &&
    setequal(names(randomness), c("version", "lanes")) &&
    identical(randomness$version, "dsvert-randomness-plan-v1") &&
    identical(names(randomness$lanes), "final_noise") &&
    identical(lane, .dsvert_dp_canonical_query_value(list(
      version = "dsvert-randomness-lane-v1",
      purpose = "privatize_final_vector",
      primitive = profile$sampler,
      coordinates = release$lattice$coordinate_count)))
  if (!isTRUE(privacy_valid)) {
    stop("Invalid synopsis privacy contract.", call. = FALSE)
  }
  expected_request <- if (identical(family, "gaussian")) {
    .dsvert_dp_capsule_exact_gaussian_request(
      as.numeric(privacy$epsilon), as.numeric(privacy$delta),
      as.numeric(release$lattice$sensitivity_steps),
      release$lattice$coordinate_count)
  } else {
    list(
      epsilon = privacy$epsilon, delta = privacy$delta,
      sensitivity_steps = release$lattice$sensitivity_steps,
      total_coordinate_count = release$lattice$coordinate_count)
  }
  if (!identical(
      release$request,
      .dsvert_dp_analysis_canonical_value_v1(expected_request))) {
    stop("The synopsis privacy contract disagrees with its planner request.",
         call. = FALSE)
  }
  if (!identical(value$public_shape, .dsvert_dp_canonical_query_value(list(
      version = "dsvert-stateless-catalog-synopsis-shape-v1",
      coordinates = release$lattice$coordinate_count)))) {
    stop("Invalid synopsis public shape.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_ANALYSIS_SYNOPSIS_SEMANTIC_VERSION,
    catalog_projection = projection,
    source_claim_set_sha256 = claim_set_sha256,
    noise_authority_roles = roles, privacy = privacy,
    release = release, public_shape = value$public_shape))
}

.dsvert_dp_synopsis_authority_roles_v1 <- function(policy, manifest) {
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  contract <- .dsvert_dp_capsule_source_contract(policy, manifest)
  peers <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "synopsis noise authorities")
  if (length(peers) != 2L || anyDuplicated(peers) ||
      !identical(peers, sort(peers, method = "radix")) ||
      !all(peers %in% names(pins))) {
    stop("The synopsis noise-authority assignment is invalid.",
         call. = FALSE)
  }
  list(
    version = "dsvert-synopsis-noise-authority-roles-v1",
    role_order = list(
      "primary_noise_authority", "secondary_noise_authority"),
    authority_ids = as.list(unname(pins[peers])))
}

.dsvert_dp_synopsis_artifact_v1 <- function(
    policy, manifest, claim_set, .planner = NULL,
    .verifier = .dsvert_relay_verify_message) {
  claim_set <- .dsvert_dp_synopsis_source_claim_set_validate_v1(
    claim_set, policy, manifest, .verifier = .verifier)
  physical_plan <- .dsvert_dp_synopsis_physical_plan_v1(
    policy, manifest, .planner = .planner)
  release <- physical_plan[c(
    "version", "request", "profile", "lattice", "backend_selection",
    "draw_law", "draw_law_sha256")]
  profile <- physical_plan$profile
  semantic <- .dsvert_dp_analysis_synopsis_semantic_validate_v1(list(
    version = .DSVERT_DP_ANALYSIS_SYNOPSIS_SEMANTIC_VERSION,
    catalog_projection = claim_set$projection,
    source_claim_set_sha256 = claim_set$sha256,
    noise_authority_roles = .dsvert_dp_synopsis_authority_roles_v1(
      policy, manifest),
    privacy = list(
      version = "dsvert-per-synopsis-dp-v1",
      adjacency = claim_set$projection$catalog$admission$adjacency,
      privacy_unit = "patient",
      epsilon = .dsvert_dp_synopsis_declared_decimal_v1(
        policy$global_total_epsilon, "epsilon", 8),
      delta = .dsvert_dp_synopsis_declared_decimal_v1(
        policy$global_total_delta, "delta", 1, open_maximum = TRUE),
      mechanism = list(
        version = profile$release_mechanism,
        family = if (identical(
          profile$mechanism, .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)) {
          "gaussian"
        } else {
          "discrete_laplace"
        },
        sensitivity = list(
          version = "dsvert-sensitivity-v1",
          norm = physical_plan$lattice$sensitivity_norm,
          steps = if (identical(
            profile$mechanism, .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)) {
            physical_plan$request$l2_sensitivity_steps
          } else {
            physical_plan$lattice$sensitivity_steps
          }),
        randomness = list(
          version = "dsvert-randomness-plan-v1",
          lanes = list(final_noise = list(
            version = "dsvert-randomness-lane-v1",
            purpose = "privatize_final_vector",
            primitive = profile$sampler,
            coordinates = physical_plan$lattice$coordinate_count))))),
    release = release,
    public_shape = list(
      version = "dsvert-stateless-catalog-synopsis-shape-v1",
      coordinates = physical_plan$lattice$coordinate_count)))
  list(
    semantic = semantic,
    artifact_key = .dsvert_dp_analysis_artifact_key_v1(semantic),
    physical_plan = physical_plan)
}
