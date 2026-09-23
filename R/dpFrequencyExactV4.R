# Frequency selector generation 2: exact modular Laplace and optional Gaussian.
# Generation 1 readers remain in dpAnalysisContract.R for historical artifacts.
.dsvert_dp_analysis_frequency_plan_fields_v1 <- function() list(
    convolution = c(
      "version", "sampler", "stop_bits", "stop_numerator", "uniform_bits",
      "binary_geometric_bits", "bernoulli_thresholds", "sensitivity_steps",
      "total_coordinate_count", "epsilon_effective_upper_numerator",
      "epsilon_effective_upper_denominator", "one_geometric_tv_numerator",
      "one_geometric_tv_denominator", "tail_upper_numerator",
      "tail_upper_denominator", "rounding_upper_numerator",
      "rounding_upper_denominator", "implementation_delta_numerator",
      "implementation_delta_denominator", "implementation_delta_bound",
      "maximum_noise_magnitude", "maximum_chunk_coordinates",
      "private_stream_bytes_per_coordinate", "accounting",
      "capability_available", "independent_noise_peer_count",
      "complete_epsilon_per_peer", "epsilon_divided_by_peer_count",
      "geometric_variables_per_peer_per_coordinate",
      "geometric_variables_total_per_coordinate",
      "per_peer_implementation_delta_numerator",
      "per_peer_implementation_delta_denominator",
      "per_peer_implementation_delta_bound",
      "release_implementation_delta_aggregation",
      "two_peer_ideal_transfer_delta_numerator",
      "two_peer_ideal_transfer_delta_denominator",
      "two_peer_ideal_transfer_delta_bound", "threat_model",
      "privacy_argument"),
    gaussian = c(
      "version", "mechanism", "sampler", "reference",
      "total_coordinate_count", "maximum_chunk_coordinates",
      "request_binding_sha256", "epsilon_numerator", "epsilon_denominator",
      "allocated_delta_numerator", "allocated_delta_denominator",
      "core_delta_numerator", "core_delta_denominator",
      "tail_delta_numerator", "tail_delta_denominator",
      "l2_sensitivity_numerator", "l2_sensitivity_denominator",
      "rho_numerator", "rho_denominator", "zcdp_log_upper_integer",
      "zcdp_conversion_exponent_numerator",
      "zcdp_conversion_exponent_denominator", "sigma_squared_numerator",
      "sigma_squared_denominator", "proposal_scale",
      "maximum_noise_magnitude_per_peer",
      "maximum_noise_magnitude_two_peers", "tail_proof_exponent_numerator",
      "tail_proof_exponent_denominator", "tail_proof_target_numerator",
      "tail_proof_target_denominator", "vector_tail_tv_upper_numerator",
      "vector_tail_tv_upper_denominator",
      "vector_sampler_tv_upper_numerator",
      "vector_sampler_tv_upper_denominator",
      "vector_total_tv_upper_numerator",
      "vector_total_tv_upper_denominator",
      "per_peer_implementation_delta_numerator",
      "per_peer_implementation_delta_denominator", "simultaneous_95_abs",
      "sampler_candidate_count", "sampler_random_bits_per_coordinate",
      "sampler_random_bytes_per_coordinate", "sampler_table_precision_bits",
      "sampler_magnitude_count", "sampler_search_steps",
      "sampler_full_scan_steps", "sampler_cdf_table_bytes",
      "accuracy_accounting", "accounting", "privacy_theorem",
      "independent_noise_peer_count", "complete_epsilon_per_peer",
      "epsilon_divided_by_peer_count", "release_delta_aggregation",
      "nominal_variance_multiplier", "nominal_standard_deviation_factor",
      "at_least_one_honest_noise_peer", "maximum_colluding_noise_peers",
      "adversary_view", "adversary_view_privacy_argument",
      "source_share_hiding_precondition", "exact_rational_sampler",
      "finite_support_transfer_charged", "fixed_work_sampler",
      "sampler_branches_on_protected_values",
      "sampler_branches_on_private_randomness", "host_constant_time_claim",
      "transcript_dp_claim", "logical_transcript_fixed_shape",
      "physical_timing_dp_claim", "observable_worker_shape",
      "capability_available", "unavailable_reason"))

.dsvert_dp_analysis_frequency_primitives_v3 <- function() list(
  convolution = "independent_full_global_draw_convolution_ring128_v4",
  gaussian = "independent_full_global_dyadic_discrete_gaussian_tv_bounded_ring128_v2")

.dsvert_dp_analysis_frequency_candidate_requests_v3 <- function(
    privacy, calibration, dimension) {
  values <- .dsvert_dp_analysis_frequency_candidate_requests_v2(
    privacy, calibration, dimension)
  .dsvert_joint_dp_pure_request(values$convolution)
  values
}

.dsvert_dp_analysis_frequency_policy_sha256_v3 <- function() {
  .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/backend-selection-policy/v3|", list(
      version = "dsvert-frequency-backend-selection-policy-v3",
      oracle_policy = "minimum_certified_simultaneous_95_abs_convolution_tie_v2",
      candidate_primitives = unname(.dsvert_dp_analysis_frequency_primitives_v3()),
      objective = "minimum_certified_simultaneous_95_abs",
      accuracy_event = "max_j_abs_error_gt_radius",
      tie_break = "convolution_laplace_v4_on_equal_certified_radius",
      input_scope = "public_adjacency_planner_requests_and_coordinate_upper_bound_only",
      source_material_consulted = FALSE, private_randomness_consulted = FALSE,
      runtime_failure_consulted = FALSE, automatic_fallback = FALSE,
      utility_optimality_claimed = FALSE))
}

.dsvert_dp_analysis_frequency_exact_radius_v4 <- function(request, bound) {
  rate <- .dsvert_joint_dp_pure_request(request)
  k <- 0L
  power <- 1
  while (power < 80 * rate$dimension) {
    k <- k + 1L
    power <- power * 10
  }
  numerator <- 3 * k * rate$denominator
  threshold <- (numerator + rate$numerator - 1) %/% rate$numerator
  upper <- openssl::bignum(format(bound, scientific = FALSE, trim = TRUE))
  radius <- 2 * threshold
  if (radius >= upper || upper + radius > (openssl::bignum(2)^127) - 1)
    radius <- upper
  as.character(radius)
}

.dsvert_dp_analysis_frequency_accuracy_validate_v3 <- function(
    certificate, plan, primitive, request, bound) {
  fail <- function() stop("Invalid Frequency accuracy certificate.", call. = FALSE)
  profile <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  fields <- c("primitive", "plan_sha256", "event", "method",
    "release_tv_upper_numerator", "release_tv_upper_denominator",
    "simultaneous_95_abs", "absolute_support")
  plan_fields <- .dsvert_dp_analysis_frequency_plan_fields_v1()[[
    if (isTRUE(profile$gaussian)) "gaussian" else "convolution"]]
  if (isTRUE(profile$exact)) plan_fields <- c(plan_fields, .DSVERT_JOINT_DP_PURE_CERTIFICATE_FIELDS)
  if (is.null(profile) || !.dsvert_dp_analysis_frequency_object_v1(plan, plan_fields) ||
      anyDuplicated(names(plan)) || !.dsvert_dp_analysis_frequency_object_v1(
      certificate, fields, list(primitive = primitive,
        event = "max_j_abs_error_gt_radius",
        plan_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
          .DSVERT_DP_ANALYSIS_FREQUENCY_PLAN_DOMAIN_V1, plan))) ||
      !identical(plan$version, profile$plan) ||
      !identical(plan$sampler, profile$sampler) ||
      !identical(as.numeric(plan$total_coordinate_count),
                 as.numeric(request$total_coordinate_count)) ||
      !identical(as.numeric(plan$maximum_chunk_coordinates),
                 min(profile$max_chunk_coordinates, request$total_coordinate_count)) ||
      !identical(plan$capability_available, TRUE) ||
      !identical(as.numeric(plan$independent_noise_peer_count), 2) ||
      !identical(plan$complete_epsilon_per_peer, TRUE) ||
      !identical(plan$epsilon_divided_by_peer_count, FALSE)) fail()
  if (isTRUE(profile$exact)) {
    .dsvert_joint_dp_pure_plan_validate(plan, request)
    if (!identical(certificate$method,
        "exact_two_draw_exponential_union_modular_clamp_v1") ||
        !identical(certificate$release_tv_upper_numerator, "0") ||
        !identical(certificate$release_tv_upper_denominator, "1") ||
        !identical(certificate$absolute_support,
          format(bound, scientific = FALSE, trim = TRUE)) ||
        !identical(certificate$simultaneous_95_abs,
          .dsvert_dp_analysis_frequency_exact_radius_v4(request, bound))) fail()
  } else {
    peer <- .dsvert_dp_analysis_frequency_uint_v1(
      plan$maximum_noise_magnitude_per_peer, TRUE)
    support <- .dsvert_dp_analysis_frequency_uint_v1(
      plan$maximum_noise_magnitude_two_peers, TRUE)
    tv <- .dsvert_dp_analysis_frequency_fraction_v1(list(
      numerator = plan$vector_total_tv_upper_numerator,
      denominator = plan$vector_total_tv_upper_denominator), TRUE)
    released_tv <- .dsvert_dp_analysis_frequency_reduce_v2(
      2 * tv$numerator, tv$denominator)
    sensitivity <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(
      request$l2_sensitivity_steps)
    if (!identical(plan$mechanism, "dyadic_discrete_gaussian_truncated_tv_bounded") ||
        !identical(plan$release_delta_aggregation, "max_per_peer_not_sum") ||
        !identical(plan$l2_sensitivity_numerator, as.character(sensitivity$numerator)) ||
        !identical(plan$l2_sensitivity_denominator, as.character(sensitivity$denominator)) ||
        !isTRUE(support == 2 * peer) || !isTRUE(40 * tv$numerator < tv$denominator) ||
        !identical(certificate$method, "gaussian_plan_v2_subgaussian_mgf_tv_transfer") ||
        !identical(certificate$release_tv_upper_numerator, released_tv$numerator) ||
        !identical(certificate$release_tv_upper_denominator, released_tv$denominator) ||
        !identical(certificate$absolute_support, as.character(support)) ||
        !identical(certificate$simultaneous_95_abs, plan$simultaneous_95_abs)) fail()
  }
  radius <- .dsvert_dp_analysis_frequency_uint_v1(certificate$simultaneous_95_abs)
  support <- .dsvert_dp_analysis_frequency_uint_v1(certificate$absolute_support, TRUE)
  if (radius > support || (!isTRUE(profile$exact) &&
      openssl::bignum(format(bound, scientific = FALSE, trim = TRUE)) + support >
        (openssl::bignum(2)^127) - 1)) fail()
  invisible(TRUE)
}

.dsvert_dp_analysis_frequency_selection_certificate_v3 <- function(
    primitive, plan_hash, radius) list(
  version = "dsvert-joint-dp-frequency-backend-selection-certificate-v2",
  policy = "minimum_certified_simultaneous_95_abs_convolution_tie_v2",
  objective = "minimum_certified_simultaneous_95_abs",
  selected_primitive = primitive, selected_plan_sha256 = plan_hash,
  selected_simultaneous_95_abs = radius,
  tie_break = "convolution_laplace_v4_on_equal_certified_radius",
  input_scope = "public_adjacency_planner_requests_and_coordinate_upper_bound_only",
  source_material_consulted = FALSE, private_randomness_consulted = FALSE,
  runtime_failure_consulted = FALSE, automatic_fallback = FALSE,
  utility_optimality_claimed = FALSE)

.dsvert_dp_analysis_frequency_backend_selection_v3 <- function(
    privacy, calibration, dimension, coordinate_upper_bound, .selector = NULL) {
  fail <- function() stop("Invalid Frequency backend selector output", call. = FALSE)
  requests <- .dsvert_dp_analysis_frequency_candidate_requests_v3(
    privacy, calibration, dimension)
  request <- list(version = "dsvert-joint-dp-frequency-backend-selection-request-v2",
    adjacency = privacy$adjacency,
    coordinate_upper_bound = format(coordinate_upper_bound, scientific = FALSE,
                                   trim = TRUE, digits = 22L),
    convolution_request = requests$convolution, gaussian_request = requests$gaussian)
  if (is.null(.selector)) .selector <- function(value) {
    .callMpcTool("joint-dp-frequency-backend-select-v2", value, simplify_output = FALSE)
  }
  output <- .selector(request)
  unavailable <- is.null(output$gaussian_plan)
  fields <- c("version", "request", "convolution_plan", "gaussian_plan",
    "convolution_certificate", "gaussian_certificate", "selection_certificate",
    if (unavailable) "gaussian_unavailable_reason")
  if (!.dsvert_dp_analysis_frequency_object_v1(output, fields,
      list(version = "dsvert-joint-dp-frequency-backend-selection-v2")) ||
      !identical(output$request, request) ||
      (unavailable && (!is.null(output$gaussian_certificate) ||
        !is.character(output$gaussian_unavailable_reason) ||
        length(output$gaussian_unavailable_reason) != 1L ||
        is.na(output$gaussian_unavailable_reason) ||
        !nzchar(output$gaussian_unavailable_reason)))) fail()
  primitives <- .dsvert_dp_analysis_frequency_primitives_v3()
  candidates <- list()
  for (kind in names(primitives)) {
    profile <- .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]])
    request_hash <- .dsvert_dp_analysis_frequency_hash_v1(
      profile$request_domain, requests[[kind]])
    if (kind == "gaussian" && unavailable) {
      candidates[[kind]] <- list(available = FALSE,
        planner_request_sha256 = request_hash,
        unavailable_reason = output$gaussian_unavailable_reason)
      next
    }
    plan <- output[[paste0(kind, "_plan")]]
    certificate <- output[[paste0(kind, "_certificate")]]
    .dsvert_dp_analysis_frequency_accuracy_validate_v3(
      certificate, plan, primitives[[kind]], requests[[kind]], coordinate_upper_bound)
    candidates[[kind]] <- list(available = TRUE,
      planner_request_sha256 = request_hash,
      full_plan_sha256 = certificate$plan_sha256,
      accuracy_certificate_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
        .DSVERT_DP_ANALYSIS_FREQUENCY_ACCURACY_DOMAIN_V1, certificate),
      simultaneous_95_abs = certificate$simultaneous_95_abs,
      absolute_support = certificate$absolute_support)
  }
  winner <- if (!unavailable && openssl::bignum(candidates$gaussian$simultaneous_95_abs) <
      openssl::bignum(candidates$convolution$simultaneous_95_abs)) "gaussian" else "convolution"
  selected <- candidates[[winner]]
  expected <- .dsvert_dp_analysis_frequency_selection_certificate_v3(
    primitives[[winner]], selected$full_plan_sha256, selected$simultaneous_95_abs)
  if (!identical(.dsvert_dp_analysis_frequency_hash_v1("", output$selection_certificate),
                 .dsvert_dp_analysis_frequency_hash_v1("", expected))) fail()
  summary <- list(version = "dsvert-frequency-backend-selection-v3",
    policy_sha256 = .dsvert_dp_analysis_frequency_policy_sha256_v3(),
    selection_certificate_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
      .DSVERT_DP_ANALYSIS_FREQUENCY_SELECTION_DOMAIN_V1, expected),
    objective = expected$objective, tie_break = expected$tie_break,
    candidates = candidates, selected_primitive = primitives[[winner]],
    selected_simultaneous_95_abs = selected$simultaneous_95_abs)
  list(summary = summary, selected_request = requests[[winner]],
    selected_plan = output[[paste0(winner, "_plan")]],
    selected_accuracy_certificate = output[[paste0(winner, "_certificate")]],
    selection_certificate = expected)
}

.dsvert_dp_analysis_frequency_selection_validate_v3 <- function(
    selection, selected_primitive, plan, privacy, calibration, dimension, bound) {
  fail <- function() stop("Invalid Frequency backend selection", call. = FALSE)
  fields <- c("version", "policy_sha256", "selection_certificate_sha256",
    "objective", "tie_break", "candidates", "selected_primitive", "selected_simultaneous_95_abs")
  if (!.dsvert_dp_analysis_frequency_object_v1(selection, fields, list(
      version = "dsvert-frequency-backend-selection-v3",
      policy_sha256 = .dsvert_dp_analysis_frequency_policy_sha256_v3(),
      objective = "minimum_certified_simultaneous_95_abs",
      tie_break = "convolution_laplace_v4_on_equal_certified_radius"))) fail()
  requests <- .dsvert_dp_analysis_frequency_candidate_requests_v3(privacy, calibration, dimension)
  primitives <- .dsvert_dp_analysis_frequency_primitives_v3()
  if (!.dsvert_dp_analysis_frequency_object_v1(selection$candidates, names(primitives))) fail()
  for (kind in names(primitives)) {
    candidate <- selection$candidates[[kind]]
    profile <- .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]])
    if (kind == "gaussian" && identical(candidate$available, FALSE)) {
      if (!.dsvert_dp_analysis_frequency_object_v1(candidate,
          c("available", "planner_request_sha256", "unavailable_reason")) ||
          !is.character(candidate$unavailable_reason) ||
          length(candidate$unavailable_reason) != 1L || is.na(candidate$unavailable_reason) ||
          !nzchar(candidate$unavailable_reason)) fail()
    } else {
      if (!.dsvert_dp_analysis_frequency_object_v1(candidate, c("available",
          "planner_request_sha256", "full_plan_sha256", "accuracy_certificate_sha256",
          "simultaneous_95_abs", "absolute_support"), list(available = TRUE)) ||
          !.dsvert_dp_analysis_frequency_hex_v1(candidate$full_plan_sha256) ||
          !.dsvert_dp_analysis_frequency_hex_v1(candidate$accuracy_certificate_sha256)) fail()
      radius <- .dsvert_dp_analysis_frequency_uint_v1(candidate$simultaneous_95_abs)
      support <- .dsvert_dp_analysis_frequency_uint_v1(candidate$absolute_support, TRUE)
      if (radius > support) fail()
      if (kind == "convolution" &&
          (!identical(candidate$absolute_support, format(bound, scientific = FALSE, trim = TRUE)) ||
           !identical(candidate$simultaneous_95_abs,
             .dsvert_dp_analysis_frequency_exact_radius_v4(requests$convolution, bound)))) fail()
      if (kind == "gaussian" && (calibration$implementation_delta <= 0 ||
          openssl::bignum(format(bound, scientific = FALSE, trim = TRUE)) + support >
            (openssl::bignum(2)^127) - 1)) fail()
    }
    if (!identical(candidate$planner_request_sha256,
        .dsvert_dp_analysis_frequency_hash_v1(profile$request_domain, requests[[kind]]))) fail()
  }
  candidates <- selection$candidates
  winner <- if (isTRUE(candidates$gaussian$available) &&
      openssl::bignum(candidates$gaussian$simultaneous_95_abs) <
      openssl::bignum(candidates$convolution$simultaneous_95_abs)) "gaussian" else "convolution"
  selected <- candidates[[winner]]
  expected <- .dsvert_dp_analysis_frequency_selection_certificate_v3(
    primitives[[winner]], selected$full_plan_sha256, selected$simultaneous_95_abs)
  if (!identical(selection$selected_primitive, primitives[[winner]]) ||
      !identical(selected_primitive, primitives[[winner]]) ||
      !identical(selection$selected_simultaneous_95_abs, selected$simultaneous_95_abs) ||
      !identical(plan$full_plan_sha256, selected$full_plan_sha256) ||
      !identical(plan$planner_request_sha256, selected$planner_request_sha256) ||
      !identical(selection$selection_certificate_sha256,
        .dsvert_dp_analysis_frequency_hash_v1(.DSVERT_DP_ANALYSIS_FREQUENCY_SELECTION_DOMAIN_V1, expected))) fail()
  invisible(TRUE)
}

.dsvert_dp_analysis_frequency_plan_summary_v2 <- function(config) {
  fail <- function() stop("Invalid Frequency backend selection", call. = FALSE)
  selection <- config$backend_selection
  if (!.dsvert_dp_analysis_frequency_object_v1(selection, c("summary", "selected_request",
      "selected_plan", "selected_accuracy_certificate", "selection_certificate"))) fail()
  primitive <- selection$summary$selected_primitive
  profile <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  if (is.null(profile)) fail()
  kind <- if (profile$gaussian) "gaussian" else "convolution"
  request <- .dsvert_dp_analysis_frequency_candidate_requests_v3(
    config$privacy, config$calibration, config$factor_domain$dimension)[[kind]]
  if (!identical(.dsvert_dp_analysis_frequency_hash_v1("", request),
                 .dsvert_dp_analysis_frequency_hash_v1("", selection$selected_request))) fail()
  full <- selection$selected_plan
  certificate <- selection$selected_accuracy_certificate
  .dsvert_dp_analysis_frequency_accuracy_validate_v3(
    certificate, full, primitive, request, config$coordinate_upper_bound)
  candidate <- selection$summary$candidates[[kind]]
  if (!identical(candidate$accuracy_certificate_sha256,
      .dsvert_dp_analysis_frequency_hash_v1(.DSVERT_DP_ANALYSIS_FREQUENCY_ACCURACY_DOMAIN_V1, certificate))) fail()
  expected_selection <- .dsvert_dp_analysis_frequency_selection_certificate_v3(
    primitive, certificate$plan_sha256, certificate$simultaneous_95_abs)
  if (!identical(.dsvert_dp_analysis_frequency_hash_v1("", selection$selection_certificate),
                 .dsvert_dp_analysis_frequency_hash_v1("", expected_selection))) fail()
  fraction <- function(n, d) list(numerator = as.character(n), denominator = as.character(d))
  allocated <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(request$delta)
  implementation <- if (profile$gaussian) fraction(full$per_peer_implementation_delta_numerator,
    full$per_peer_implementation_delta_denominator) else fraction("0", "1")
  maximum <- if (profile$gaussian) full$maximum_noise_magnitude_per_peer else "unbounded"
  exact <- isTRUE(profile$exact)
  result <- list(version = if (exact) "dsvert-frequency-plan-summary-v2" else "dsvert-frequency-plan-summary-v1",
    physical_plan_version = profile$plan, full_plan_sha256 = certificate$plan_sha256,
    planner_request_sha256 = .dsvert_dp_analysis_frequency_hash_v1(profile$request_domain, request),
    coordinate_order_sha256 = .dsvert_dp_analysis_frequency_coordinate_order_sha256_v1(config$factor_domain$levels),
    d = config$factor_domain$dimension, chunk_coordinates = min(profile$max_chunk_coordinates, config$factor_domain$dimension),
    allocated_delta = fraction(allocated$numerator, allocated$denominator),
    core_delta = if (profile$gaussian) fraction(full$core_delta_numerator, full$core_delta_denominator) else fraction("0", "1"),
    implementation_delta = implementation, maximum_noise_per_peer = maximum,
    profile_sha256 = .dsvert_dp_analysis_frequency_hash_v1("dsVert/frequency/physical-profile/v1|", profile),
    backend_selection = selection$summary)
  upper <- format(config$coordinate_upper_bound, scientific = FALSE, trim = TRUE)
  if (exact) result$wrap_certificate <- .dsvert_joint_dp_pure_output_certificate(full, upper, 0L) else
    result$no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1("dsVert/frequency/ring128-no-wrap/v1|",
      list(version = "dsvert-frequency-ring128-no-wrap-v1", coordinate_upper_bound = upper,
        maximum_noise_per_peer = maximum, maximum_noise_release = as.character(2 * openssl::bignum(maximum))))
  sensitivity <- list(value = if (config$privacy$adjacency == "replace_one_fixed_cohort")
    if (profile$gaussian) sqrt(2) else 2 else 1)
  .dsvert_dp_analysis_frequency_plan_validate_v1(result, profile, config$privacy,
    sensitivity, config$factor_domain$dimension, config$coordinate_upper_bound, config$calibration)
  if (!is.null(config$transport_chunk_coordinates) &&
      as.numeric(config$transport_chunk_coordinates) != result$chunk_coordinates) fail()
  result
}
