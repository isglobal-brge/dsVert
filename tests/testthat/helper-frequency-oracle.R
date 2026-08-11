.analysis_frequency_oracle_fixture <- function(
    request, outcome = c("convolution", "gaussian", "tie")) {
  outcome <- match.arg(outcome)
  dimension <- request$convolution_request$total_coordinate_count
  radii <- switch(outcome,
    convolution = list(convolution = "5", gaussian = "16"),
    gaussian = list(convolution = "16", gaussian = "5"),
    tie = list(convolution = "5", gaussian = "5"))
  winner <- if (identical(outcome, "gaussian")) "gaussian" else "convolution"
  convolution_fields <- c(
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
    "privacy_argument")
  convolution_plan <- stats::setNames(
    as.list(rep("1", length(convolution_fields))), convolution_fields)
  convolution_values <- list(
    version = paste0("dsvert-joint-dp-vector-independent-full-draw-",
                     "convolution-plan-v3"),
    sampler = paste0("hkdf-sha256-chacha20-independent-full-draw-",
                     "binary-geometric-tv-v3"),
    sensitivity_steps = request$convolution_request$sensitivity_steps,
    total_coordinate_count = dimension,
    binary_geometric_bits = 1,
    bernoulli_thresholds = list("1"),
    one_geometric_tv_numerator = "1",
    one_geometric_tv_denominator = format(
      4000000 * dimension, scientific = FALSE, trim = TRUE),
    implementation_delta_numerator = "1",
    implementation_delta_denominator = "1000000",
    implementation_delta_bound = "1/1000000",
    per_peer_implementation_delta_numerator = "1",
    per_peer_implementation_delta_denominator = "1000000",
    per_peer_implementation_delta_bound = "1/1000000",
    maximum_noise_magnitude = "100",
    maximum_chunk_coordinates = min(8192L, dimension),
    capability_available = TRUE,
    independent_noise_peer_count = 2,
    complete_epsilon_per_peer = TRUE,
    epsilon_divided_by_peer_count = FALSE,
    geometric_variables_per_peer_per_coordinate = 2,
    geometric_variables_total_per_coordinate = 4,
    release_implementation_delta_aggregation = "max_per_peer_not_sum")
  convolution_plan[names(convolution_values)] <- convolution_values
  gaussian_fields <- c(
    "version", "mechanism", "sampler", "reference",
    "total_coordinate_count", "maximum_chunk_coordinates",
    "request_binding_sha256", "epsilon_numerator", "epsilon_denominator",
    "allocated_delta_numerator", "allocated_delta_denominator",
    "core_delta_numerator", "core_delta_denominator", "tail_delta_numerator",
    "tail_delta_denominator", "l2_sensitivity_numerator",
    "l2_sensitivity_denominator", "rho_numerator", "rho_denominator",
    "zcdp_log_upper_integer", "zcdp_conversion_exponent_numerator",
    "zcdp_conversion_exponent_denominator", "sigma_squared_numerator",
    "sigma_squared_denominator", "proposal_scale",
    "maximum_noise_magnitude_per_peer", "maximum_noise_magnitude_two_peers",
    "tail_proof_exponent_numerator", "tail_proof_exponent_denominator",
    "tail_proof_target_numerator", "tail_proof_target_denominator",
    "vector_tail_tv_upper_numerator", "vector_tail_tv_upper_denominator",
    "vector_sampler_tv_upper_numerator",
    "vector_sampler_tv_upper_denominator", "vector_total_tv_upper_numerator",
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
    "capability_available", "unavailable_reason")
  gaussian_plan <- stats::setNames(
    as.list(rep("1", length(gaussian_fields))), gaussian_fields)
  gaussian_sensitivity <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(
    request$gaussian_request$l2_sensitivity_steps)
  gaussian_delta <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(
    request$gaussian_request$delta)
  gaussian_values <- list(
    version = paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-",
                     "tv-bounded-plan-v2"),
    mechanism = "dyadic_discrete_gaussian_truncated_tv_bounded",
    sampler = paste0("cks-target-outward-rational-dyadic-cdf-hkdf-sha256-",
                     "chacha20-coordinate-domain-v2"),
    total_coordinate_count = dimension,
    maximum_chunk_coordinates = min(8192L, dimension),
    l2_sensitivity_numerator = as.character(gaussian_sensitivity$numerator),
    l2_sensitivity_denominator = as.character(gaussian_sensitivity$denominator),
    vector_total_tv_upper_numerator = "1",
    vector_total_tv_upper_denominator = "2000000",
    allocated_delta_numerator = as.character(gaussian_delta$numerator),
    allocated_delta_denominator = as.character(gaussian_delta$denominator),
    core_delta_numerator = "1",
    core_delta_denominator = "2000",
    per_peer_implementation_delta_numerator = "1",
    per_peer_implementation_delta_denominator = "1000000",
    maximum_noise_magnitude_per_peer = "90",
    maximum_noise_magnitude_two_peers = "180",
    simultaneous_95_abs = radii$gaussian,
    independent_noise_peer_count = 2,
    complete_epsilon_per_peer = TRUE,
    epsilon_divided_by_peer_count = FALSE,
    release_delta_aggregation = "max_per_peer_not_sum",
    capability_available = TRUE)
  gaussian_plan[names(gaussian_values)] <- gaussian_values
  plan_hash <- function(plan) .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/full-plan/v1|", plan)
  certificates <- list(
    convolution = list(
      primitive = "independent_full_global_draw_convolution_ring128_v3",
      plan_sha256 = plan_hash(convolution_plan),
      event = "max_j_abs_error_gt_radius",
      method = "exact_two_discrete_laplace_convolution_tail_v1",
      release_tv_upper_numerator = "1",
      release_tv_upper_denominator = "1000000",
      simultaneous_95_abs = radii$convolution,
      absolute_support = "200"),
    gaussian = list(
      primitive = paste0("independent_full_global_dyadic_discrete_gaussian_",
                         "tv_bounded_ring128_v2"),
      plan_sha256 = plan_hash(gaussian_plan),
      event = "max_j_abs_error_gt_radius",
      method = "gaussian_plan_v2_subgaussian_mgf_tv_transfer",
      release_tv_upper_numerator = "1",
      release_tv_upper_denominator = "1000000",
      simultaneous_95_abs = radii$gaussian,
      absolute_support = "180"))
  primitive <- certificates[[winner]]$primitive
  list(
    version = "dsvert-joint-dp-frequency-backend-selection-v1",
    request = request,
    convolution_plan = convolution_plan,
    gaussian_plan = gaussian_plan,
    convolution_certificate = certificates$convolution,
    gaussian_certificate = certificates$gaussian,
    selection_certificate = list(
      version = "dsvert-joint-dp-frequency-backend-selection-certificate-v1",
      policy = "minimum_certified_simultaneous_95_abs_convolution_tie_v1",
      objective = "minimum_certified_simultaneous_95_abs",
      selected_primitive = primitive,
      selected_plan_sha256 = certificates[[winner]]$plan_sha256,
      selected_simultaneous_95_abs = radii[[winner]],
      tie_break = "convolution_laplace_v3_on_equal_certified_radius",
      input_scope = paste0("public_adjacency_planner_requests_and_coordinate_",
                           "upper_bound_only"),
      source_material_consulted = FALSE,
      private_randomness_consulted = FALSE,
      runtime_failure_consulted = FALSE,
      automatic_fallback = FALSE,
      utility_optimality_claimed = FALSE))
}
