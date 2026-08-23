# Canonical workload for one reusable biomedical DP capsule.
#
# This file deliberately has no DataSHIELD entry point and never resolves a
# protected R object.  The signed schema is custodian metadata.  The internal
# local materializer consumes only snapshots that have already passed the
# immutable snapshot resolver.  The v7 manifest authorizes only the registered
# materialize/share/sample/finalize lifecycle; live connector availability is
# checked at runtime and no intermediate is independently releasable.

.DSVERT_DP_CAPSULE_WORKLOAD_VERSION <-
  "dsvert-biomedical-capsule-workload-v7"
.DSVERT_DP_CAPSULE_SCHEMA_VERSION <-
  "dsvert-biomedical-capsule-schema-v1"
.DSVERT_DP_CAPSULE_EXECUTION_STATE <-
  "registered_lifecycle_available_requires_runtime_preflight"
.DSVERT_DP_CAPSULE_RELEASE_LIFECYCLE_VERSION <-
  "dsvert-biomedical-capsule-release-lifecycle-v1"
.DSVERT_DP_CAPSULE_SIGNING_DOMAIN <-
  "dsVert/dp/biomedical-capsule-schema/v1|"
.DSVERT_DP_CAPSULE_GAUSSIAN_REQUEST_BINDING_DOMAIN <-
  paste0("dsVert/joint-dp-vector/dyadic-discrete-gaussian-plan-",
         "request-binding/v2")

.dsvert_dp_capsule_registered_release_lifecycle <- function() {
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_RELEASE_LIFECYCLE_VERSION,
    state = "registered_productive_joint_dp_vector_lifecycle",
    manifest_authority = TRUE,
    included_coordinate_producers = TRUE,
    source_secret_sharing = TRUE,
    recipient_encrypted_transport = TRUE,
    sampler_integration = TRUE,
    confidential_finalizer = TRUE,
    durable_sticky_replay = TRUE,
    package_integration_verified = TRUE,
    live_connector_execution = "runtime_preflight_required",
    raw_intermediate_releasable = FALSE,
    analyst_can_bypass_lifecycle = FALSE))
}

.dsvert_dp_capsule_id <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    stop("Invalid biomedical capsule ", what, ".", call. = FALSE)
  }
  enc2utf8(value)
}

.dsvert_dp_capsule_column_reference <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid biomedical capsule ", what, ".", call. = FALSE)
  }
  value <- enc2utf8(value)
  separator <- regexpr("$", value, fixed = TRUE)[[1L]]
  if (separator > 0L && grepl(
        "$", substring(value, separator + 1L), fixed = TRUE)) {
    stop("Invalid biomedical capsule ", what, ".", call. = FALSE)
  }
  parts <- if (separator < 0L) value else c(
    substring(value, 1L, separator - 1L),
    substring(value, separator + 1L))
  if (length(parts) == 1L) {
    return(list(
      reference = .dsvert_dp_capsule_id(parts[[1L]], what),
      owner_peer = NULL,
      column = .dsvert_dp_capsule_id(parts[[1L]], what)))
  }
  owner <- .dsvert_dp_capsule_id(parts[[1L]], paste(what, "owner"))
  column <- .dsvert_dp_capsule_id(parts[[2L]], what)
  list(reference = paste0(owner, "$", column), owner_peer = owner,
       column = column)
}

.dsvert_dp_capsule_reference_matches <- function(reference, descriptor) {
  parsed <- tryCatch(
    .dsvert_dp_capsule_column_reference(reference, "column reference"),
    error = function(error) NULL)
  !is.null(parsed) && is.list(descriptor) &&
    identical(parsed$column, descriptor$column) &&
    (is.null(parsed$owner_peer) ||
       identical(parsed$owner_peer, descriptor$owner_peer))
}

.dsvert_dp_capsule_named_list <- function(value, what, empty = TRUE) {
  if (is.null(value) && isTRUE(empty)) value <- list()
  if (isTRUE(empty) && is.list(value) && !length(value)) return(list())
  valid_empty <- isTRUE(empty) || length(value) > 0L
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value)) ||
      !valid_empty) {
    stop("Invalid biomedical capsule ", what, ".", call. = FALSE)
  }
  value[order(names(value), method = "radix")]
}

.dsvert_dp_capsule_coordinate_add <- function(current, increment) {
  valid <- function(x) {
    is.numeric(x) && length(x) == 1L && !is.na(x) && is.finite(x) &&
      x >= 0 && x == floor(x)
  }
  if (!valid(current) || !valid(increment) ||
      current > .DSVERT_DP_MAX_COORDINATES ||
      increment > .DSVERT_DP_MAX_COORDINATES - current) {
    stop("The biomedical capsule exceeds the DP coordinate limit.",
         call. = FALSE)
  }
  as.integer(current + increment)
}

# Every non-trivial positive binary64 operation used by an L2 certificate is
# rounded outward immediately.  With u = eps/2, the factor below dominates one
# correctly-rounded operation plus the multiplication that applies the guard:
# (1-u)^2 * (1+32*eps) > 1.  The 32-epsilon margin also covers conversion
# and expression-evaluation roundings around each primitive. Applying it per
# operation avoids an error bound that silently depends on the number or
# ordering of workload terms.
.DSVERT_DP_CAPSULE_L2_OUTWARD_FACTOR <-
  1 + 32 * .Machine$double.eps

.dsvert_dp_capsule_l2_outward_value <- function(value, what) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 0) {
    stop("The biomedical capsule ", what, " is invalid.", call. = FALSE)
  }
  if (value == 0) return(0)
  # A positive subnormal is promoted to the minimum normal. This is deliberately
  # conservative and prevents gradual-underflow details from weakening a bound.
  if (value < .Machine$double.xmin) value <- .Machine$double.xmin
  result <- value * .DSVERT_DP_CAPSULE_L2_OUTWARD_FACTOR
  if (!is.finite(result) || result <= value) {
    stop("The biomedical capsule ", what, " is not representable.",
         call. = FALSE)
  }
  result
}

.dsvert_dp_capsule_l2_add <- function(left, right) {
  if (!is.numeric(left) || length(left) != 1L || is.na(left) ||
      !is.finite(left) || left < 0 ||
      !is.numeric(right) || length(right) != 1L || is.na(right) ||
      !is.finite(right) || right < 0) {
    stop("The biomedical capsule L2 sum is invalid.", call. = FALSE)
  }
  if (left == 0) return(right)
  if (right == 0) return(left)
  .dsvert_dp_capsule_l2_outward_value(
    left + right, "L2 sum")
}

.dsvert_dp_capsule_l2_multiply <- function(left, right) {
  if (!is.numeric(left) || length(left) != 1L || is.na(left) ||
      !is.finite(left) || left < 0 ||
      !is.numeric(right) || length(right) != 1L || is.na(right) ||
      !is.finite(right) || right < 0) {
    stop("The biomedical capsule L2 product is invalid.", call. = FALSE)
  }
  if (left == 0 || right == 0) return(0)
  product <- left * right
  if (!is.finite(product)) {
    stop("The biomedical capsule L2 product is not representable.",
         call. = FALSE)
  }
  if (product == 0) product <- .Machine$double.xmin
  .dsvert_dp_capsule_l2_outward_value(product, "L2 product")
}

.dsvert_dp_capsule_l2_square <- function(value) {
  .dsvert_dp_capsule_l2_multiply(value, value)
}

.dsvert_dp_capsule_l2_sqrt <- function(value) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 0) {
    stop("The biomedical capsule squared L2 sensitivity is invalid.",
         call. = FALSE)
  }
  if (value == 0) return(0)
  .dsvert_dp_capsule_l2_outward_value(
    sqrt(value), "L2 square root")
}

.dsvert_dp_capsule_sensitivity_add <- function(total, l1, l2) {
  if (!is.list(total) || !is.numeric(l1) || length(l1) != 1L ||
      is.na(l1) || !is.finite(l1) || l1 < 0 ||
      !is.numeric(l2) || length(l2) != 1L || is.na(l2) ||
      !is.finite(l2) || l2 < 0) {
    stop("The biomedical capsule sensitivity is invalid.", call. = FALSE)
  }
  next_l1 <- total$l1 + l1
  next_l2_squared <- .dsvert_dp_capsule_l2_add(
    total$l2_squared, .dsvert_dp_capsule_l2_square(l2))
  if (!is.finite(next_l1) || !is.finite(next_l2_squared) ||
      next_l1 > .dsvert_dp_exact_integer_limit ||
      next_l2_squared > .dsvert_dp_exact_integer_limit^2) {
    stop("The biomedical capsule sensitivity is not representable.",
         call. = FALSE)
  }
  list(l1 = next_l1, l2_squared = next_l2_squared)
}

# Public L2 inputs that do not arise from an operation in this file are also
# moved outward before use. Integer L1 bounds remain exact and are never
# inflated.
.dsvert_dp_capsule_outward_l2 <- function(value) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 0) {
    stop("The biomedical capsule L2 sensitivity is invalid.",
         call. = FALSE)
  }
  if (value == 0) return(0)
  result <- .dsvert_dp_capsule_l2_outward_value(
    value, "L2 sensitivity")
  if (!is.finite(result) || result <= value ||
      result > .dsvert_dp_exact_integer_limit) {
    stop("The biomedical capsule L2 sensitivity is not representable.",
         call. = FALSE)
  }
  result
}

# The public policy values are binary64 numbers, while the rational planner reads
# decimal rationals.  Moving epsilon and delta inward, and L2 sensitivity
# outward, before the round-trip decimal encoding prevents that conversion
# from weakening the declared privacy guarantee.  The 128-epsilon separation
# dominates the final 17-digit decimal rounding error by a wide margin.
.dsvert_dp_capsule_gaussian_decimal <- function(
    value, direction = c("inward", "outward"), what) {
  direction <- match.arg(direction)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value <= 0) {
    stop("Invalid fixed-work discrete-Gaussian ", what, ".", call. = FALSE)
  }
  margin <- 128 * .Machine$double.eps
  guarded <- if (identical(direction, "inward")) {
    value * (1 - margin)
  } else {
    value * (1 + margin)
  }
  ordered <- if (identical(direction, "inward")) {
    is.finite(guarded) && guarded > 0 && guarded < value
  } else {
    is.finite(guarded) && guarded > value
  }
  if (!isTRUE(ordered)) {
    stop("The fixed-work discrete-Gaussian ", what,
         " cannot be conservatively encoded.", call. = FALSE)
  }
  encoded <- format(
    guarded, digits = 17L, scientific = TRUE, trim = TRUE,
    decimal.mark = ".")
  decoded <- suppressWarnings(as.numeric(encoded))
  ordered <- if (identical(direction, "inward")) {
    is.finite(decoded) && decoded > 0 && decoded < value
  } else {
    is.finite(decoded) && decoded > value
  }
  if (!isTRUE(ordered)) {
    stop("The fixed-work discrete-Gaussian ", what,
         " decimal is not conservative.", call. = FALSE)
  }
  encoded
}

.dsvert_dp_capsule_exact_gaussian_request <- function(
    epsilon, delta, l2_sensitivity, coordinate_count) {
  if (!is.numeric(coordinate_count) || length(coordinate_count) != 1L ||
      is.na(coordinate_count) || !is.finite(coordinate_count) ||
      coordinate_count < 1 || coordinate_count != floor(coordinate_count) ||
      coordinate_count > .DSVERT_DP_MAX_COORDINATES) {
    stop("Invalid fixed-work discrete-Gaussian coordinate count.", call. = FALSE)
  }
  list(
    epsilon = .dsvert_dp_capsule_gaussian_decimal(
      epsilon, "inward", "epsilon"),
    delta = .dsvert_dp_capsule_gaussian_decimal(
      delta, "inward", "delta"),
    l2_sensitivity_steps = .dsvert_dp_capsule_gaussian_decimal(
      l2_sensitivity, "outward", "L2 sensitivity"),
    total_coordinate_count = as.integer(coordinate_count))
}

.dsvert_dp_capsule_exact_gaussian_request_binding <- function(plan, request) {
  fields <- c(
    epsilon = request$epsilon,
    delta = request$delta,
    l2_sensitivity_steps = request$l2_sensitivity_steps,
    total_coordinate_count = as.character(request$total_coordinate_count),
    epsilon_numerator = plan$epsilon_numerator,
    epsilon_denominator = plan$epsilon_denominator,
    allocated_delta_numerator = plan$allocated_delta_numerator,
    allocated_delta_denominator = plan$allocated_delta_denominator,
    l2_sensitivity_numerator = plan$l2_sensitivity_numerator,
    l2_sensitivity_denominator = plan$l2_sensitivity_denominator)
  message <- paste0(
    .DSVERT_DP_CAPSULE_GAUSSIAN_REQUEST_BINDING_DOMAIN, "\n",
    paste0(names(fields), "=", nchar(fields, type = "bytes"), ":",
           fields, "\n", collapse = ""))
  digest::digest(enc2utf8(message), algo = "sha256", serialize = FALSE)
}

.dsvert_dp_capsule_exact_gaussian_plan_validate <- function(
    plan, coordinate_count, request) {
  required <- c(
    "version", "mechanism", "sampler", "reference",
    "total_coordinate_count", "maximum_chunk_coordinates",
    "request_binding_sha256",
    "epsilon_numerator", "epsilon_denominator",
    "allocated_delta_numerator", "allocated_delta_denominator",
    "core_delta_numerator", "core_delta_denominator",
    "tail_delta_numerator", "tail_delta_denominator",
    "l2_sensitivity_numerator", "l2_sensitivity_denominator",
    "rho_numerator", "rho_denominator", "zcdp_log_upper_integer",
    "zcdp_conversion_exponent_numerator",
    "zcdp_conversion_exponent_denominator",
    "sigma_squared_numerator", "sigma_squared_denominator",
    "proposal_scale", "maximum_noise_magnitude_per_peer",
    "maximum_noise_magnitude_two_peers",
    "tail_proof_exponent_numerator", "tail_proof_exponent_denominator",
    "tail_proof_target_numerator", "tail_proof_target_denominator",
    "vector_tail_tv_upper_numerator",
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
    "source_share_hiding_precondition",
    "exact_rational_sampler", "finite_support_transfer_charged",
    "fixed_work_sampler", "sampler_branches_on_protected_values",
    "sampler_branches_on_private_randomness", "host_constant_time_claim",
    "transcript_dp_claim", "logical_transcript_fixed_shape",
    "physical_timing_dp_claim", "observable_worker_shape",
    "capability_available", "unavailable_reason")
  integer_fields <- c(
    "epsilon_numerator", "epsilon_denominator",
    "allocated_delta_numerator", "allocated_delta_denominator",
    "core_delta_numerator", "core_delta_denominator",
    "tail_delta_numerator", "tail_delta_denominator",
    "l2_sensitivity_numerator", "l2_sensitivity_denominator",
    "rho_numerator", "rho_denominator", "zcdp_log_upper_integer",
    "zcdp_conversion_exponent_numerator",
    "zcdp_conversion_exponent_denominator",
    "sigma_squared_numerator", "sigma_squared_denominator",
    "proposal_scale", "maximum_noise_magnitude_per_peer",
    "maximum_noise_magnitude_two_peers",
    "tail_proof_exponent_numerator", "tail_proof_exponent_denominator",
    "tail_proof_target_numerator", "tail_proof_target_denominator",
    "vector_tail_tv_upper_numerator",
    "vector_tail_tv_upper_denominator",
    "vector_sampler_tv_upper_numerator",
    "vector_sampler_tv_upper_denominator",
    "vector_total_tv_upper_numerator",
    "vector_total_tv_upper_denominator",
    "per_peer_implementation_delta_numerator",
    "per_peer_implementation_delta_denominator", "simultaneous_95_abs")
  denominator_fields <- grep("_denominator$", integer_fields, value = TRUE)
  positive_fields <- c(
    "epsilon_numerator", "allocated_delta_numerator",
    "core_delta_numerator", "tail_delta_numerator",
    "l2_sensitivity_numerator", "rho_numerator",
    "zcdp_log_upper_integer", "zcdp_conversion_exponent_numerator",
    "sigma_squared_numerator", "proposal_scale",
    "tail_proof_exponent_numerator", "tail_proof_target_numerator",
    "vector_tail_tv_upper_numerator",
    "vector_sampler_tv_upper_numerator",
    "vector_total_tv_upper_numerator",
    "per_peer_implementation_delta_numerator")
  request_valid <- is.list(request) && !is.null(names(request)) &&
    !anyNA(names(request)) && !anyDuplicated(names(request)) &&
    setequal(names(request), c(
      "epsilon", "delta", "l2_sensitivity_steps",
      "total_coordinate_count")) &&
    all(vapply(request[c(
      "epsilon", "delta", "l2_sensitivity_steps")], function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          nzchar(value) && nchar(value, type = "bytes") <= 512L &&
          !grepl("[\r\n]", value)
      }, logical(1L))) &&
    is.numeric(request$total_coordinate_count) &&
    length(request$total_coordinate_count) == 1L &&
    !is.na(request$total_coordinate_count) &&
    is.finite(request$total_coordinate_count) &&
    request$total_coordinate_count == floor(request$total_coordinate_count) &&
    identical(as.numeric(request$total_coordinate_count),
              as.numeric(coordinate_count))
  integer_valid <- is.list(plan) && all(integer_fields %in% names(plan)) &&
    all(vapply(plan[integer_fields], function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^(0|[1-9][0-9]*)$", value) &&
        nchar(value, type = "bytes") <= 16384L
    }, logical(1L)))
  unsigned_less <- function(left, right) {
    nchar(left, type = "bytes") < nchar(right, type = "bytes") ||
      (nchar(left, type = "bytes") == nchar(right, type = "bytes") &&
         left < right)
  }
  fraction_lt_one <- function(prefix) {
    unsigned_less(plan[[paste0(prefix, "_numerator")]],
                  plan[[paste0(prefix, "_denominator")]])
  }
  integer_scalar <- function(value, minimum, maximum) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value == floor(value) &&
      value >= minimum && value <= maximum
  }
  valid <- is.list(plan) && !is.null(names(plan)) && !anyNA(names(plan)) &&
    !anyDuplicated(names(plan)) && setequal(names(plan), required) &&
    isTRUE(request_valid) && isTRUE(integer_valid) &&
    identical(plan$version,
      "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-plan-v2") &&
    identical(plan$mechanism,
              "dyadic_discrete_gaussian_truncated_tv_bounded") &&
    identical(plan$sampler,
      paste0("cks-target-outward-rational-dyadic-cdf-hkdf-sha256-",
             "chacha20-coordinate-domain-v2")) &&
    identical(as.numeric(plan$total_coordinate_count),
              as.numeric(coordinate_count)) &&
    identical(as.numeric(plan$total_coordinate_count),
              as.numeric(request$total_coordinate_count)) &&
    identical(as.numeric(plan$maximum_chunk_coordinates),
              as.numeric(min(8192L, coordinate_count))) &&
    identical(as.numeric(plan$independent_noise_peer_count), 2) &&
    identical(plan$complete_epsilon_per_peer, TRUE) &&
    identical(plan$epsilon_divided_by_peer_count, FALSE) &&
    identical(plan$release_delta_aggregation, "max_per_peer_not_sum") &&
    identical(plan$exact_rational_sampler, FALSE) &&
    identical(plan$finite_support_transfer_charged, TRUE) &&
    identical(plan$fixed_work_sampler, TRUE) &&
    identical(plan$sampler_branches_on_protected_values, FALSE) &&
    # The productive v2 sampler scans its complete public CDF table and uses
    # fixed-width borrow/mask selection.  This field is about algorithmic
    # branches only; it is not a host constant-time claim.
    identical(plan$sampler_branches_on_private_randomness, FALSE) &&
    identical(plan$host_constant_time_claim, FALSE) &&
    # transcript_dp_claim is deliberately restricted to the logical worker
    # transcript (round count and payload geometry).  Wall-clock completion,
    # scheduling, polling and retransmission remain explicitly excluded.
    identical(plan$transcript_dp_claim, TRUE) &&
    identical(plan$logical_transcript_fixed_shape, TRUE) &&
    identical(plan$physical_timing_dp_claim, FALSE) &&
    identical(as.numeric(plan$nominal_variance_multiplier), 2) &&
    identical(plan$nominal_standard_deviation_factor,
              "sqrt(2)_relative_to_one_full_draw") &&
    identical(plan$at_least_one_honest_noise_peer, TRUE) &&
    identical(as.numeric(plan$maximum_colluding_noise_peers), 1) &&
    identical(plan$adversary_view,
      paste0("analyst_plus_at_most_one_designated_noise_peer_including_",
             "its_seed_draw_source_share_and_protocol_transcript")) &&
    identical(plan$adversary_view_privacy_argument,
      paste0("conditioned_on_a_simulatable_own_share_and_fixed_corrupt_",
             "peer_view_the_other_independent_complete_epsilon_full_",
             "sensitivity_draw_is_an_epsilon_delta_DP_mechanism; own_",
             "draw_translation_second_draw_signed_decode_and_public_",
             "clamp_are_post_processing; release_delta_is_max_of_the_",
             "two_symmetric_conditional_guarantees")) &&
    identical(plan$source_share_hiding_precondition,
      paste0("each_single_pre_noise_aggregate_share_is_computationally_",
             "simulatable_without_the_protected_query_under_",
             "authenticated_semi_honest_fanin")) &&
    is.character(plan$observable_worker_shape) &&
    length(plan$observable_worker_shape) == 1L &&
    !is.na(plan$observable_worker_shape) &&
    nzchar(plan$observable_worker_shape) &&
    nchar(plan$observable_worker_shape, type = "bytes") <= 1024L &&
    integer_scalar(plan$sampler_candidate_count, 1, 1) &&
    integer_scalar(plan$sampler_random_bits_per_coordinate, 128, 16384) &&
    plan$sampler_random_bits_per_coordinate %% 8 == 0 &&
    integer_scalar(plan$sampler_random_bytes_per_coordinate, 17, 2049) &&
    plan$sampler_random_bytes_per_coordinate ==
      plan$sampler_random_bits_per_coordinate / 8 + 1 &&
    integer_scalar(plan$sampler_table_precision_bits, 128, 16474) &&
    plan$sampler_table_precision_bits >=
      plan$sampler_random_bits_per_coordinate &&
    integer_scalar(plan$sampler_magnitude_count, 1, 2^20 + 1) &&
    integer_scalar(plan$sampler_search_steps, 1, 21) &&
    integer_scalar(plan$sampler_full_scan_steps, 1, 2^20 + 1) &&
    identical(as.numeric(plan$sampler_full_scan_steps),
              as.numeric(plan$sampler_magnitude_count)) &&
    integer_scalar(plan$sampler_cdf_table_bytes, 1, 2^53 - 1) &&
    identical(as.numeric(plan$sampler_cdf_table_bytes),
              as.numeric(plan$sampler_magnitude_count) *
                as.numeric(plan$sampler_random_bytes_per_coordinate)) &&
    identical(plan$capability_available, TRUE) &&
    identical(plan$unavailable_reason, "") &&
    is.character(plan$request_binding_sha256) &&
    length(plan$request_binding_sha256) == 1L &&
    !is.na(plan$request_binding_sha256) &&
    grepl("^[0-9a-f]{64}$", plan$request_binding_sha256) &&
    all(plan[denominator_fields] != "0") &&
    all(plan[positive_fields] != "0") &&
    all(vapply(c("allocated_delta", "core_delta", "tail_delta",
                 "vector_tail_tv_upper", "vector_sampler_tv_upper",
                 "vector_total_tv_upper",
                 "per_peer_implementation_delta"),
               fraction_lt_one, logical(1L)))
  if (isTRUE(valid)) {
    valid <- identical(
      plan$request_binding_sha256,
      .dsvert_dp_capsule_exact_gaussian_request_binding(plan, request))
  }
  if (!isTRUE(valid)) {
    stop("The fixed-work discrete-Gaussian planner returned an invalid certificate.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(plan)
}

.dsvert_dp_capsule_mechanism_selection <- function(
    policy, coordinate_count, l1_sensitivity, l2_sensitivity,
    selector = .dsvert_dp_noise_selection, gaussian_planner = NULL) {
  epsilon <- as.numeric(policy$global_total_epsilon)
  delta <- as.numeric(policy$global_total_delta)
  if (!is.function(selector) || !is.numeric(coordinate_count) ||
      length(coordinate_count) != 1L || is.na(coordinate_count) ||
      !is.finite(coordinate_count) || coordinate_count < 1 ||
      coordinate_count != floor(coordinate_count) ||
      coordinate_count > .DSVERT_DP_MAX_COORDINATES ||
      !is.numeric(l1_sensitivity) || length(l1_sensitivity) != 1L ||
      is.na(l1_sensitivity) || !is.finite(l1_sensitivity) ||
      l1_sensitivity <= 0 || l1_sensitivity != floor(l1_sensitivity) ||
      !is.numeric(l2_sensitivity) || length(l2_sensitivity) != 1L ||
      is.na(l2_sensitivity) || !is.finite(l2_sensitivity) ||
      l2_sensitivity <= 0 || !is.finite(epsilon) || epsilon <= 0 ||
      !is.finite(delta) || delta < 0 || delta >= 1) {
    stop("The biomedical capsule mechanism-selection inputs are invalid.",
         call. = FALSE)
  }
  uses_delta <- delta > 0
  selected <- selector(
    coordinate_count = as.integer(coordinate_count),
    laplace_epsilons = epsilon,
    laplace_sensitivities = l1_sensitivity,
    gaussian_epsilon = epsilon, gaussian_delta = delta,
    gaussian_l2_sensitivity = l2_sensitivity,
    objective = "simultaneous_95_abs")
  scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value >= 0
  }
  valid <- is.list(selected) &&
    identical(selected$selector, .DSVERT_DP_NOISE_SELECTOR) &&
    identical(selected$objective, "simultaneous_95_abs") &&
    identical(as.numeric(selected$coordinate_count),
              as.numeric(coordinate_count)) &&
    is.list(selected$laplace) && isTRUE(selected$laplace$available) &&
    scalar(selected$laplace$simultaneous_95_abs)
  if (!isTRUE(valid)) {
    stop("The biomedical capsule noise selector returned an invalid decision.",
         call. = FALSE)
  }
  if (is.null(gaussian_planner)) gaussian_planner <- function(value) {
    .callMpcTool("joint-dp-vector-gaussian-plan-v2", value)
  }
  if (!is.function(gaussian_planner)) {
    stop("The fixed-work discrete-Gaussian planner is invalid.", call. = FALSE)
  }
  gaussian_plan <- NULL
  gaussian_request <- NULL
  gaussian_unavailable <- if (!uses_delta) {
    "positive_delta_is_required"
  } else {
    tryCatch({
      gaussian_request <- .dsvert_dp_capsule_exact_gaussian_request(
        epsilon, delta, l2_sensitivity, coordinate_count)
      gaussian_plan <- gaussian_planner(gaussian_request)
      gaussian_plan <- .dsvert_dp_capsule_exact_gaussian_plan_validate(
        gaussian_plan, coordinate_count, gaussian_request)
      NULL
    }, error = function(e) "formal_fixed_work_gaussian_plan_unavailable")
  }
  gaussian_radius <- if (is.null(gaussian_plan)) Inf else
    suppressWarnings(as.numeric(gaussian_plan$simultaneous_95_abs))
  gaussian_backend_available <- is.null(gaussian_unavailable) &&
    is.finite(gaussian_radius) && gaussian_radius >= 0 &&
    gaussian_radius <= .dsvert_dp_exact_integer_limit
  if (!gaussian_backend_available && is.null(gaussian_unavailable)) {
    gaussian_unavailable <- "fixed_work_gaussian_accuracy_not_representable"
  }
  gaussian_wins <- gaussian_backend_available &&
    gaussian_radius < selected$laplace$simultaneous_95_abs
  utility_winner <- if (gaussian_wins) "gaussian" else "laplace"
  base <- list(
    version = "biomedical-capsule-noise-selection-v4",
    selector = "formal_fixed_work_backend_minimum_simultaneous_95_radius_v2",
    objective = "simultaneous_95_abs",
    tie_break = "laplace_unless_fixed_work_gaussian_strictly_improves",
    coordinate_count = as.integer(coordinate_count),
    epsilon = epsilon, allocated_delta = delta,
    gaussian_eligible = uses_delta,
    positive_delta_reserved = uses_delta,
    deployed_backends = if (gaussian_backend_available) {
      c("joint-discrete-laplace-v3",
        "dyadic-discrete-gaussian-tv-bounded-v2")
    } else "joint-discrete-laplace-v3",
    gaussian_backend_available = gaussian_backend_available,
    gaussian_unavailable_reason = gaussian_unavailable,
    gaussian_calibration_request = gaussian_request,
    gaussian_calibration_rounding = list(
      declared_policy_values = "binary64_policy_values",
      epsilon = "inward_128_machine_epsilon_relative_guard_v1",
      delta = "inward_128_machine_epsilon_relative_guard_v1",
      l2_sensitivity = "outward_128_machine_epsilon_relative_guard_v1"),
    gaussian_plan = gaussian_plan,
    gaussian_plan_sha256 = if (is.null(gaussian_plan)) NULL else
      .dsvert_joint_dp_hash(gaussian_plan),
    laplace_simultaneous_95_abs =
      selected$laplace$simultaneous_95_abs,
    gaussian_simultaneous_95_abs = if (gaussian_backend_available) {
      gaussian_radius
    } else NULL,
    deployment_rule = "formal_backend_or_explicit_laplace_fallback")
  certificate <- c(base, list(
    winner = utility_winner,
    utility_winner = utility_winner,
    decision = if (gaussian_wins) {
      "dyadic_discrete_gaussian_tv_bounded_strictly_improves_utility"
    } else if (!gaussian_backend_available) {
      "fixed_work_gaussian_unavailable_explicit_laplace_fallback"
    } else {
      "laplace_wins_or_ties_public_utility_objective"
    },
    canonical_selector_invoked = TRUE,
    selector_certificate_sha256 = .dsvert_joint_dp_hash(selected)))
  if (gaussian_wins) {
    list(
      mechanism = "dyadic_discrete_gaussian_truncated_tv_bounded",
      sensitivity_norm = "l2", sensitivity = l2_sensitivity,
      uses_delta = TRUE, certificate = certificate)
  } else {
    list(
      mechanism = "discrete-laplace", sensitivity_norm = "l1",
      sensitivity = l1_sensitivity, uses_delta = uses_delta,
      certificate = certificate)
  }
}

.dsvert_dp_capsule_schema_message <- function(unsigned) {
  charToRaw(paste0(
    .DSVERT_DP_CAPSULE_SIGNING_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_capsule_column <- function(value, owner_names) {
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) ||
      !all(c("kind", "owner_peer") %in% names(value)) ||
      !is.character(value$kind) || length(value$kind) != 1L ||
      is.na(value$kind) ||
      !value$kind %in% c("numeric", "categorical") ||
      !is.character(value$owner_peer) || length(value$owner_peer) != 1L ||
      is.na(value$owner_peer) || !value$owner_peer %in% owner_names) {
    stop("Invalid biomedical capsule column ownership.", call. = FALSE)
  }
  if (identical(value$kind, "numeric")) {
    if (!setequal(names(value), c("kind", "owner_peer", "lower", "upper")) ||
        !is.numeric(value$lower) || length(value$lower) != 1L ||
        is.na(value$lower) || !is.finite(value$lower) ||
        !is.numeric(value$upper) || length(value$upper) != 1L ||
        is.na(value$upper) || !is.finite(value$upper) ||
        value$lower >= value$upper ||
        !is.finite(value$upper - value$lower) ||
        !is.finite((value$upper - value$lower)^2)) {
      stop("Invalid biomedical capsule numeric bounds.", call. = FALSE)
    }
    return(.dsvert_dp_canonical_query_value(list(
      kind = "numeric", owner_peer = value$owner_peer,
      lower = as.numeric(value$lower), upper = as.numeric(value$upper))))
  }
  if (!setequal(names(value), c("kind", "owner_peer", "levels")) ||
      !is.atomic(value$levels) || !length(value$levels) ||
      anyNA(value$levels)) {
    stop("Invalid biomedical capsule categorical domain.", call. = FALSE)
  }
  levels <- tryCatch(
    .dsvert_canonical_label_values(
      value$levels, "biomedical capsule categorical levels",
      allow_na = FALSE, allow_blank = FALSE),
    error = function(e) NULL)
  if (is.null(levels) || anyDuplicated(levels) ||
      any(!nzchar(trimws(levels)))) {
    stop("Invalid biomedical capsule categorical domain.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    kind = "categorical", owner_peer = value$owner_peer,
    levels = sort(unname(levels), method = "radix")))
}

.dsvert_dp_capsule_schema <- function(
    policy, logical_snapshot, schema_manifest, signature_verifier) {
  required <- c(
    "version", "logical_snapshot", "peer_pinset_sha256", "datasets",
    "signatures")
  if (!is.list(schema_manifest) || is.null(names(schema_manifest)) ||
      anyNA(names(schema_manifest)) || anyDuplicated(names(schema_manifest)) ||
      !setequal(names(schema_manifest), required) ||
      !identical(schema_manifest$version,
                 .DSVERT_DP_CAPSULE_SCHEMA_VERSION) ||
      !is.function(signature_verifier)) {
    stop("Invalid signed biomedical capsule schema manifest.", call. = FALSE)
  }
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(logical_snapshot)
  signed_snapshot <- tryCatch(
    .dsvert_joint_dp_logical_snapshot(schema_manifest$logical_snapshot),
    error = function(e) NULL)
  if (is.null(signed_snapshot) || !identical(signed_snapshot, logical_snapshot)) {
    stop("The signed biomedical schema targets a different logical snapshot.",
         call. = FALSE)
  }

  pins <- policy$peer_pinset
  if (!is.character(pins) || length(pins) < 2L || is.null(names(pins)) ||
      anyNA(names(pins)) || any(!nzchar(names(pins))) ||
      anyDuplicated(names(pins)) || anyDuplicated(unname(pins))) {
    stop("The biomedical capsule requires a complete pinned-peer map.",
         call. = FALSE)
  }
  pins <- tryCatch(vapply(
    pins, .dsvert_relay_normalize_identity_pk, character(1L)),
    error = function(e) NULL)
  if (is.null(pins)) {
    stop("The biomedical capsule requires a valid pinned-peer map.",
         call. = FALSE)
  }
  pins <- pins[order(names(pins), method = "radix")]
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  if (!is.character(schema_manifest$peer_pinset_sha256) ||
      length(schema_manifest$peer_pinset_sha256) != 1L ||
      !identical(schema_manifest$peer_pinset_sha256, pin_hash) ||
      !identical(policy$peer_pinset_sha256, pin_hash)) {
    stop("The signed biomedical schema does not match the pinned consortium.",
         call. = FALSE)
  }

  datasets <- .dsvert_dp_capsule_named_list(
    schema_manifest$datasets, "dataset schema", empty = FALSE)
  normalized <- vector("list", length(datasets))
  names(normalized) <- names(datasets)
  seen_references <- character()
  seen_physical <- character()
  for (data_name in names(datasets)) {
    .dsvert_dp_capsule_id(data_name, "dataset name")
    dataset <- datasets[[data_name]]
    expected <- c(
      "dataset_id", "dataset_version", "schema_version", "alignment_group",
      "patient_keys", "columns")
    if (!is.list(dataset) || is.null(names(dataset)) ||
        anyNA(names(dataset)) || anyDuplicated(names(dataset)) ||
        !setequal(names(dataset), expected)) {
      stop("Invalid biomedical capsule dataset schema.", call. = FALSE)
    }
    dataset_id <- .dsvert_dp_capsule_id(dataset$dataset_id, "dataset id")
    dataset_version <- .dsvert_dp_capsule_id(
      dataset$dataset_version, "dataset version")
    schema_version <- .dsvert_dp_capsule_id(
      dataset$schema_version, "dataset schema version")
    alignment_group <- .dsvert_dp_capsule_id(
      dataset$alignment_group, "dataset alignment group")
    patient_keys <- .dsvert_dp_capsule_named_list(
      dataset$patient_keys, "patient-key ownership", empty = FALSE)
    if (!all(names(patient_keys) %in% names(pins)) ||
        !all(vapply(patient_keys, function(value) {
          is.character(value) && length(value) == 1L && !is.na(value) &&
            grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)
        }, logical(1L)))) {
      stop("Every dataset owner needs one public patient-key schema binding.",
           call. = FALSE)
    }
    patient_keys <- lapply(patient_keys, enc2utf8)
    columns <- .dsvert_dp_capsule_named_list(
      dataset$columns, "column schema", empty = FALSE)
    normalized_columns <- vector("list", length(columns))
    names(normalized_columns) <- names(columns)
    for (column_name in names(columns)) {
      reference <- .dsvert_dp_capsule_column_reference(
        column_name, "column name")
      column <- .dsvert_dp_capsule_column(
        columns[[column_name]], names(pins))
      if (!is.null(reference$owner_peer) &&
          !identical(reference$owner_peer, column$owner_peer)) {
        stop("A qualified biomedical capsule column names the wrong owner.",
             call. = FALSE)
      }
      physical <- paste(
        column$owner_peer, data_name, reference$column, sep = "\r")
      if (column_name %in% seen_references || physical %in% seen_physical) {
        stop("Biomedical capsule column references must identify one signed ",
             "owner/dataset/column triplet.", call. = FALSE)
      }
      seen_references <- c(seen_references, column_name)
      seen_physical <- c(seen_physical, physical)
      normalized_columns[[column_name]] <- column
    }
    column_owners <- unique(vapply(
      normalized_columns, `[[`, character(1L), "owner_peer"))
    if (!setequal(names(patient_keys), column_owners)) {
      stop("Patient-key ownership must exactly cover the dataset columns.",
           call. = FALSE)
    }
    normalized[[data_name]] <- .dsvert_dp_canonical_query_value(list(
      dataset_id = dataset_id, dataset_version = dataset_version,
      schema_version = schema_version, alignment_group = alignment_group,
      patient_keys = patient_keys, columns = normalized_columns))
  }
  alignment_groups <- unique(vapply(
    normalized, `[[`, character(1L), "alignment_group"))
  if (length(alignment_groups) != 1L) {
    stop("One biomedical capsule must describe exactly one signed alignment ",
         "group; use a separate logical snapshot for another cohort.",
         call. = FALSE)
  }

  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash, datasets = normalized))
  signatures <- .dsvert_dp_capsule_named_list(
    schema_manifest$signatures, "schema signatures", empty = FALSE)
  if (!setequal(names(signatures), names(pins)) ||
      !all(vapply(signatures, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          grepl("^[A-Za-z0-9_-]{86}$", value)
      }, logical(1L)))) {
    stop("Every pinned peer must sign the global biomedical schema.",
         call. = FALSE)
  }
  message <- .dsvert_dp_capsule_schema_message(unsigned)
  verified <- vapply(names(pins), function(peer) {
    isTRUE(tryCatch(
      signature_verifier(message, unname(pins[[peer]]), signatures[[peer]]),
      error = function(e) FALSE))
  }, logical(1L))
  if (!all(verified)) {
    stop("The global biomedical schema signatures are invalid.",
         call. = FALSE)
  }
  list(
    unsigned = unsigned,
    sha256 = .dsvert_joint_dp_hash(unsigned),
    signers = sort(names(pins), method = "radix"),
    signatures = .dsvert_dp_canonical_query_value(
      signatures[sort(names(pins), method = "radix")]))
}

.dsvert_dp_capsule_validate_local_schema <- function(policy, schema) {
  local_peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  local_numeric <- local_categorical <- list()
  local_datasets <- character()
  for (data_name in names(schema$datasets)) {
    dataset <- schema$datasets[[data_name]]
    if (local_peer %in% names(dataset$patient_keys)) {
      local_datasets <- c(local_datasets, data_name)
      descriptor <- policy$datasets[[data_name]]
      if (!is.list(descriptor) ||
          !identical(descriptor$id, dataset$dataset_id) ||
          !identical(descriptor$version, dataset$dataset_version) ||
          !identical(dataset$patient_keys[[local_peer]],
                     policy$patient_column)) {
        stop("The local dataset policy does not match the signed schema.",
             call. = FALSE)
      }
    }
    for (column_name in names(dataset$columns)) {
      column <- dataset$columns[[column_name]]
      if (!identical(column$owner_peer, local_peer)) next
      physical_name <- .dsvert_dp_capsule_column_reference(
        column_name, "column name")$column
      if (identical(column$kind, "numeric")) {
        local_numeric[[physical_name]] <- c(column$lower, column$upper)
      } else {
        local_categorical[[physical_name]] <- column$levels
      }
    }
  }
  if (!length(local_datasets) ||
      !setequal(names(policy$datasets), local_datasets) ||
      !setequal(names(policy$numeric_bounds), names(local_numeric)) ||
      !setequal(names(policy$categorical_levels), names(local_categorical))) {
    stop("The local DP policy does not cover exactly its signed columns.",
         call. = FALSE)
  }
  for (name in names(local_numeric)) {
    if (!isTRUE(all.equal(
          unname(as.numeric(policy$numeric_bounds[[name]])),
          unname(as.numeric(local_numeric[[name]])), tolerance = 0))) {
      stop("A local numeric bound conflicts with the signed schema.",
           call. = FALSE)
    }
  }
  for (name in names(local_categorical)) {
    configured <- sort(unname(policy$categorical_levels[[name]]),
                       method = "radix")
    if (!identical(configured, local_categorical[[name]])) {
      stop("A local categorical domain conflicts with the signed schema.",
           call. = FALSE)
    }
  }
  invisible(TRUE)
}

.dsvert_dp_capsule_validate_local_projection_schema <- function(
    policy, schema, primitive_scope) {
  scope <- .dsvert_dp_capsule_scope_policy_binding(primitive_scope)
  pair <- if (identical(scope$mode, "catalog_v1") &&
      !length(scope$numeric_moments) &&
      !length(scope$categorical_marginals) &&
      length(scope$categorical_pairs) == 1L &&
      !length(scope$correlations)) {
    scope$categorical_pairs[[1L]]
  } else NULL
  columns <- tryCatch(
    .dsvert_dp_capsule_qualified_columns(schema),
    error = function(error) NULL)
  selected <- if (is.list(columns) && !is.null(pair) &&
      all(pair %in% names(columns))) columns[pair] else NULL
  owners <- if (is.list(selected)) vapply(
    selected, `[[`, character(1L), "owner_peer") else character()
  datasets <- if (is.list(selected)) vapply(
    selected, `[[`, character(1L), "dataset") else character()
  same_owner <- is.list(schema$datasets) && length(schema$datasets) == 1L &&
    is.list(selected) && length(selected) == 2L &&
    all(vapply(selected, function(column) {
      identical(column$kind, "categorical")
    }, logical(1L))) && length(unique(owners)) == 1L &&
    length(unique(datasets)) == 1L &&
    identical(names(schema$datasets), unique(datasets)) &&
    identical(names(schema$datasets[[1L]]$patient_keys), unique(owners))
  empty_cross_scope <- identical(scope$mode, "catalog_v1") &&
    !length(scope$numeric_moments) &&
    !length(scope$categorical_marginals) &&
    !length(scope$categorical_pairs) && !length(scope$correlations)
  cross_selected <- if (isTRUE(empty_cross_scope) && is.list(columns) &&
      length(columns) == 2L) columns else NULL
  cross_owners <- if (is.list(cross_selected)) vapply(
    cross_selected, `[[`, character(1L), "owner_peer") else character()
  cross_datasets <- if (is.list(cross_selected)) vapply(
    cross_selected, `[[`, character(1L), "dataset") else character()
  cross_owner <- is.list(schema$datasets) &&
    length(schema$datasets) %in% 1:2 &&
    is.list(cross_selected) && length(cross_selected) == 2L &&
    all(vapply(cross_selected, function(column) {
      identical(column$kind, "categorical")
    }, logical(1L))) && length(unique(cross_owners)) == 2L &&
    setequal(names(schema$datasets), unique(cross_datasets)) &&
    all(vapply(names(schema$datasets), function(data_name) {
      expected <- sort(unique(cross_owners[cross_datasets == data_name]),
                       method = "radix")
      identical(names(schema$datasets[[data_name]]$patient_keys), expected)
    }, logical(1L)))
  if (!isTRUE(same_owner) && !isTRUE(cross_owner)) {
    stop("The local Synopsis projection is not one same-owner pair.",
         call. = FALSE)
  }
  if (isTRUE(same_owner)) {
    configured <- .dsvert_dp_capsule_scope_policy_binding(
      policy$capsule_workload_scope)
    if (identical(configured$mode, "catalog_v1")) {
      authorized <- any(vapply(configured$categorical_pairs, function(raw) {
        length(raw) == 2L && (
          (.dsvert_dp_capsule_reference_matches(raw[[1L]], selected[[1L]]) &&
           .dsvert_dp_capsule_reference_matches(raw[[2L]], selected[[2L]])) ||
          (.dsvert_dp_capsule_reference_matches(raw[[1L]], selected[[2L]]) &&
           .dsvert_dp_capsule_reference_matches(raw[[2L]], selected[[1L]])))
      }, logical(1L)))
      if (!isTRUE(authorized)) {
        stop("The local Synopsis pair is not in the custodian catalog.",
             call. = FALSE)
      }
    }
  }
  local_peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  selected <- if (isTRUE(same_owner)) selected else cross_selected
  local_columns <- selected[vapply(selected, function(column) {
    identical(column$owner_peer, local_peer)
  }, logical(1L))]
  if (length(local_columns)) {
    local_datasets <- unique(vapply(
      local_columns, `[[`, character(1L), "dataset"))
    for (data_name in local_datasets) {
    descriptor <- policy$datasets[[data_name]]
    dataset <- schema$datasets[[data_name]]
    owned <- local_columns[vapply(local_columns, function(column) {
      identical(column$dataset, data_name)
    }, logical(1L))]
    if (!is.list(descriptor) ||
        !identical(descriptor$id, dataset$dataset_id) ||
        !identical(descriptor$version, dataset$dataset_version) ||
        !identical(dataset$patient_keys[[local_peer]],
                   policy$patient_column)) {
      stop("The projected dataset conflicts with its owner policy.",
           call. = FALSE)
    }
    for (column in owned) {
      physical <- column$column
      expected <- policy$categorical_levels[[physical]]
      if (is.null(expected) || !identical(
          sort(unname(expected), method = "radix"), column$levels)) {
        stop("A projected categorical domain conflicts with owner policy.",
             call. = FALSE)
      }
    }
    }
  }
  invisible(TRUE)
}

.dsvert_dp_capsule_specs <- function(value, what) {
  .dsvert_dp_capsule_named_list(value, what, empty = TRUE)
}

.dsvert_dp_capsule_gaussian_spec <- function(
    policy, analysis_id, specs, require_public_bounds = TRUE) {
  analysis_id <- .dsvert_dp_capsule_id(analysis_id, "Gaussian analysis id")
  raw <- specs[[analysis_id]]
  if (!is.list(raw) || is.null(names(raw)) || anyNA(names(raw)) ||
      anyDuplicated(names(raw)) || !is.character(raw$version) ||
      length(raw$version) != 1L || is.na(raw$version)) {
    stop("Invalid biomedical Gaussian specification.", call. = FALSE)
  }
  version <- .dsvert_dp_capsule_id(raw$version, "Gaussian version")
  dataset <- .dsvert_dp_capsule_id(raw$dataset, "Gaussian dataset")
  if (identical(version, "random_intercept_v1")) {
    expected <- c(
      "version", "dataset", "outcome", "cluster",
      "max_patients_per_cluster")
    if (!setequal(names(raw), expected)) {
      stop("Invalid random-intercept LMM specification.", call. = FALSE)
    }
    outcome <- .dsvert_dp_capsule_column_reference(
      raw$outcome, "LMM outcome")$reference
    cluster <- .dsvert_dp_capsule_column_reference(
      raw$cluster, "LMM cluster")$reference
    maximum <- raw$max_patients_per_cluster
    if (!is.numeric(maximum) || length(maximum) != 1L || is.na(maximum) ||
        !is.finite(maximum) || maximum != floor(maximum) || maximum < 2 ||
        maximum > policy$unit_capacity || identical(outcome, cluster)) {
      stop("Invalid random-intercept LMM model terms.", call. = FALSE)
    }
    if (!is.logical(require_public_bounds) ||
        length(require_public_bounds) != 1L || is.na(require_public_bounds)) {
      stop("Invalid Gaussian specification validation mode.", call. = FALSE)
    }
    if (isTRUE(require_public_bounds) &&
        (!dataset %in% names(policy$datasets) ||
         !outcome %in% names(policy$numeric_bounds) ||
         !cluster %in% names(policy$categorical_levels))) {
      stop("The random-intercept LMM specification lacks public bounds.",
           call. = FALSE)
    }
    return(list(
      version = version, dataset = dataset, outcome = outcome,
      cluster = cluster, max_patients_per_cluster = as.integer(maximum),
      kind = "random_intercept"))
  }
  expected <- c(
    "version", "dataset", "outcome", "predictors", "intercept")
  if (!setequal(names(raw), expected)) {
    stop("Invalid biomedical Gaussian specification.", call. = FALSE)
  }
  outcome <- .dsvert_dp_capsule_column_reference(
    raw$outcome, "Gaussian outcome")$reference
  predictors <- raw$predictors
  if (is.list(predictors) && is.null(names(predictors)) &&
      all(vapply(predictors, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value)
      }, logical(1L)))) {
    predictors <- unname(unlist(predictors, use.names = FALSE))
  }
  if (!is.character(predictors) || !length(predictors) ||
      !is.null(names(predictors)) || anyNA(predictors) ||
      anyDuplicated(predictors) || outcome %in% predictors ||
      !is.logical(raw$intercept) || length(raw$intercept) != 1L ||
      is.na(raw$intercept)) {
    stop("Invalid biomedical Gaussian model terms.", call. = FALSE)
  }
  predictors <- sort(vapply(predictors, function(value) {
    .dsvert_dp_capsule_column_reference(
      value, "Gaussian predictor")$reference
  }, character(1L)), method = "radix")
  variables <- c(outcome, predictors)
  if (!is.logical(require_public_bounds) ||
      length(require_public_bounds) != 1L || is.na(require_public_bounds)) {
    stop("Invalid Gaussian specification validation mode.", call. = FALSE)
  }
  if (isTRUE(require_public_bounds) &&
      (!dataset %in% names(policy$datasets) ||
       any(!variables %in% names(policy$numeric_bounds)))) {
    stop("The Gaussian specification lacks public numeric bounds.",
         call. = FALSE)
  }
  list(
    version = version, dataset = dataset, outcome = outcome,
    predictors = unname(predictors), intercept = isTRUE(raw$intercept),
    kind = "linear")
}

.dsvert_dp_capsule_qualified_columns <- function(schema) {
  result <- list()
  for (data_name in names(schema$datasets)) {
    dataset <- schema$datasets[[data_name]]
    for (reference in names(dataset$columns)) {
      column_name <- .dsvert_dp_capsule_column_reference(
        reference, "column name")$column
      result[[reference]] <- c(dataset$columns[[reference]], list(
        dataset = data_name, alignment_group = dataset$alignment_group,
        column = column_name))
    }
  }
  result[order(names(result), method = "radix")]
}

.dsvert_dp_capsule_pair_count <- function(columns) {
  n <- as.double(length(columns))
  if (n < 2L) return(0L)
  pairs <- n * (n - 1) / 2
  if (!is.finite(pairs) || pairs > .DSVERT_DP_MAX_COORDINATES) {
    stop("The biomedical capsule categorical-pair family exceeds the DP ",
         "coordinate limit.",
         call. = FALSE)
  }
  as.integer(pairs)
}

.dsvert_dp_capsule_pair_coordinates <- function(columns) {
  n <- length(columns)
  if (n < 2L) return(0L)
  total <- 0L
  for (left in seq_len(n - 1L)) {
    left_levels <- length(columns[[left]]$levels)
    for (right in seq.int(left + 1L, n)) {
      right_levels <- length(columns[[right]]$levels)
      if (left_levels > floor(
            .DSVERT_DP_MAX_COORDINATES / right_levels)) {
        stop("The biomedical capsule categorical-pair domain exceeds the DP ",
             "coordinate limit.",
             call. = FALSE)
      }
      total <- .dsvert_dp_capsule_coordinate_add(
        total, left_levels * right_levels)
    }
  }
  total
}

.dsvert_dp_capsule_vertical_specs <- function(value, columns) {
  value <- .dsvert_dp_capsule_specs(value, "vertical-cross specifications")
  result <- vector("list", length(value))
  names(result) <- names(value)
  for (name in names(value)) {
    .dsvert_dp_capsule_id(name, "vertical-cross id")
    spec <- value[[name]]
    expected <- c(
      "version", "left_dataset", "right_dataset", "left", "right",
      "family")
    if (!is.list(spec) || is.null(names(spec)) || anyNA(names(spec)) ||
        anyDuplicated(names(spec)) || !setequal(names(spec), expected)) {
      stop("Invalid biomedical vertical-cross specification.", call. = FALSE)
    }
    version <- .dsvert_dp_capsule_id(spec$version, "vertical-cross version")
    left_dataset <- .dsvert_dp_capsule_id(
      spec$left_dataset, "vertical-cross left dataset")
    right_dataset <- .dsvert_dp_capsule_id(
      spec$right_dataset, "vertical-cross right dataset")
    left <- .dsvert_dp_capsule_column_reference(
      spec$left, "vertical-cross left column")$reference
    right <- .dsvert_dp_capsule_column_reference(
      spec$right, "vertical-cross right column")$reference
    family <- spec$family
    if (!is.character(family) || length(family) != 1L || is.na(family) ||
        !family %in% c(
          "categorical_pair", "numeric_cross_moment",
        "numeric_by_category") || identical(left, right) ||
        is.null(columns[[left]]) || is.null(columns[[right]]) ||
        !identical(columns[[left]]$dataset, left_dataset) ||
        !identical(columns[[right]]$dataset, right_dataset) ||
        !identical(columns[[left]]$alignment_group,
                   columns[[right]]$alignment_group) ||
        identical(columns[[left]]$owner_peer,
                  columns[[right]]$owner_peer)) {
      stop("Invalid biomedical vertical-cross ownership.", call. = FALSE)
    }
    kinds <- sort(c(columns[[left]]$kind, columns[[right]]$kind),
                  method = "radix")
    expected_kinds <- switch(family,
      categorical_pair = c("categorical", "categorical"),
      numeric_cross_moment = c("numeric", "numeric"),
      numeric_by_category = c("categorical", "numeric"))
    if (!identical(kinds, expected_kinds)) {
      stop("The biomedical vertical-cross family and column kinds disagree.",
           call. = FALSE)
    }
    references <- c(
      paste(columns[[left]]$owner_peer, left_dataset,
            columns[[left]]$column, sep = "::"),
      paste(columns[[right]]$owner_peer, right_dataset,
            columns[[right]]$column, sep = "::"))
    order_index <- order(references, method = "radix")
    side_columns <- c(left, right)[order_index]
    side_datasets <- c(left_dataset, right_dataset)[order_index]
    result[[name]] <- .dsvert_dp_canonical_query_value(list(
      version = version,
      alignment_group = columns[[left]]$alignment_group,
      family = family,
      left_dataset = side_datasets[[1L]], left = side_columns[[1L]],
      right_dataset = side_datasets[[2L]], right = side_columns[[2L]],
      left_owner = columns[[side_columns[[1L]]]]$owner_peer,
      right_owner = columns[[side_columns[[2L]]]]$owner_peer,
      implementation_state = "reserved_not_materialized"))
  }
  result
}

.dsvert_dp_capsule_scope_columns <- function(
    value, columns, kind, what) {
  if (is.null(value)) value <- character()
  if (!is.character(value) || anyNA(value) ||
      (!is.null(names(value)) && length(value))) {
    stop("Invalid biomedical capsule ", what, " catalog.",
         call. = FALSE)
  }
  value <- sort(unique(vapply(
    unname(value), .dsvert_dp_capsule_id, character(1L),
    what = paste(what, "column"))), method = "radix")
  if (any(!value %in% names(columns)) || any(vapply(
        columns[value], `[[`, character(1L), "kind") != kind)) {
    stop("The biomedical capsule ", what,
         " catalog conflicts with the signed schema.", call. = FALSE)
  }
  value
}

.dsvert_dp_capsule_scope_pairs <- function(
    value, columns, kind, what) {
  if (is.null(value)) value <- list()
  if (!is.list(value) || (!is.null(names(value)) && length(value))) {
    stop("Invalid biomedical capsule ", what, " catalog.",
         call. = FALSE)
  }
  normalized <- lapply(value, function(pair) {
    if (is.list(pair) && is.null(names(pair))) {
      pair <- unname(unlist(pair, use.names = FALSE))
    }
    if (!is.character(pair) || length(pair) != 2L || anyNA(pair) ||
        !is.null(names(pair))) {
      stop("Invalid biomedical capsule ", what, " pair.",
           call. = FALSE)
    }
    pair <- sort(vapply(
      pair, .dsvert_dp_capsule_id, character(1L),
      what = paste(what, "column")), method = "radix")
    left <- columns[[pair[[1L]]]]
    right <- columns[[pair[[2L]]]]
    if (identical(pair[[1L]], pair[[2L]]) || is.null(left) ||
        is.null(right) || !identical(left$kind, kind) ||
        !identical(right$kind, kind) ||
        !identical(left$dataset, right$dataset) ||
        !identical(left$owner_peer, right$owner_peer)) {
      stop("The biomedical capsule ", what,
           " pair must be same-owner and same-dataset in the signed schema.",
           call. = FALSE)
    }
    unname(pair)
  })
  if (!length(normalized)) return(list())
  keys <- vapply(normalized, function(pair) {
    .dsvert_dp_canonical_json(as.list(pair))
  }, character(1L))
  normalized <- normalized[!duplicated(keys)]
  keys <- keys[!duplicated(keys)]
  normalized[order(keys, method = "radix")]
}

.dsvert_dp_capsule_scope_all_pairs <- function(columns) {
  result <- list()
  groups <- split(names(columns), vapply(columns, function(column) {
    .dsvert_joint_dp_hash(list(
      dataset = column$dataset, owner_peer = column$owner_peer))
  }, character(1L)))
  for (group in groups) {
    group <- sort(unname(group), method = "radix")
    if (length(group) < 2L) next
    for (left in seq_len(length(group) - 1L)) {
      for (right in seq.int(left + 1L, length(group))) {
        result[[length(result) + 1L]] <- c(group[[left]], group[[right]])
      }
    }
  }
  result
}

.dsvert_dp_capsule_scope_policy_binding <- function(value) {
  if (is.null(value)) value <- list(mode = "all_schema")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !is.character(value$mode) ||
      length(value$mode) != 1L || is.na(value$mode) ||
      !value$mode %in% c("all_schema", "catalog_v1")) {
    stop("Invalid custodian-owned biomedical capsule workload scope.",
         call. = FALSE)
  }
  if (identical(value$mode, "all_schema")) {
    if (!setequal(names(value), "mode")) {
      stop("Invalid custodian-owned biomedical capsule workload scope.",
           call. = FALSE)
    }
    return(list(mode = "all_schema"))
  }
  fields <- c(
    "mode", "numeric_moments", "categorical_marginals",
    "categorical_pairs", "correlations")
  if (!setequal(names(value), fields)) {
    stop("Invalid custodian-owned biomedical capsule workload scope.",
         call. = FALSE)
  }
  normalize_columns <- function(columns, what) {
    if (is.null(columns)) columns <- character()
    if (!is.character(columns) || anyNA(columns) ||
        (!is.null(names(columns)) && length(columns))) {
      stop("Invalid biomedical capsule ", what, " catalog.",
           call. = FALSE)
    }
    sort(unique(vapply(
      unname(columns), .dsvert_dp_capsule_id, character(1L),
      what = paste(what, "column"))), method = "radix")
  }
  normalize_pairs <- function(pairs, what) {
    if (is.null(pairs)) pairs <- list()
    if (!is.list(pairs) || (!is.null(names(pairs)) && length(pairs))) {
      stop("Invalid biomedical capsule ", what, " catalog.",
           call. = FALSE)
    }
    pairs <- lapply(pairs, function(pair) {
      if (is.list(pair) && is.null(names(pair))) {
        pair <- unname(unlist(pair, use.names = FALSE))
      }
      if (!is.character(pair) || length(pair) != 2L || anyNA(pair) ||
          !is.null(names(pair))) {
        stop("Invalid biomedical capsule ", what, " pair.",
             call. = FALSE)
      }
      unname(sort(vapply(
        pair, .dsvert_dp_capsule_id, character(1L),
        what = paste(what, "column")), method = "radix"))
    })
    if (!length(pairs)) return(list())
    keys <- vapply(pairs, function(pair) {
      .dsvert_dp_canonical_json(as.list(pair))
    }, character(1L))
    pairs <- pairs[!duplicated(keys)]
    keys <- keys[!duplicated(keys)]
    unname(pairs[order(keys, method = "radix")])
  }
  list(
    mode = "catalog_v1",
    numeric_moments = normalize_columns(
      value$numeric_moments, "numeric-moment"),
    categorical_marginals = normalize_columns(
      value$categorical_marginals, "categorical-marginal"),
    categorical_pairs = normalize_pairs(
      value$categorical_pairs, "categorical-pair"),
    correlations = normalize_pairs(value$correlations, "correlation"))
}

.dsvert_dp_capsule_workload_scope <- function(
    value, columns, global_policy, describe_specs, survival_specs,
    gaussian_specs, configured_vertical) {
  value <- .dsvert_dp_capsule_scope_policy_binding(value)
  mode <- value$mode

  all_numeric <- columns[vapply(
    columns, `[[`, character(1L), "kind") == "numeric"]
  all_categorical <- columns[vapply(
    columns, `[[`, character(1L), "kind") == "categorical"]
  explicit_numeric <- explicit_categorical <- character()
  explicit_categorical_pairs <- explicit_correlations <- list()
  if (identical(mode, "catalog_v1")) {
    explicit_numeric <- .dsvert_dp_capsule_scope_columns(
      value$numeric_moments, columns, "numeric", "numeric-moment")
    explicit_categorical <- .dsvert_dp_capsule_scope_columns(
      value$categorical_marginals, columns, "categorical",
      "categorical-marginal")
    explicit_categorical_pairs <- .dsvert_dp_capsule_scope_pairs(
      value$categorical_pairs, columns, "categorical",
      "categorical-pair")
    explicit_correlations <- .dsvert_dp_capsule_scope_pairs(
      value$correlations, columns, "numeric", "correlation")
  }

  referenced_numeric <- referenced_categorical <- character()
  reference <- function(variable) {
    column <- columns[[variable]]
    if (is.null(column)) {
      stop("A signed workload specification references an unknown column.",
           call. = FALSE)
    }
    if (identical(column$kind, "numeric")) {
      referenced_numeric <<- c(referenced_numeric, variable)
    } else {
      referenced_categorical <<- c(referenced_categorical, variable)
    }
  }
  for (analysis_id in names(describe_specs)) {
    raw <- describe_specs[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- .dsvert_dp_describe_spec(
      global_policy, data_name, analysis_id, specs = describe_specs)
    lapply(spec$variables, reference)
  }
  for (analysis_id in names(survival_specs)) {
    raw <- survival_specs[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- .dsvert_dp_survival_spec(
      global_policy, data_name, analysis_id, specs = survival_specs)
    variables <- c(spec$time, spec$event, spec$entry)
    lapply(variables[!vapply(variables, is.null, logical(1L))], reference)
  }
  for (analysis_id in names(gaussian_specs)) {
    spec <- .dsvert_dp_capsule_gaussian_spec(
      global_policy, analysis_id, gaussian_specs)
    lapply(c(spec$outcome, spec$predictors), reference)
  }
  for (analysis_id in names(configured_vertical)) {
    spec <- configured_vertical[[analysis_id]]
    reference(spec$left)
    reference(spec$right)
  }
  referenced_numeric <- sort(unique(referenced_numeric), method = "radix")
  referenced_categorical <- sort(
    unique(referenced_categorical), method = "radix")

  if (identical(mode, "all_schema")) {
    numeric <- names(all_numeric)
    categorical <- names(all_categorical)
    categorical_pairs <- .dsvert_dp_capsule_scope_all_pairs(all_categorical)
    correlations <- .dsvert_dp_capsule_scope_all_pairs(all_numeric)
  } else {
    categorical_pairs <- explicit_categorical_pairs
    correlations <- explicit_correlations
    numeric <- c(
      explicit_numeric, referenced_numeric,
      unlist(correlations, use.names = FALSE))
    categorical <- c(
      explicit_categorical, referenced_categorical,
      unlist(categorical_pairs, use.names = FALSE))
    numeric <- sort(unique(numeric), method = "radix")
    categorical <- sort(unique(categorical), method = "radix")
  }
  list(
    mode = mode,
    numeric_moments = unname(numeric),
    categorical_marginals = unname(categorical),
    categorical_pairs = unname(categorical_pairs),
    correlations = unname(correlations),
    explicit_catalog = list(
      numeric_moments = unname(explicit_numeric),
      categorical_marginals = unname(explicit_categorical),
      categorical_pairs = unname(explicit_categorical_pairs),
      correlations = unname(explicit_correlations)),
    referenced_by_signed_specs = list(
      numeric = unname(referenced_numeric),
      categorical = unname(referenced_categorical),
      describe = unname(names(describe_specs)),
      survival = unname(names(survival_specs)),
      gaussian = unname(names(gaussian_specs)),
      vertical_cross = unname(names(configured_vertical))))
}

.dsvert_dp_capsule_workload_require_materializable <- function(manifest) {
  workload <- if (is.list(manifest)) manifest$workload else NULL
  valid <- is.list(manifest) &&
    identical(manifest$version, .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) &&
    identical(manifest$capsule_schema,
              .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) &&
    identical(manifest$execution_state,
              .DSVERT_DP_CAPSULE_EXECUTION_STATE) &&
    is.list(workload) &&
    identical(workload$workload_version,
              .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) &&
    identical(workload$execution_state,
              .DSVERT_DP_CAPSULE_EXECUTION_STATE) &&
    identical(workload$declared_workload_fully_materialized, TRUE) &&
    identical(workload$package_family_coverage_complete, FALSE) &&
    identical(workload$registered_release_lifecycle,
              .dsvert_dp_capsule_registered_release_lifecycle())
  if (!isTRUE(valid)) {
    stop("The biomedical capsule is not bound to the registered release lifecycle.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_capsule_workload_manifest <- function(
    policy, logical_snapshot, schema_manifest,
    describe_specs = .dsvert_dp_option("describe_specs", list()),
    survival_specs = .dsvert_dp_option("survival_specs", list()),
    gaussian_specs = .dsvert_dp_option("gaussian_specs", list()),
    vertical_cross_specs = .dsvert_dp_option("vertical_cross_specs", list()),
    .signature_verifier = .dsvert_relay_verify_message,
    .noise_selector = .dsvert_dp_noise_selection,
    .gaussian_planner = NULL, .primitive_scope = NULL) {
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(logical_snapshot)
  synopsis_policy <- .dsvert_dp_synopsis_policy_is_v1(policy)
  policy_context <- if (isTRUE(synopsis_policy)) {
    .dsvert_dp_synopsis_policy_context_v1(policy)
  } else {
    .dsvert_joint_dp_policy_context(policy, require_designated = FALSE)
  }
  signed <- .dsvert_dp_capsule_schema(
    policy, logical_snapshot, schema_manifest, .signature_verifier)
  schema <- signed$unsigned
  if (is.null(.primitive_scope)) {
    .dsvert_dp_capsule_validate_local_schema(policy, schema)
  } else {
    .dsvert_dp_capsule_validate_local_projection_schema(
      policy, schema, .primitive_scope)
  }
  columns <- .dsvert_dp_capsule_qualified_columns(schema)

  all_numeric_columns <- columns[vapply(
    columns, `[[`, character(1L), "kind") == "numeric"]
  all_categorical_columns <- columns[vapply(
    columns, `[[`, character(1L), "kind") == "categorical"]
  global_policy <- policy
  # Workload specifications and primitive scope are custodian metadata.  They
  # are normalized before any protected snapshot can be resolved.
  global_policy$datasets <- schema$datasets
  global_policy$numeric_bounds <- lapply(
    all_numeric_columns, function(column) c(column$lower, column$upper))
  global_policy$categorical_levels <- lapply(
    all_categorical_columns, `[[`, "levels")
  describe_specs <- .dsvert_dp_capsule_specs(
    describe_specs, "describe specifications")
  survival_specs <- .dsvert_dp_capsule_specs(
    survival_specs, "survival specifications")
  gaussian_specs <- .dsvert_dp_capsule_specs(
    gaussian_specs, "Gaussian specifications")
  configured_vertical <- .dsvert_dp_capsule_vertical_specs(
    vertical_cross_specs, columns)
  scope_policy <- if (is.null(.primitive_scope)) {
    policy$capsule_workload_scope
  } else {
    .dsvert_dp_capsule_scope_policy_binding(.primitive_scope)
  }
  primitive_scope <- .dsvert_dp_capsule_workload_scope(
    scope_policy, columns, global_policy,
    describe_specs, survival_specs, gaussian_specs, configured_vertical)
  numeric_columns <- all_numeric_columns[
    primitive_scope$numeric_moments]
  categorical_columns <- all_categorical_columns[
    primitive_scope$categorical_marginals]
  grid_bits <- policy$numeric_grid_bits
  if (!is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("The biomedical capsule numeric grid is invalid.", call. = FALSE)
  }
  grid_bits <- as.integer(grid_bits)
  grid_scale <- 2^grid_bits
  capacity <- policy$unit_capacity
  if (!is.numeric(capacity) || length(capacity) != 1L || is.na(capacity) ||
      !is.finite(capacity) || capacity < 1 || capacity != floor(capacity) ||
      capacity > .DSVERT_DP_MAX_COORDINATES ||
      capacity > floor(.dsvert_dp_exact_integer_limit / grid_scale)) {
    stop("The biomedical capsule capacity is not representable.",
         call. = FALSE)
  }
  capacity <- as.integer(capacity)
  adjacency_multiplier <- .dsvert_dp_adjacency_multiplier(policy)
  admission <- .dsvert_dp_admission_public(policy)

  coordinate_count <- 0L
  sensitivity <- list(l1 = 0, l2_squared = 0)
  lattice_sensitivity <- list(l1 = 0, l2_squared = 0)
  add_family <- function(count, l1, l2,
                         lattice_l1 = l1, lattice_l2 = l2) {
    coordinate_count <<- .dsvert_dp_capsule_coordinate_add(
      coordinate_count, count)
    sensitivity <<- .dsvert_dp_capsule_sensitivity_add(
      sensitivity, l1, l2)
    lattice_sensitivity <<- .dsvert_dp_capsule_sensitivity_add(
      lattice_sensitivity, lattice_l1, lattice_l2)
  }

  count_owners <- sort(unique(unlist(lapply(
    schema$datasets, function(dataset) names(dataset$patient_keys)),
    use.names = FALSE)), method = "radix")
  count_owner <- count_owners[[1L]]
  count_datasets <- names(schema$datasets)[vapply(
    schema$datasets, function(dataset) {
      count_owner %in% names(dataset$patient_keys)
    }, logical(1L))]
  count_dataset <- sort(count_datasets, method = "radix")[[1L]]
  count_sensitivity <- if (identical(
      policy$adjacency, "replace_one_fixed_cohort")) 0 else 1
  count_family <- list(
    version = "admitted-unit-count-v2", coordinate_count = 1L,
    owner_peer = count_owner, dataset = count_dataset,
    contribution_semantics =
      "canonical_owner_canonical_dataset_admitted_units_only",
    statistic_minimum = 0, statistic_maximum = capacity,
    l1_sensitivity = count_sensitivity,
    l2_sensitivity = count_sensitivity)
  add_family(1L, count_family$l1_sensitivity, count_family$l2_sensitivity)

  numeric_artifacts <- lapply(numeric_columns, function(column) list(
    dataset = column$dataset, column = column$column,
    owner_peer = column$owner_peer, lower = column$lower,
    upper = column$upper, numeric_grid_bits = grid_bits,
    repeated_record_policy =
      "clip_finite_rows_then_mean_once_per_admitted_unit_v1",
    missingness_policy =
      "NA_NaN_Inf_have_no_numeric_value_finite_out_of_bounds_clip",
    count_semantics = "finite_admitted_unit_count_for_this_column",
    statistic_maximum = c(capacity, capacity * grid_scale,
                          capacity * grid_scale)))
  numeric_coordinate_count <- 3 * as.double(length(numeric_artifacts))
  numeric_l1 <- length(numeric_artifacts) *
    (1 + 2 * grid_scale)
  numeric_per_column_l2_squared <- .dsvert_dp_capsule_l2_add(
    1, .dsvert_dp_capsule_l2_multiply(
      2, .dsvert_dp_capsule_l2_square(grid_scale)))
  numeric_l2 <- .dsvert_dp_capsule_l2_sqrt(
    .dsvert_dp_capsule_l2_multiply(
      length(numeric_artifacts), numeric_per_column_l2_squared))
  numeric_lattice_l1 <- 3 * length(numeric_artifacts)
  numeric_lattice_l2 <- .dsvert_dp_capsule_l2_sqrt(
    .dsvert_dp_capsule_l2_multiply(3, length(numeric_artifacts)))
  add_family(
    numeric_coordinate_count, numeric_l1, numeric_l2,
    lattice_l1 = numeric_lattice_l1,
    lattice_l2 = numeric_lattice_l2)

  # Pairwise-complete bivariate moments are materialised only when both
  # variables belong to the same signed dataset and owner.  Each complete unit
  # contributes (1, x, y, x^2, y^2, xy) on [0,1]^2.  A missing pair contributes
  # the zero vector, so zero versus (1,1,1,1,1,1) is a valid worst-case
  # neighbour under both supported adjacency models.  Consequently the tight
  # per-pair natural L1/L2 bounds are 6 and sqrt(6), rather than an automatic
  # replace-one factor of two.
  numeric_pair_artifacts <- correlation_artifacts <- list()
  numeric_pair_coordinate_count <- 0L
  numeric_pair_count <- 0
  numeric_pair_raw_l1 <- numeric_pair_raw_l2_squared <- 0
  numeric_pair_per_raw_l2_squared <- .dsvert_dp_capsule_l2_add(
    1, .dsvert_dp_capsule_l2_multiply(
      5, .dsvert_dp_capsule_l2_square(grid_scale)))
  correlation_pair_keys <- if (length(primitive_scope$correlations)) {
    vapply(primitive_scope$correlations, function(pair) {
      .dsvert_dp_canonical_json(as.list(pair))
    }, character(1L))
  } else {
    character()
  }
  for (data_name in sort(names(schema$datasets), method = "radix")) {
    dataset_numeric <- numeric_columns[vapply(
      numeric_columns, function(column) {
        identical(column$dataset, data_name)
      }, logical(1L))]
    owners <- sort(unique(vapply(
      dataset_numeric, `[[`, character(1L), "owner_peer")),
      method = "radix")
    for (owner in owners) {
      owned <- dataset_numeric[vapply(
        dataset_numeric, function(column) {
          identical(column$owner_peer, owner)
        }, logical(1L))]
      if (length(owned) < 2L) next
      owned <- owned[order(vapply(
        owned, `[[`, character(1L), "column"), method = "radix")]
      analysis_id <- paste(data_name, owner, sep = "::")
      pair_references <- selected_variables <- character()
      for (left_index in seq_len(length(owned) - 1L)) {
        for (right_index in seq.int(left_index + 1L, length(owned))) {
          left <- owned[[left_index]]
          right <- owned[[right_index]]
          pair_key <- .dsvert_dp_canonical_json(as.list(c(
            left$column, right$column)))
          if (!pair_key %in% correlation_pair_keys) next
          descriptor <- list(
            version = "pairwise-complete-normalized-moments-v1",
            analysis_id = analysis_id,
            dataset = data_name, owner_peer = owner,
            left = list(
              column = left$column, lower = left$lower,
              upper = left$upper),
            right = list(
              column = right$column, lower = right$lower,
              upper = right$upper),
            numeric_grid_bits = grid_bits,
            coordinate_count = 6L,
            coordinate_order = paste(
              "count,quantized_sum_left,quantized_sum_right,",
              "quantized_sumsq_left,quantized_sumsq_right,",
              "quantized_cross_product", sep = ""),
            repeated_record_policy = paste(
              "clip_finite_rows_then_mean_each_variable_once_per_",
              "admitted_unit_v1", sep = ""),
            missingness_policy =
              "pairwise_complete_units_with_both_collapsed_values_v1",
            statistic_maximum = c(
              capacity, rep(capacity * grid_scale, 5L)),
            source_raw_l1_sensitivity = 1 + 5 * grid_scale,
            source_raw_l2_sensitivity =
              .dsvert_dp_capsule_l2_sqrt(
                numeric_pair_per_raw_l2_squared),
            natural_l1_sensitivity = 6,
            natural_l2_sensitivity =
              .dsvert_dp_capsule_l2_sqrt(6),
            adjacency = policy$adjacency,
            adjacency_sensitivity_basis = paste(
              "zero_missing_pair_vs_complete_unit_is_worst_case_for_",
              "add_remove_and_replace_one", sep = ""))
          artifact_id <- .dsvert_joint_dp_hash(list(
            family = "numeric_pair_moments", descriptor = descriptor))
          if (!is.null(numeric_pair_artifacts[[artifact_id]])) {
            stop("The numeric-pair capsule artifact id collided.",
                 call. = FALSE)
          }
          numeric_pair_artifacts[[artifact_id]] <- descriptor
          pair_references <- c(pair_references, artifact_id)
          selected_variables <- c(
            selected_variables, left$column, right$column)
          numeric_pair_coordinate_count <-
            .dsvert_dp_capsule_coordinate_add(
              numeric_pair_coordinate_count, 6L)
          numeric_pair_count <- numeric_pair_count + 1
          numeric_pair_raw_l1 <- numeric_pair_raw_l1 + 1 + 5 * grid_scale
          numeric_pair_raw_l2_squared <- .dsvert_dp_capsule_l2_add(
            numeric_pair_raw_l2_squared,
            numeric_pair_per_raw_l2_squared)
          if (!is.finite(numeric_pair_raw_l1) ||
              !is.finite(numeric_pair_raw_l2_squared) ||
              numeric_pair_raw_l1 > .dsvert_dp_exact_integer_limit ||
              numeric_pair_raw_l2_squared >
                .dsvert_dp_exact_integer_limit^2) {
            stop("The numeric-pair capsule sensitivity is not representable.",
                 call. = FALSE)
          }
        }
      }
      if (!length(pair_references)) next
      correlation_artifacts[[analysis_id]] <- list(
        version = "same-owner-pairwise-correlation-artifact-v1",
        analysis_id = analysis_id, dataset = data_name, owner_peer = owner,
        variables = unname(sort(
          unique(selected_variables), method = "radix")),
        pair_references = unname(pair_references),
        pair_count = as.integer(length(pair_references)),
        coordinate_count = as.integer(6L * length(pair_references)),
        implementation_state = "same_owner_materialized",
        cross_owner_state = "reserved_not_materialized")
    }
  }
  if (length(numeric_pair_artifacts)) {
    numeric_pair_artifacts <- numeric_pair_artifacts[
      order(names(numeric_pair_artifacts), method = "radix")]
  }
  if (length(correlation_artifacts)) {
    correlation_artifacts <- correlation_artifacts[
      order(names(correlation_artifacts), method = "radix")]
  }
  numeric_pair_l2 <- .dsvert_dp_capsule_l2_sqrt(
    numeric_pair_raw_l2_squared)
  numeric_pair_natural_l1 <- 6 * numeric_pair_count
  numeric_pair_natural_l2 <- .dsvert_dp_capsule_l2_sqrt(
    .dsvert_dp_capsule_l2_multiply(6, numeric_pair_count))
  add_family(
    numeric_pair_coordinate_count,
    numeric_pair_raw_l1, numeric_pair_l2,
    lattice_l1 = numeric_pair_natural_l1,
    lattice_l2 = numeric_pair_natural_l2)

  marginal_coordinate_count <- sum(vapply(
    categorical_columns, function(column) length(column$levels), numeric(1L)))
  marginal_l1 <- length(categorical_columns) * adjacency_multiplier
  marginal_l2 <- .dsvert_dp_capsule_l2_sqrt(
    .dsvert_dp_capsule_l2_multiply(
      length(categorical_columns), adjacency_multiplier))
  add_family(marginal_coordinate_count, marginal_l1, marginal_l2)
  marginal_artifacts <- lapply(categorical_columns, function(column) list(
    dataset = column$dataset, column = column$column,
    owner_peer = column$owner_peer, levels = column$levels,
    repeated_record_policy = "consistent_level_else_exclude_v1",
    missingness_policy = "missing_or_out_of_domain_rows_are_ignored",
    statistic_maximum = capacity))

  pair_sets <- vertical_pair_sets <- cross_owner_sets <- list()
  pair_coordinate_count <- 0L
  pair_count_total <- 0
  for (data_name in names(schema$datasets)) {
    dataset_categories <- categorical_columns[vapply(
      categorical_columns, function(column) {
        identical(column$dataset, data_name)
      }, logical(1L))]
    owners <- sort(unique(vapply(
      dataset_categories, `[[`, character(1L), "owner_peer")),
      method = "radix")
    for (owner in owners) {
      owned <- dataset_categories[vapply(
        dataset_categories, function(column) {
          identical(column$owner_peer, owner)
        }, logical(1L))]
      owned_names <- names(owned)
      selected_pairs <- primitive_scope$categorical_pairs[vapply(
        primitive_scope$categorical_pairs, function(pair) {
          all(pair %in% owned_names)
        }, logical(1L))]
      pair_count <- length(selected_pairs)
      if (pair_count > 0) {
        included_names <- sort(unique(unlist(
          selected_pairs, use.names = FALSE)), method = "radix")
        owned <- owned[included_names]
        pair_coordinates <- 0L
        for (pair in selected_pairs) {
          left_levels <- length(owned[[pair[[1L]]]]$levels)
          right_levels <- length(owned[[pair[[2L]]]]$levels)
          if (left_levels > floor(
                .DSVERT_DP_MAX_COORDINATES / right_levels)) {
            stop("The biomedical capsule categorical-pair domain exceeds the DP coordinate limit.",
                 call. = FALSE)
          }
          pair_coordinates <- .dsvert_dp_capsule_coordinate_add(
            pair_coordinates, left_levels * right_levels)
        }
        key <- paste(data_name, owner, sep = "::")
        pair_sets[[key]] <- list(
          dataset = data_name, owner_peer = owner,
          columns = lapply(owned, function(column) list(
            column = column$column, levels = column$levels)),
          included_pairs = lapply(selected_pairs, unname),
          repeated_record_policy =
            "consistent_joint_cell_else_exclude_v1",
          missingness_policy =
            "missing_or_out_of_domain_rows_are_ignored",
          coordinate_count = pair_coordinates,
          pair_count = as.integer(pair_count),
          statistic_maximum = capacity)
        add_family(
          pair_coordinates,
          pair_count * adjacency_multiplier,
          .dsvert_dp_capsule_l2_sqrt(
            .dsvert_dp_capsule_l2_multiply(
              pair_count, adjacency_multiplier)))
        pair_coordinate_count <- .dsvert_dp_capsule_coordinate_add(
          pair_coordinate_count, pair_coordinates)
        pair_count_total <- pair_count_total + pair_count
      }
    }
  }

  if (identical(primitive_scope$mode, "all_schema")) {
    alignment_groups <- sort(unique(vapply(
      schema$datasets, `[[`, character(1L), "alignment_group")),
      method = "radix")
    for (alignment_group in alignment_groups) {
    aligned <- columns[vapply(columns, function(column) {
      identical(column$alignment_group, alignment_group)
    }, logical(1L))]
    owners <- sort(unique(vapply(
      aligned, `[[`, character(1L), "owner_peer")), method = "radix")
    if (length(owners) < 2L) next
    for (left_index in seq_len(length(owners) - 1L)) {
      for (right_index in seq.int(left_index + 1L, length(owners))) {
        left_owner <- owners[[left_index]]
        right_owner <- owners[[right_index]]
        left <- aligned[vapply(aligned, function(column) {
          identical(column$owner_peer, left_owner)
        }, logical(1L))]
        right <- aligned[vapply(aligned, function(column) {
          identical(column$owner_peer, right_owner)
        }, logical(1L))]
        left_public <- lapply(left, function(column) list(
          dataset = column$dataset, column = column$column,
          kind = column$kind))
        right_public <- lapply(right, function(column) list(
          dataset = column$dataset, column = column$column,
          kind = column$kind))
        left_numeric <- left[vapply(
          left, `[[`, character(1L), "kind") == "numeric"]
        right_numeric <- right[vapply(
          right, `[[`, character(1L), "kind") == "numeric"]
        left_categorical <- left[vapply(
          left, `[[`, character(1L), "kind") == "categorical"]
        right_categorical <- right[vapply(
          right, `[[`, character(1L), "kind") == "categorical"]
        required_families <- "aligned_iterative_model_cross_terms"
        if (length(left_numeric) && length(right_numeric)) {
          required_families <- c(
            required_families,
            "numeric_cross_products_for_correlation_and_components")
        }
        if ((length(left_numeric) && length(right_categorical)) ||
            (length(left_categorical) && length(right_numeric))) {
          required_families <- c(
            required_families, "numeric_by_category_cross_summaries")
        }
        projected <- 0L
        if (length(left_categorical) && length(right_categorical)) {
          required_families <- c(
            required_families, "categorical_cross_tables")
          for (left_column in left_categorical) {
            for (right_column in right_categorical) {
              projected <- .dsvert_dp_capsule_coordinate_add(
                projected,
                as.double(length(left_column$levels)) *
                  as.double(length(right_column$levels)))
            }
          }
        }
        key <- paste(
          alignment_group, left_owner, right_owner, sep = "::")
        cross_owner_sets[[key]] <- list(
          alignment_group = alignment_group,
          left_owner = left_owner, right_owner = right_owner,
          left_columns = left_public, right_columns = right_public,
          required_families = sort(unique(required_families),
                                   method = "radix"),
          implementation_state = "reserved_not_materialized")
        if (projected > 0L) {
          vertical_pair_sets[[key]] <- list(
            alignment_group = alignment_group,
            left_owner = left_owner, right_owner = right_owner,
            left_columns = names(left_categorical),
            right_columns = names(right_categorical),
            projected_coordinate_count = projected,
            included_coordinate_count = 0L,
            implementation_state = "reserved_not_materialized")
        }
      }
    }
    }
  }

  gaussian_artifacts <- vector("list", length(gaussian_specs))
  names(gaussian_artifacts) <- names(gaussian_specs)
  gaussian_coordinate_count <- gaussian_raw_l1 <-
    gaussian_natural_l1 <- 0
  gaussian_raw_l2_squared <- gaussian_natural_l2_squared <- 0
  for (analysis_id in names(gaussian_specs)) {
    spec <- .dsvert_dp_capsule_gaussian_spec(
      global_policy, analysis_id, gaussian_specs)
    if (identical(spec$kind, "random_intercept")) {
      variables <- c(spec$outcome, spec$cluster)
      model_columns <- columns[variables]
      owners <- unique(vapply(
        model_columns, `[[`, character(1L), "owner_peer"))
      datasets <- vapply(model_columns, `[[`, character(1L), "dataset")
      kinds <- vapply(model_columns, `[[`, character(1L), "kind")
      if (!identical(unname(kinds), c("numeric", "categorical")) ||
          length(owners) != 1L || length(unique(datasets)) != 1L ||
          !identical(datasets[[1L]], spec$dataset)) {
        stop("A random-intercept LMM specification must be same-owner with a numeric outcome and categorical cluster.",
             call. = FALSE)
      }
      cluster_capacity <- as.integer(spec$max_patients_per_cluster)
      base_raw_l1 <- 2 * cluster_capacity + 2 + 3 * grid_scale
      base_raw_l2 <- .dsvert_dp_capsule_l2_sqrt(
        .dsvert_dp_capsule_l2_add(
          .dsvert_dp_capsule_l2_add(
            .dsvert_dp_capsule_l2_add(
              2,
              .dsvert_dp_capsule_l2_square(2 * cluster_capacity - 1)),
            .dsvert_dp_capsule_l2_multiply(2, grid_scale^2)),
          (grid_scale + 1)^2))
      adjacency_multiplier <- .dsvert_dp_adjacency_multiplier(global_policy)
      raw_l1 <- adjacency_multiplier * base_raw_l1
      raw_l2 <- adjacency_multiplier * base_raw_l2
      natural_l1 <- raw_l1 / grid_scale
      natural_l2 <- raw_l2 / grid_scale
      model_coordinate_count <- 6L
      outcome <- columns[[spec$outcome]]
      cluster <- columns[[spec$cluster]]
      gaussian_artifacts[[analysis_id]] <- list(
        version = "bounded-normalized-random-intercept-moments-v1",
        spec_version = spec$version, analysis_id = analysis_id,
        dataset = spec$dataset, owner_peer = owners[[1L]],
        outcome = list(
          column = outcome$column, lower = outcome$lower,
          upper = outcome$upper),
        cluster = list(column = cluster$column, levels = cluster$levels),
        observation_capacity = as.integer(capacity),
        max_patients_per_cluster = cluster_capacity,
        numeric_grid_bits = grid_bits,
        coordinate_count = model_coordinate_count,
        coordinate_order = paste(
          "n_then_cluster_count_then_cluster_size_sq_then_quantized_sum_y",
          "then_quantized_sum_y_sq_then_quantized_cluster_mean_sq_v1",
          sep = "_"),
        source_coordinate_scaling =
          "three_counts_then_three_common_lattice_moments_v1",
        repeated_record_policy = paste(
          "clip_finite_outcome_then_mean_once_per_admitted_patient_and",
          "require_one_consistent_public_cluster_level_v1", sep = "_"),
        missingness_policy = paste(
          "missing_or_nonfinite_outcome_or_missing_or_inconsistent_cluster",
          "excludes_the_patient_from_all_six_coordinates_v1", sep = "_"),
        contribution_domain = paste(
          "one_bounded_patient_outcome_and_one_consistent_cluster_level",
          "with_public_cluster_size_cap_v1", sep = "_"),
        statistic_maximum = c(
          capacity, capacity, capacity * cluster_capacity,
          rep(capacity * grid_scale, 3L)),
        source_raw_l1_sensitivity = raw_l1,
        source_raw_l2_sensitivity = raw_l2,
        natural_l1_sensitivity = natural_l1,
        natural_l2_sensitivity = natural_l2,
        adjacency = global_policy$adjacency,
        adjacency_sensitivity_basis = paste(
          "one_patient_changes_three_counts_by_1_1_and_at_most",
          "2C_minus_1_and_three_quantized_moments_by_S_S_and_S_plus_1",
          "with_replace_one_as_two_add_remove_changes_v1", sep = "_"),
        estimation_scope =
          "bounded_random_intercept_method_of_moments_no_fixed_covariates_v1",
        implementation_state = "same_owner_materialized",
        cross_owner_state = "reserved_not_materialized")
      gaussian_coordinate_count <- .dsvert_dp_capsule_coordinate_add(
        gaussian_coordinate_count, model_coordinate_count)
      gaussian_raw_l1 <- gaussian_raw_l1 + raw_l1
      gaussian_raw_l2_squared <- .dsvert_dp_capsule_l2_add(
        gaussian_raw_l2_squared, .dsvert_dp_capsule_l2_square(raw_l2))
      gaussian_natural_l1 <- gaussian_natural_l1 + natural_l1
      gaussian_natural_l2_squared <- .dsvert_dp_capsule_l2_add(
        gaussian_natural_l2_squared,
        .dsvert_dp_capsule_l2_square(natural_l2))
      next
    }
    variables <- c(spec$outcome, spec$predictors)
    model_columns <- columns[variables]
    owners <- unique(vapply(
      model_columns, `[[`, character(1L), "owner_peer"))
    datasets <- vapply(model_columns, `[[`, character(1L), "dataset")
    kinds <- vapply(model_columns, `[[`, character(1L), "kind")
    if (any(kinds != "numeric") ||
        !identical(columns[[spec$outcome]]$dataset, spec$dataset)) {
      stop("A Gaussian specification has an invalid signed numeric model.",
           call. = FALSE)
    }
    cross_owner <- length(owners) > 1L || length(unique(datasets)) > 1L
    if ((!cross_owner && !identical(spec$version, "v1")) ||
        (cross_owner && !identical(spec$version, "v2"))) {
      stop(if (cross_owner) {
        paste("A cross-owner Gaussian specification must explicitly use",
              "version 'v2'.")
      } else {
        "A same-owner Gaussian specification must use version 'v1'."
      }, call. = FALSE)
    }
    design_terms <- c(
      if (isTRUE(spec$intercept)) "(Intercept)" else character(),
      spec$predictors)
    design_count <- length(design_terms)
    xtx_count <- as.double(design_count) * (design_count + 1) / 2
    model_coordinate_count <- xtx_count + design_count + 2
    model_coordinate_count <- .dsvert_dp_capsule_coordinate_add(
      0L, model_coordinate_count)
    raw_l1 <- 1 + (model_coordinate_count - 1) * grid_scale
    raw_l2 <- .dsvert_dp_capsule_l2_sqrt(
      .dsvert_dp_capsule_l2_add(
        1, .dsvert_dp_capsule_l2_multiply(
          model_coordinate_count - 1,
          .dsvert_dp_capsule_l2_square(grid_scale))))
    natural_l1 <- as.numeric(model_coordinate_count)
    natural_l2 <- .dsvert_dp_capsule_l2_sqrt(model_coordinate_count)
    if (cross_owner) {
      # The cross producer writes every coordinate, including n, directly on
      # the common S lattice.  This differs deliberately from v1, whose count
      # coordinate is left-shifted only by the joint-vector finalizer.
      raw_l1 <- model_coordinate_count * grid_scale
      raw_l2 <- .dsvert_dp_capsule_l2_multiply(
        .dsvert_dp_capsule_l2_sqrt(model_coordinate_count), grid_scale)
    }
    predictor_bounds <- lapply(spec$predictors, function(variable) {
      column <- columns[[variable]]
      if (cross_owner) {
        list(
          column = column$column, dataset = column$dataset,
          owner_peer = column$owner_peer,
          lower = column$lower, upper = column$upper)
      } else {
        list(column = column$column, lower = column$lower,
             upper = column$upper)
      }
    })
    names(predictor_bounds) <- spec$predictors
    outcome <- columns[[spec$outcome]]
    outcome_bound <- if (cross_owner) {
      list(
        column = outcome$column, dataset = outcome$dataset,
        owner_peer = outcome$owner_peer,
        lower = outcome$lower, upper = outcome$upper)
    } else {
      list(
        column = outcome$column, lower = outcome$lower,
        upper = outcome$upper)
    }
    if (!cross_owner) {
      gaussian_artifacts[[analysis_id]] <- list(
      version = "bounded-normalized-gaussian-sufficient-statistics-v1",
      spec_version = spec$version, analysis_id = analysis_id,
      dataset = spec$dataset, owner_peer = owners[[1L]],
      outcome = outcome_bound,
      predictors = predictor_bounds,
      predictor_order = unname(spec$predictors),
      intercept = spec$intercept, design_terms = unname(design_terms),
      numeric_grid_bits = grid_bits,
      coordinate_count = model_coordinate_count,
      coordinate_order = paste(
        "n_then_xtx_upper_column_major_then_xty_design_order_then_yty",
        "v1", sep = "_"),
      repeated_record_policy = paste(
        "clip_finite_rows_then_mean_each_variable_once_per_admitted_unit",
        "v1", sep = "_"),
      missingness_policy =
        "complete_case_across_outcome_and_all_predictors_v1",
      contribution_domain =
        "one_vector_of_normalized_monomials_in_closed_unit_interval_v1",
      count_gram_intercept_policy = paste(
        "n_is_complete_case_count_and_moment_upper_bound_gram11_governs",
        "the_solve_no_averaging_v1", sep = "_"),
      statistic_maximum = c(
        capacity, rep(capacity * grid_scale,
                      model_coordinate_count - 1L)),
      source_raw_l1_sensitivity = raw_l1,
      source_raw_l2_sensitivity = raw_l2,
      natural_l1_sensitivity = natural_l1,
      natural_l2_sensitivity = natural_l2,
      adjacency = policy$adjacency,
      adjacency_sensitivity_basis = paste(
        "zero_missing_complete_case_vs_all_one_complete_unit_is_worst",
        "case_for_add_remove_and_replace_one", sep = "_"),
      regularization_policy =
        "none_in_release_explicit_client_postprocessing_only_v1",
      implementation_state = "same_owner_materialized",
      cross_owner_state = "reserved_not_materialized")
    } else {
      required_signed_bits <- as.integer(ceiling(log2(capacity + 1))) +
        2L * grid_bits + 3L
      if (!is.finite(required_signed_bits) || required_signed_bits >= 127L) {
        stop(structure(
          list(
            message = paste(
              "The cross-owner Gaussian public bounds exceed the certified",
              "Ring128 exact-computation domain."),
            call = NULL,
            reason = "cross_gaussian_numeric_backend_unrepresentable",
            required_signed_bits = required_signed_bits),
          class = c("dsvert_numeric_backend_unrepresentable", "error",
                    "condition")))
      }
      participating <- sort(unique(owners), method = "radix")
      computation <- sort(policy$designated_noise_peers, method = "radix")
      if (length(computation) != 2L || anyNA(computation) ||
          anyDuplicated(computation) ||
          any(!computation %in% names(policy$peer_pinset))) {
        stop("A cross-owner Gaussian model requires exactly two signed computation peers.",
             call. = FALSE)
      }
      # For a,b in [0,S], with a=round(xS), b=round(yS), exact floor(ab/S)
      # differs from xyS by at most 2 + 1/(4S) integer lattice steps.
      product_error_steps <- 2 + 1 / (4 * grid_scale)
      gaussian_artifacts[[analysis_id]] <- list(
        version = paste0(
          "bounded-normalized-gaussian-cross-sufficient-statistics-v1"),
        spec_version = spec$version, analysis_id = analysis_id,
        dataset = spec$dataset, owner_peer = outcome$owner_peer,
        outcome = outcome_bound, predictors = predictor_bounds,
        predictor_order = unname(spec$predictors),
        input_variable_order = unname(c(spec$predictors, spec$outcome)),
        participating_peers = as.list(participating),
        computation_peers = as.list(computation),
        intercept = spec$intercept, design_terms = unname(design_terms),
        numeric_grid_bits = grid_bits,
        coordinate_count = model_coordinate_count,
        coordinate_order = paste(
          "n_then_xtx_upper_column_major_then_xty_design_order_then_yty",
          "v2", sep = "_"),
        source_coordinate_scaling =
          "all_coordinates_already_on_common_numeric_lattice_v1",
        private_input_layout = paste0(
          "capacity_padded_value_then_validity_per_signed_variable_",
          "manifest_order_v1"),
        repeated_record_policy = paste(
          "clip_finite_rows_then_mean_each_variable_once_per_admitted_unit",
          "v1", sep = "_"),
        missingness_policy =
          "complete_case_mask_remains_secret_shared_through_joint_noise_v1",
        contribution_domain = paste0(
          "round_normalized_inputs_then_exact_floor_ring128_products_",
          "on_closed_unit_interval_v1"),
        count_gram_intercept_policy = paste(
          "n_and_all_moments_share_one_secret_complete_case_mask_and_are",
          "released_only_after_joint_dp_v1", sep = "_"),
        statistic_maximum = rep(
          capacity * grid_scale, model_coordinate_count),
        source_raw_l1_sensitivity = model_coordinate_count * grid_scale,
        source_raw_l2_sensitivity = raw_l2,
        natural_l1_sensitivity = natural_l1,
        natural_l2_sensitivity = natural_l2,
        adjacency = policy$adjacency,
        adjacency_sensitivity_basis = paste(
          "zero_missing_complete_case_vs_all_one_complete_unit_is_worst",
          "case_for_add_remove_and_replace_one", sep = "_"),
        quantization_contract = list(
          input_rounding = "nearest_integer_ties_to_even_r_v1",
          product_rounding = "exact_signed_floor_after_division_by_scale_v1",
          per_product_max_abs_error_lattice_steps = product_error_steps,
          per_product_max_abs_error_normalized =
            product_error_steps / grid_scale,
          per_sum_max_abs_error_lattice_steps =
            capacity * product_error_steps,
          same_owner_v1_numerically_identical = FALSE),
        numeric_certificate = list(
          version = "dsvert-cross-gaussian-numeric-certificate-v1",
          ring_bits = 128L, frac_bits = grid_bits,
          required_signed_bits = required_signed_bits,
          operand_maximum = grid_scale,
          raw_product_maximum = grid_scale^2,
          accumulated_coordinate_maximum = capacity * grid_scale,
          truncation = "exact_signed_floor_gc_ot_or_direct_wide_v1",
          comparison = "not_used_after_custodian_bound_clipping",
          modular_wrap_proved_absent = TRUE,
          overflow_behavior = "typed_abort_before_commit"),
        transcript = list(
          version = "dsvert-cross-gaussian-fixed-transcript-v1",
          padded_units = capacity,
          variable_count = length(variables),
          validity_product_rounds = length(variables) - 1L,
          masked_value_rounds = 1L,
          moment_product_rounds = 1L,
          data_dependent_branches = 0L,
          exact_intermediate_release_count = 0L),
        alignment_contract = list(
          version = "private-psi-ordered-manifest-consensus-v1",
          public_patient_dependent_hash = FALSE,
          mismatch_behavior = "typed_non_prealigned_cohort_failure"),
        regularization_policy =
          "none_in_release_explicit_client_postprocessing_only_v1",
        implementation_state = "cross_owner_exact_gc_materialized",
        cross_owner_state = "exact_gc_to_joint_dp_vector_v1")
    }
    gaussian_coordinate_count <- .dsvert_dp_capsule_coordinate_add(
      gaussian_coordinate_count, model_coordinate_count)
    gaussian_raw_l1 <- gaussian_raw_l1 + raw_l1
    gaussian_raw_l2_squared <- .dsvert_dp_capsule_l2_add(
      gaussian_raw_l2_squared, .dsvert_dp_capsule_l2_square(raw_l2))
    gaussian_natural_l1 <- gaussian_natural_l1 + natural_l1
    gaussian_natural_l2_squared <- .dsvert_dp_capsule_l2_add(
      gaussian_natural_l2_squared,
      .dsvert_dp_capsule_l2_square(natural_l2))
  }
  gaussian_raw_l2 <- .dsvert_dp_capsule_l2_sqrt(
    gaussian_raw_l2_squared)
  gaussian_natural_l2 <- .dsvert_dp_capsule_l2_sqrt(
    gaussian_natural_l2_squared)
  add_family(
    gaussian_coordinate_count, gaussian_raw_l1, gaussian_raw_l2,
    lattice_l1 = gaussian_natural_l1,
    lattice_l2 = gaussian_natural_l2)

  describe_artifacts <- vector("list", length(describe_specs))
  names(describe_artifacts) <- names(describe_specs)
  describe_histogram_catalog <- list()
  for (analysis_id in names(describe_specs)) {
    raw <- describe_specs[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- .dsvert_dp_describe_spec(
      global_policy, data_name, analysis_id, specs = describe_specs)
    owners <- unique(vapply(
      columns[spec$variables], `[[`, character(1L), "owner_peer"))
    if (length(owners) != 1L || any(vapply(
          columns[spec$variables], `[[`, character(1L), "dataset") !=
          spec$dataset)) {
      stop("A describe specification requires an unimplemented vertical ",
           "producer.", call. = FALSE)
    }
    ordered_variables <- sort(spec$variables, method = "radix")
    moment_references <- histogram_references <-
      vector("list", length(ordered_variables))
    for (index in seq_along(ordered_variables)) {
      variable <- ordered_variables[[index]]
      moment_references[[index]] <- list(
        family = "numeric_moments", artifact = variable)
      spec_index <- match(variable, spec$variables)
      histogram <- list(
        version = spec$version, dataset = spec$dataset,
        owner_peer = owners[[1L]], column = variable,
        lower = columns[[variable]]$lower,
        upper = columns[[variable]]$upper,
        numeric_grid_bits = grid_bits,
        grid = spec$histogram_grids[[spec_index]],
        coordinate_count = length(spec$histogram_grids[[spec_index]]) + 1L,
        coordinate_order = "fixed_grid_bins_then_invalid_bin",
        repeated_record_policy =
          "clip_finite_rows_then_mean_once_per_admitted_unit_v1",
        missingness_policy =
          "NA_NaN_Inf_units_enter_fixed_invalid_bin",
        statistic_maximum = capacity,
        l1_sensitivity = adjacency_multiplier,
        l2_sensitivity =
          .dsvert_dp_capsule_l2_sqrt(adjacency_multiplier))
      primitive_id <- .dsvert_joint_dp_hash(list(
        family = "fixed_numeric_histogram", descriptor = histogram))
      if (is.null(describe_histogram_catalog[[primitive_id]])) {
        describe_histogram_catalog[[primitive_id]] <- histogram
      }
      histogram_references[[index]] <- list(
        family = "fixed_numeric_histograms", primitive_id = primitive_id)
    }
    describe_artifacts[[analysis_id]] <- list(
      version = spec$version, dataset = spec$dataset,
      owner_peer = owners[[1L]], variables = ordered_variables,
      histogram_grids = spec$histogram_grids[order(spec$variables,
                                                    method = "radix")],
      numeric_moment_references = moment_references,
      histogram_references = histogram_references,
      allocation_names = spec$allocation_names,
      allocation_weights = spec$allocation_weights,
      coordinate_count = spec$coordinate_count,
      l1_sensitivity = spec$sum_family_l1_sensitivity_bound,
      l2_sensitivity = .dsvert_dp_capsule_outward_l2(
        spec$l2_sensitivity_bound),
      statistic_maximum = capacity * grid_scale)
  }
  if (length(describe_histogram_catalog)) {
    describe_histogram_catalog <- describe_histogram_catalog[
      order(names(describe_histogram_catalog), method = "radix")]
  }
  describe_histogram_coordinate_count <- sum(vapply(
    describe_histogram_catalog, `[[`, numeric(1L), "coordinate_count"))
  describe_histogram_count <- length(describe_histogram_catalog)
  describe_histogram_l1 <- describe_histogram_count * adjacency_multiplier
  describe_histogram_l2 <- .dsvert_dp_capsule_l2_sqrt(
    .dsvert_dp_capsule_l2_multiply(
      describe_histogram_count, adjacency_multiplier))
  add_family(
    describe_histogram_coordinate_count,
    describe_histogram_l1, describe_histogram_l2)

  survival_artifacts <- vector("list", length(survival_specs))
  names(survival_artifacts) <- names(survival_specs)
  for (analysis_id in names(survival_specs)) {
    raw <- survival_specs[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- .dsvert_dp_survival_spec(
      global_policy, data_name, analysis_id, specs = survival_specs)
    variables <- c(spec$time, spec$event, spec$entry)
    variables <- variables[!vapply(variables, is.null, logical(1L))]
    owners <- unique(vapply(
      columns[variables], `[[`, character(1L), "owner_peer"))
    if (length(owners) != 1L || any(vapply(
          columns[variables], `[[`, character(1L), "dataset") !=
          spec$dataset)) {
      stop("A survival specification requires an unimplemented vertical ",
           "producer.", call. = FALSE)
    }
    survival_artifacts[[analysis_id]] <- list(
      version = spec$version, dataset = spec$dataset,
      owner_peer = owners[[1L]], time = spec$time, event = spec$event,
      entry = if (is.null(spec$entry)) "none" else spec$entry,
      censor = spec$censor, causes = spec$causes,
      time_grid = spec$time_grid, time_bounds = spec$time_bounds,
      coordinate_order =
        "entry_bins_if_any_then_exit_time_within_outcome_then_invalid_bin",
      repeated_record_policy = paste(
        "earliest_event_else_latest_censor_then_cause_then_entry",
        "deterministic_v2", sep = "_"),
      missingness_policy =
        "NA_NaN_Inf_or_out_of_domain_selected_unit_enters_invalid_bin",
      coordinate_count = spec$coordinate_count,
      l1_sensitivity = spec$l1_sensitivity,
      l2_sensitivity = .dsvert_dp_capsule_outward_l2(
        spec$l2_sensitivity),
      statistic_maximum = capacity)
    add_family(
      spec$coordinate_count, spec$l1_sensitivity,
      .dsvert_dp_capsule_outward_l2(spec$l2_sensitivity))
  }

  cross_categorical_artifacts <- list()
  for (analysis_id in names(configured_vertical)) {
    spec <- configured_vertical[[analysis_id]]
    if (!identical(spec$family, "categorical_pair")) next
    if (!identical(spec$version, "v2")) {
      stop("A cross-owner categorical pair must explicitly use version 'v2'.",
           call. = FALSE)
    }
    left <- columns[[spec$left]]
    right <- columns[[spec$right]]
    left_levels <- unname(left$levels)
    right_levels <- unname(right$levels)
    cell_count <- as.double(length(left_levels)) * length(right_levels)
    if (!is.finite(cell_count) || cell_count < 4L ||
        cell_count > .DSVERT_DP_MAX_COORDINATES) {
      stop("The cross-owner categorical table shape is not representable.",
           call. = FALSE)
    }
    computation <- sort(policy$designated_noise_peers, method = "radix")
    participating <- sort(unique(c(spec$left_owner, spec$right_owner)),
                          method = "radix")
    if (length(participating) != 2L || length(computation) != 2L ||
        anyNA(computation) || anyDuplicated(computation) ||
        any(!computation %in% names(policy$peer_pinset))) {
      stop("A cross-owner categorical pair requires exactly two signed computation peers.",
           call. = FALSE)
    }
    required_signed_bits <- as.integer(ceiling(log2(capacity + 1))) +
      grid_bits + 3L
    if (!is.finite(required_signed_bits) || required_signed_bits >= 127L) {
      stop(structure(list(
        message = paste(
          "The cross-owner categorical public bounds exceed the certified",
          "Ring128 exact-computation domain."),
        call = NULL,
        reason = "cross_categorical_numeric_backend_unrepresentable",
        required_signed_bits = required_signed_bits),
        class = c("dsvert_numeric_backend_unrepresentable", "error",
                  "condition")))
    }
    selected_l1 <- if (identical(
        policy$adjacency, "replace_one_fixed_cohort")) 2 else 1
    selected_l2 <- if (identical(
        policy$adjacency, "replace_one_fixed_cohort")) sqrt(2) else 1
    artifact <- list(
      version = "fixed-domain-categorical-cross-contingency-v1",
      spec_version = spec$version, analysis_id = analysis_id,
      alignment_group = spec$alignment_group,
      left = list(
        dataset = spec$left_dataset, column = left$column,
        owner_peer = spec$left_owner, levels = left_levels),
      right = list(
        dataset = spec$right_dataset, column = right$column,
        owner_peer = spec$right_owner, levels = right_levels),
      participating_peers = as.list(participating),
      computation_peers = as.list(computation),
      coordinate_count = as.integer(cell_count),
      coordinate_order = paste(
        "canonical_left_level_rows_then_canonical_right_level_columns",
        "column_major_v1", sep = "_"),
      source_coordinate_scaling =
        "all_coordinates_already_on_common_numeric_lattice_v1",
      private_input_layout = paste(
        "capacity_padded_one_hot_by_public_level_then_side",
        "manifest_order_v1", sep = "_"),
      repeated_record_policy = paste(
        "per_owner_consistent_level_else_zero_then_one_joint_cell",
        "per_admitted_unit_v1", sep = "_"),
      missingness_policy = paste(
        "missing_out_of_domain_or_conflicting_side_is_all_zero_and",
        "contributes_no_joint_cell_v1", sep = "_"),
      statistic_maximum = rep(capacity * grid_scale, cell_count),
      add_remove_l1_sensitivity = 1,
      add_remove_l2_sensitivity = 1,
      replace_one_l1_sensitivity = 2,
      replace_one_l2_sensitivity = .dsvert_dp_capsule_outward_l2(sqrt(2)),
      selected_l1_sensitivity = selected_l1,
      selected_l2_sensitivity =
        .dsvert_dp_capsule_outward_l2(selected_l2),
      source_raw_l1_sensitivity = selected_l1 * grid_scale,
      source_raw_l2_sensitivity =
        .dsvert_dp_capsule_outward_l2(selected_l2 * grid_scale),
      adjacency = policy$adjacency,
      adjacency_sensitivity_basis = paste(
        "one_hot_joint_cell_add_remove_and_difference_of_two_cells",
        "replace_one_v1", sep = "_"),
      numeric_certificate = list(
        version = "dsvert-cross-categorical-numeric-certificate-v1",
        ring_bits = 128L, frac_bits = grid_bits,
        required_signed_bits = required_signed_bits,
        operand_maximum = grid_scale,
        product_maximum = grid_scale,
        accumulated_coordinate_maximum = capacity * grid_scale,
        truncation = "exact_signed_floor_gc_ot_v1",
        modular_wrap_proved_absent = TRUE,
        overflow_behavior = "typed_abort_before_commit"),
      transcript = list(
        version = "dsvert-cross-categorical-fixed-transcript-v1",
        padded_units = capacity,
        row_level_count = length(left_levels),
        column_level_count = length(right_levels),
        product_coordinate_count = capacity * cell_count,
        exact_multiplication_rounds = 1L,
        data_dependent_branches = 0L,
        exact_intermediate_release_count = 0L),
      alignment_contract = list(
        version = "private-psi-ordered-manifest-consensus-v1",
        public_patient_dependent_hash = FALSE,
        mismatch_behavior = "typed_non_prealigned_cohort_failure"),
      implementation_state = "cross_owner_exact_gc_materialized",
      cross_owner_state = "exact_gc_to_joint_dp_vector_v1")
    cross_categorical_artifacts[[analysis_id]] <-
      .dsvert_dp_canonical_query_value(artifact)
    configured_vertical[[analysis_id]] <-
      cross_categorical_artifacts[[analysis_id]]
    pair_coordinate_count <- .dsvert_dp_capsule_coordinate_add(
      pair_coordinate_count, cell_count)
    pair_count_total <- pair_count_total + 1
    add_family(
      cell_count, selected_l1 * grid_scale,
      .dsvert_dp_capsule_outward_l2(selected_l2 * grid_scale),
      lattice_l1 = selected_l1,
      lattice_l2 = .dsvert_dp_capsule_outward_l2(selected_l2))
  }
  unsupported_configured <- configured_vertical[vapply(
    configured_vertical, function(spec) {
      !identical(spec$implementation_state,
                 "cross_owner_exact_gc_materialized")
    }, logical(1L))]
  vertical <- list(
    implementation_state = if (length(cross_categorical_artifacts) &&
        !length(unsupported_configured)) {
      "categorical_pair_exact_gc_materialized"
    } else if (length(cross_categorical_artifacts)) {
      "categorical_pair_materialized_other_cross_families_reserved"
    } else if (length(cross_owner_sets) || length(configured_vertical)) {
      "reserved_not_materialized"
    } else {
      "not_required_by_signed_schema"
    },
    cross_owner_sets = cross_owner_sets,
    categorical_pair_sets = vertical_pair_sets,
    configured_crosses = configured_vertical,
    included_coordinate_count = sum(vapply(
      cross_categorical_artifacts, `[[`, numeric(1L), "coordinate_count")))

  bounds <- .dsvert_dp_canonical_query_value(list(
    version = "biomedical-capsule-bounds-v1",
    schema_manifest_sha256 = signed$sha256,
    unit_capacity = capacity, numeric_grid_bits = grid_bits,
    numeric_grid_scale = grid_scale,
    numeric_columns = numeric_artifacts,
    categorical_columns = marginal_artifacts,
    gaussian_artifacts = gaussian_artifacts,
    describe_artifacts = describe_artifacts,
    survival_artifacts = survival_artifacts))
  families <- .dsvert_dp_canonical_query_value(list(
    admitted_count = count_family,
    numeric_moments = list(
      coordinate_count = numeric_coordinate_count,
      coordinate_order = "count,quantized_sum,quantized_sumsq_per_column",
      artifacts = numeric_artifacts,
      l1_sensitivity = numeric_l1, l2_sensitivity = numeric_l2),
    numeric_pair_moments = list(
      coordinate_count = numeric_pair_coordinate_count,
      coordinate_order =
        "sorted_artifact_id_then_six_pairwise_complete_moments",
      artifacts = numeric_pair_artifacts,
      l1_sensitivity = numeric_pair_raw_l1,
      l2_sensitivity = numeric_pair_l2,
      natural_l1_sensitivity = numeric_pair_natural_l1,
      natural_l2_sensitivity = numeric_pair_natural_l2),
    fixed_numeric_histograms = list(
      coordinate_count = describe_histogram_coordinate_count,
      coordinate_order =
        "sorted_primitive_id_then_fixed_grid_bins_then_invalid_bin",
      artifacts = describe_histogram_catalog,
      l1_sensitivity = describe_histogram_l1,
      l2_sensitivity = describe_histogram_l2),
    categorical_marginals = list(
      coordinate_count = marginal_coordinate_count,
      coordinate_order = "sorted_column_then_sorted_level",
      artifacts = marginal_artifacts,
      l1_sensitivity = marginal_l1, l2_sensitivity = marginal_l2),
    categorical_pairs = list(
      coordinate_count = pair_coordinate_count,
      coordinate_order = paste(
        "sorted_dataset_owner_then_lexicographic_unordered_column_pair",
        "then_column_major_sorted_levels"),
      sets = pair_sets,
      cross_artifacts = cross_categorical_artifacts,
      l1_sensitivity = pair_count_total * adjacency_multiplier,
      l2_sensitivity = .dsvert_dp_capsule_l2_sqrt(
        .dsvert_dp_capsule_l2_multiply(
          pair_count_total, adjacency_multiplier))),
    gaussian_models = list(
      coordinate_count = gaussian_coordinate_count,
      coordinate_order = "sorted_analysis_id_then_model_coordinates_v1",
      artifacts = gaussian_artifacts,
      l1_sensitivity = gaussian_raw_l1,
      l2_sensitivity = gaussian_raw_l2,
      natural_l1_sensitivity = gaussian_natural_l1,
      natural_l2_sensitivity = gaussian_natural_l2,
      cross_owner_state = "reserved_not_materialized"),
    correlation_artifacts = correlation_artifacts,
    describe_artifacts = describe_artifacts,
    survival_artifacts = survival_artifacts))
  source_raw_l2_sensitivity <- .dsvert_dp_capsule_l2_sqrt(
    sensitivity$l2_squared)
  natural_l2_sensitivity <- .dsvert_dp_capsule_l2_sqrt(
    lattice_sensitivity$l2_squared)
  integer_l1_sensitivity <- lattice_sensitivity$l1 * grid_scale
  integer_l2_sensitivity <- .dsvert_dp_capsule_l2_multiply(
    natural_l2_sensitivity, grid_scale)
  if (!is.finite(integer_l1_sensitivity) ||
      integer_l1_sensitivity <= 0 ||
      integer_l1_sensitivity != floor(integer_l1_sensitivity) ||
      integer_l1_sensitivity > .dsvert_dp_exact_integer_limit ||
      !is.finite(integer_l2_sensitivity) ||
      integer_l2_sensitivity <= 0 ||
      integer_l2_sensitivity > .dsvert_dp_exact_integer_limit) {
    stop("The biomedical capsule common-lattice sensitivity is not ",
         "representable.", call. = FALSE)
  }
  release_lattice <- .dsvert_dp_canonical_query_value(list(
    version = "biomedical-capsule-common-lattice-v1",
    transform_rule = "raw_coordinate_left_shift_to_common_numeric_grid_v1",
    output_lattice_bits = grid_bits,
    output_lattice_scale = grid_scale,
    natural_l1_sensitivity = lattice_sensitivity$l1,
    integer_l1_sensitivity_steps = integer_l1_sensitivity,
    natural_l2_sensitivity = natural_l2_sensitivity,
    integer_l2_sensitivity_steps = integer_l2_sensitivity))
  mechanism_selection <- .dsvert_dp_capsule_mechanism_selection(
    policy, coordinate_count, integer_l1_sensitivity,
    integer_l2_sensitivity,
    selector = .noise_selector, gaussian_planner = .gaussian_planner)
  possible_pair_count <- function(available) {
    groups <- table(vapply(available, function(column) {
      .dsvert_joint_dp_hash(list(
        dataset = column$dataset, owner_peer = column$owner_peer))
    }, character(1L)))
    if (!length(groups)) return(0)
    sum(as.double(groups) * (as.double(groups) - 1) / 2)
  }
  scope_selection <- .dsvert_dp_canonical_query_value(list(
    mode = primitive_scope$mode,
    explicit_catalog = primitive_scope$explicit_catalog,
    referenced_by_signed_specs =
      primitive_scope$referenced_by_signed_specs,
    included = list(
      numeric_moments = primitive_scope$numeric_moments,
      categorical_marginals = primitive_scope$categorical_marginals,
      same_owner_categorical_pairs = primitive_scope$categorical_pairs,
      same_owner_correlations = primitive_scope$correlations)))
  primitive_scope_contract <- .dsvert_dp_canonical_query_value(list(
    version = "dsvert-biomedical-capsule-primitive-scope-v1",
    mode = primitive_scope$mode,
    authority = "custodian_policy_and_signed_workload_specs_only",
    analyst_expandable = FALSE,
    client_query_can_add_coordinates = FALSE,
    consensus = paste(
      "byte_identical_manifest_hash_with_all_pinned_peer_build",
      "signatures_required_before_source_access", sep = "_"),
    mismatch_behavior = "reject_before_protected_snapshot_resolution",
    compatibility_default = "all_schema",
    recommended_deployment_mode = "catalog_v1",
    selection_sha256 = .dsvert_joint_dp_hash(scope_selection),
    selection = scope_selection,
    projected_cost = list(
      schema_numeric_column_count = as.integer(length(all_numeric_columns)),
      schema_categorical_column_count =
        as.integer(length(all_categorical_columns)),
      possible_same_owner_numeric_pair_count =
        possible_pair_count(all_numeric_columns),
      possible_same_owner_categorical_pair_count =
        possible_pair_count(all_categorical_columns),
      included_numeric_moment_count =
        as.integer(length(numeric_artifacts)),
      included_categorical_marginal_count =
        as.integer(length(marginal_artifacts)),
      included_numeric_pair_count =
        as.integer(length(numeric_pair_artifacts)),
      included_categorical_pair_count =
        as.integer(length(primitive_scope$categorical_pairs)),
      included_cross_categorical_pair_count =
        as.integer(length(cross_categorical_artifacts)),
      numeric_moment_coordinate_count =
        as.integer(numeric_coordinate_count),
      numeric_pair_coordinate_count =
        as.integer(numeric_pair_coordinate_count),
      categorical_marginal_coordinate_count =
        as.integer(marginal_coordinate_count),
      categorical_pair_coordinate_count =
        as.integer(pair_coordinate_count),
      gaussian_model_coordinate_count =
        as.integer(gaussian_coordinate_count),
      projected_coordinate_count = as.integer(coordinate_count),
      projected_integer_l1_sensitivity = integer_l1_sensitivity,
      projected_integer_l2_sensitivity = integer_l2_sensitivity,
      automatic_pair_expansion = if (identical(
          primitive_scope$mode, "all_schema")) {
        "explicit_all_schema"
      } else {
        "none"
      },
      scaling_contract = if (identical(
          primitive_scope$mode, "all_schema")) {
        "explicit_schema_wide_pair_families_may_be_quadratic"
      } else {
        paste(
          "linear_in_declared_univariates_plus_explicit_pairs_and",
          "declared_model_cross_products", sep = "_")
      })))
  source_context_hash <- .dsvert_joint_dp_hash(list(
    version = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    logical_snapshot = logical_snapshot,
    schema_manifest_sha256 = signed$sha256,
    admission = admission, bounds = bounds, families = families,
    vertical_crosses = vertical,
    primitive_scope = primitive_scope_contract,
    release_lattice = release_lattice,
    mechanism_selection = mechanism_selection$certificate))
  clipping_hash <- .dsvert_joint_dp_hash(list(
    admission = admission, bounds = bounds))
  mechanism <- list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = "biomedical.capsule.vector.v2",
    purpose = "biomedical_capsule_full_vector",
    source_context_hash = source_context_hash,
    mechanism = mechanism_selection$mechanism,
    mechanism_version = "biomedical-capsule-vector-v2",
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    sensitivity_norm = mechanism_selection$sensitivity_norm,
    sensitivity = mechanism_selection$sensitivity,
    coordinate_count = coordinate_count,
    uses_delta = mechanism_selection$uses_delta,
    clipping_hash = clipping_hash, ring_bits = 128L, frac_bits = 0L)
  mechanism <- .dsvert_joint_dp_mechanism(mechanism, policy)
  registered_release_lifecycle <-
    .dsvert_dp_capsule_registered_release_lifecycle()
  reuse_and_composition <- if (isTRUE(synopsis_policy)) {
    list(
      privacy_scope = "per_canonical_artifact_v1",
      same_artifact = "unlimited_sticky_replay_and_postprocessing",
      replay_count_limit = "none",
      prior_replay_can_deny = FALSE,
      prior_replay_changes_accuracy = FALSE,
      distinct_artifact_composition =
        "not_globally_bounded_by_this_protocol",
      historical_composition_can_deny = FALSE,
      request_limit = FALSE, rate_limit = FALSE,
      privacy_budget_gate = FALSE,
      release_instance_policy =
        "one_sticky_publication_per_canonical_artifact_key",
      global_composition_claim = FALSE,
      claim_scope = paste0(
        "per_artifact_dp_indistinguishability_not_probability_zero_",
        "reconstruction"))
  } else {
    list(
      privacy_scope = "bounded_custodian_lifetime",
      same_capsule = "unlimited_sticky_replay_and_postprocessing",
      reuse_count_limit = "none",
      prior_reuse_can_deny = FALSE,
      prior_reuse_changes_accuracy = FALSE,
      new_logical_snapshot = "new_capsule",
      new_capsule_composition =
        "exact_basic_composition_under_authenticated_lifetime_bound",
      historical_composition_can_deny = TRUE,
      request_limit = FALSE,
      privacy_budget_gate = TRUE,
      reservation_point =
        "cross_signed_allocator_commit_before_data_access",
      release_instance_policy =
        "at_most_one_public_release_instance_per_capsule_id",
      lifetime_max_distinct_capsules = as.numeric(
        policy_context$common$lifetime_max_distinct_capsules),
      lifetime_epsilon_upper_bound =
        policy_context$common$lifetime_epsilon_upper_bound,
      lifetime_delta_upper_bound =
        policy_context$common$lifetime_delta_upper_bound,
      global_lifetime_dp_claim = TRUE,
      claim_scope = paste0(
        "bounded_dp_indistinguishability_not_probability_zero_",
        "reconstruction"))
  }
  workload <- .dsvert_dp_canonical_query_value(list(
    workload_version = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    schema_attestation = list(
      version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
      manifest_sha256 = signed$sha256, signers = signed$signers,
      signatures = signed$signatures),
    coordinate_count = coordinate_count,
    sensitivity = list(
      l1 = integer_l1_sensitivity,
      l2 = integer_l2_sensitivity,
      source_raw_l1 = sensitivity$l1,
      source_raw_l2 = source_raw_l2_sensitivity,
      natural_output_l1 = lattice_sensitivity$l1,
      natural_output_l2 = natural_l2_sensitivity,
      l1_rounding = "exact_integer_upper_bound",
      l2_rounding =
        "per_operation_outward_binary64_guard_v2"),
    families = families, vertical_crosses = vertical,
    primitive_scope = primitive_scope_contract,
    release_lattice = release_lattice,
    mechanism_selection = mechanism_selection$certificate,
    registered_release_lifecycle = registered_release_lifecycle,
    reuse_and_composition = reuse_and_composition,
    declared_workload_fully_materialized = TRUE,
    package_family_coverage_complete = FALSE,
    execution_state = .DSVERT_DP_CAPSULE_EXECUTION_STATE,
    capsule_mechanism = mechanism))
  capsule_identity <- if (isTRUE(synopsis_policy)) {
    .dsvert_dp_synopsis_capsule_identity_v1(
      policy, logical_snapshot,
      capsule_schema = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
      admission = admission, bounds = bounds, workload = workload)
  } else {
    .dsvert_joint_dp_capsule_identity(
      policy, logical_snapshot,
      capsule_schema = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
      admission = admission, bounds = bounds, workload = workload)
  }
  result <- list(
    version = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    logical_snapshot = logical_snapshot,
    capsule_schema = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    admission = admission, bounds = bounds, workload = workload,
    capsule_identity = capsule_identity,
    execution_state = .DSVERT_DP_CAPSULE_EXECUTION_STATE)
  .dsvert_dp_canonical_query_value(result)
}
