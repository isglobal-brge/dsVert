# Canonical per-analysis identity and deterministic sticky randomness.
#
# This path is intentionally independent of persistent accounting, request
# counters and result stores. It is data-free until a caller supplies an opaque
# snapshot commitment minted by the owning site.
# Product entrypoints must obtain the semantic value from a method-specific
# server compiler and K-peer consensus; this internal file is not a caller-
# supplied analysis API.

.DSVERT_DP_ANALYSIS_CONTRACT_VERSION <- "dsvert-analysis-contract-v1"
.DSVERT_DP_ANALYSIS_SEMANTIC_VERSION <- "dsvert-analysis-semantic-v1"
.DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION <- "dsvert-analysis-semantic-fixed-categorical-vector-v2"
.DSVERT_DP_ANALYSIS_SYNOPSIS_SEMANTIC_VERSION <-
  "dsvert-analysis-semantic-stateless-catalog-synopsis-v1"
.DSVERT_DP_ANALYSIS_EXECUTION_VERSION <- "dsvert-analysis-execution-v1"
.DSVERT_DP_ANALYSIS_SNAPSHOT_VERSION <- "dsvert-analysis-snapshot-v1"
.DSVERT_DP_ANALYSIS_ARTIFACT_DOMAIN <-
  "dsVert/analysis-artifact-key/v1|"
.DSVERT_DP_ANALYSIS_SNAPSHOT_DOMAIN <-
  "dsVert/analysis-snapshot-commitment/v1|"
.DSVERT_DP_ANALYSIS_SNAPSHOT_KEY_DOMAIN <-
  "dsVert/analysis-snapshot-commitment-key/v1"
.DSVERT_DP_STICKY_NOISE_KEY_DOMAIN <-
  "dsVert/analysis-sticky-noise-key/v1"
.DSVERT_DP_STICKY_SUBSEED_DOMAIN <-
  "dsVert/sticky-artifact-subseed/v1|"
.DSVERT_DP_ANALYSIS_GAUSSIAN_TV_PER_COORDINATE <- 2^-40
.DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM <-
  "discrete-laplace-output-perturbation-tv-v2"
.DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER <-
  "hkdf-sha256-aes128ctr-two-geometric-tv-v2"
.DSVERT_DP_ANALYSIS_FREQUENCY_ORDER_DOMAIN <- "dsVert/fixed-categorical-frequency/coordinate-order/v1|"
.DSVERT_DP_ANALYSIS_FREQUENCY_POLICY_DOMAIN_V2 <-
  "dsVert/frequency/backend-selection-policy/v2|"
.DSVERT_DP_ANALYSIS_FREQUENCY_PLAN_DOMAIN_V1 <-
  "dsVert/frequency/full-plan/v1|"
.DSVERT_DP_ANALYSIS_FREQUENCY_ACCURACY_DOMAIN_V1 <-
  "dsVert/frequency/backend-selection/accuracy-certificate/v1|"
.DSVERT_DP_ANALYSIS_FREQUENCY_SELECTION_DOMAIN_V1 <-
  "dsVert/frequency/backend-selection/certificate/v1|"
.DSVERT_DP_ANALYSIS_FREQUENCY_CONTRIBUTION_DOMAIN_V1 <-
  "dsVert/dp-frequency/contribution/v1|"

.DSVERT_DP_ANALYSIS_RESERVED_FIELDS <- c(
  "analysis_id", "attempt_id", "connection_id", "epoch", "key_id", "nonce",
  "operation_id", "release_index", "request_id", "session_id", "user_id",
  "username", "data_name", "peer_name", "frontdoor", "route", "ledger_path",
  "lifetime_limit", "privacy_epoch", "noise_epoch", "noise_key_id",
  "connection_order", "format", "postprocessing")

.dsvert_dp_analysis_canonical_value_v1 <- function(value) {
  if (is.null(value)) return(NULL)
  if (is.object(value)) {
    stop("Unsupported analysis contract value", call. = FALSE)
  }
  if (is.list(value)) {
    list_attributes <- attributes(value)
    if (!is.null(list_attributes) &&
        !identical(names(list_attributes), "names")) {
      stop("Attributed list analysis contract values are not supported",
           call. = FALSE)
    }
    fields <- names(value)
    if (!is.null(fields) &&
        (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields))) {
      stop("Invalid analysis contract fields", call. = FALSE)
    }
    if (!is.null(fields)) {
      value <- value[order(fields, method = "radix")]
    }
    return(lapply(value, .dsvert_dp_analysis_canonical_value_v1))
  }
  if (!is.null(attributes(value))) {
    stop("Attributed atomic analysis contract values are not supported",
         call. = FALSE)
  }
  if (length(value) == 0L) {
    stop("Empty atomic vectors are not valid analysis contract values",
         call. = FALSE)
  }
  if (length(value) > 1L) {
    return(lapply(unname(as.list(value)),
                  .dsvert_dp_analysis_canonical_value_v1))
  }
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_dp_analysis_scalar_id <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", value)) {
    stop("Invalid ", what, " in the analysis contract", call. = FALSE)
  }
  value
}

.dsvert_dp_analysis_named_list <- function(value, what, allow_empty = FALSE) {
  valid <- is.list(value) &&
    ((isTRUE(allow_empty) && length(value) == 0L) ||
     (!is.null(names(value)) && !anyNA(names(value)) &&
      !anyDuplicated(names(value)) && all(nzchar(names(value))) &&
      length(value) > 0L))
  if (!isTRUE(valid)) {
    stop("Invalid ", what, " in the analysis contract", call. = FALSE)
  }
  value
}

.dsvert_dp_analysis_reject_operational_fields <- function(value) {
  if (!is.list(value)) return(invisible(NULL))
  fields <- names(value)
  if (!is.null(fields) && any(fields %in% .DSVERT_DP_ANALYSIS_RESERVED_FIELDS)) {
    stop("Operational request fields cannot define a semantic artifact",
         call. = FALSE)
  }
  for (element in value) {
    .dsvert_dp_analysis_reject_operational_fields(element)
  }
  invisible(NULL)
}

.dsvert_dp_analysis_identity_pk <- function(value, what) {
  compact <- if (is.character(value) && length(value) == 1L &&
                 !is.na(value)) {
    gsub("[\r\n[:space:]]", "", value)
  } else {
    ""
  }
  if (!grepl("^[A-Za-z0-9+/_-]{43}=?$", compact)) {
    stop("Invalid ", what, " in the analysis contract", call. = FALSE)
  }
  tryCatch(
    .dsvert_relay_normalize_identity_pk(compact),
    error = function(error) stop("Invalid ", what,
                                 " in the analysis contract",
                                 call. = FALSE))
}

.dsvert_dp_analysis_positive_integer <- function(value, what) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) ||
      value < 1 || value != floor(value) || value > .Machine$integer.max) {
    stop("Invalid ", what, " in the analysis contract", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_analysis_nonnegative_integer <- function(value, what) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) ||
      value < 0 || value != floor(value) || value > .Machine$integer.max) {
    stop("Invalid ", what, " in the analysis contract", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_analysis_frequency_scalar_id_v1 <- function(value) tryCatch({.dsvert_dp_analysis_scalar_id(value, "Frequency field"); TRUE}, error = function(error) FALSE)
.dsvert_dp_analysis_frequency_named_list_v1 <- function(value) tryCatch({.dsvert_dp_analysis_named_list(value, "Frequency list"); TRUE}, error = function(error) FALSE)
.dsvert_dp_analysis_frequency_identity_pk_v1 <- function(value) .dsvert_dp_analysis_identity_pk(value, "Frequency identity")
.dsvert_dp_analysis_frequency_positive_integer_v1 <- function(value) .dsvert_dp_analysis_positive_integer(value, "Frequency integer")
.dsvert_dp_analysis_frequency_levels_dimension_v1 <- function(
    levels, dimension, prefix = NULL) {
  dimension <- tryCatch(
    .dsvert_dp_analysis_frequency_positive_integer_v1(dimension),
    error = function(error) NULL)
  if (!is.list(levels) || !is.null(names(levels)) || is.null(dimension) ||
      dimension > .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS ||
      length(levels) != dimension) return(NULL)
  total_bytes <- 0
  if (!is.null(prefix)) {
    if (!is.character(prefix) || length(prefix) != 1L || is.na(prefix)) {
      return(NULL)
    }
    total_bytes <- tryCatch(
      nchar(prefix, type = "bytes"), error = function(error) NA_integer_)
    if (is.na(total_bytes) ||
        total_bytes > .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES) return(NULL)
  }
  for (level in levels) {
    if (!is.character(level) || length(level) != 1L || is.na(level)) return(NULL)
    level_bytes <- tryCatch(
      nchar(level, type = "bytes"), error = function(error) NA_integer_)
    if (length(level_bytes) != 1L || is.na(level_bytes) ||
        level_bytes > .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES -
          total_bytes) return(NULL)
    total_bytes <- total_bytes + level_bytes
  }
  dimension
}
.dsvert_dp_analysis_frequency_object_v1 <- function(value, fields,
                                                     fixed = list()) {
  is.list(value) && !is.null(names(value)) &&
    setequal(names(value), fields) && all(vapply(names(fixed), function(name) {
      identical(value[[name]], fixed[[name]])
    }, logical(1L)))
}
.dsvert_dp_analysis_frequency_hash_v1 <- function(domain, value) {
  payload <- paste0(domain, .dsvert_dp_canonical_json(.dsvert_dp_analysis_canonical_value_v1(value)))
  digest::digest(charToRaw(payload), algo = "sha256", serialize = FALSE)
}
.dsvert_dp_analysis_frequency_hex_v1 <- function(value) {
  is.character(value) && length(value) == 1L && !is.na(value) &&
    grepl("^[0-9a-f]{64}$", value)
}
.dsvert_dp_analysis_frequency_number_v1 <- function(value) {
  is.numeric(value) && length(value) == 1L && !is.na(value) &&
    is.finite(value)
}
.dsvert_dp_analysis_frequency_profile_v1 <- function(primitive) {
  if (!.dsvert_dp_analysis_frequency_scalar_id_v1(primitive)) return(NULL)
  common <- list(
    planner_request_derivation_version = "dsvert-frequency-planner-request-derivation-v1",
    chunk_partition_version = "contiguous_full_chunks_except_last_v1",
    max_chunk_coordinates = 8192, output_lattice_bits = 1,
    draw_count = 2, full_epsilon_per_draw = TRUE,
    variance_multiplier = 2, delta_aggregation = "max_per_peer_not_sum",
    output_transform = "signed-Ring128-decode-then-fixed-public-coordinate-clamp-v1",
    peer_name_binding = "semantic_authority_role_token_v1",
    selection_semantics = "deterministic_not_utility_optimal")
  specific <- switch(primitive,
    independent_full_global_draw_convolution_ring128_v3 = list(
      gaussian = FALSE, mechanism_family = "discrete_laplace",
      sensitivity_norm = "l1",
      mechanism = "two-independent-complete-vector-discrete-laplace-draws-v3",
      sampler = paste0("hkdf-sha256-chacha20-independent-full-draw-",
        "binary-geometric-tv-v3"),
      plan = paste0("dsvert-joint-dp-vector-independent-full-draw-",
        "convolution-plan-v3"),
      stream_domain = "dsVert/joint-dp/vector-convolution-private-stream/v3/",
      stream_mode = "chunk_contract_sequential_per_peer",
      request_domain = "dsVert/frequency/planner-request/convolution-v3|",
      rechunk_invariant = FALSE),
    independent_full_global_dyadic_discrete_gaussian_tv_bounded_ring128_v2 =
      list(
        gaussian = TRUE, mechanism_family = "gaussian",
        sensitivity_norm = "l2",
        mechanism = paste0("two-independent-complete-vector-dyadic-",
          "discrete-gaussian-tv-bounded-draws-v2"),
        sampler = paste0("cks-target-outward-rational-dyadic-cdf-hkdf-",
          "sha256-chacha20-coordinate-domain-v2"),
        plan = paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-",
                      "tv-bounded-plan-v2"),
        stream_domain = "dsVert/joint-dp/dyadic-discrete-gaussian/coordinate/v2/",
        stream_mode = "absolute_coordinate_per_peer",
        request_domain = "dsVert/frequency/planner-request/gaussian-v2|",
        rechunk_invariant = TRUE),
    NULL)
  if (is.null(specific)) NULL else c(common, specific)
}

.dsvert_dp_analysis_frequency_coordinate_order_sha256_v1 <- function(levels) {
  .dsvert_dp_analysis_frequency_hash_v1(
    .DSVERT_DP_ANALYSIS_FREQUENCY_ORDER_DOMAIN, list(
      version = "dsvert-frequency-coordinate-order-v1", levels = levels))
}
.dsvert_dp_analysis_frequency_contribution_sha256_v1 <- function() {
  .dsvert_dp_analysis_frequency_hash_v1(
    .DSVERT_DP_ANALYSIS_FREQUENCY_CONTRIBUTION_DOMAIN_V1, list(
      alignment_protocol = "dsvert-pinned-padded-psi-v4",
      duplicate_policy = "first",
      repeated_record_policy =
        "psi_v4_first_eligible_source_record_per_privacy_unit_v1",
      max_records_per_unit = 1,
      overflow_policy =
        "clip_to_psi_v4_first_eligible_source_record_v1"))
}
.dsvert_dp_analysis_frequency_uint_v1 <- function(value, positive = FALSE) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") > 512L ||
      !grepl("^(0|[1-9][0-9]*)$", value) ||
      (positive && identical(value, "0")))
    stop("Invalid Frequency unsigned integer", call. = FALSE)
  openssl::bignum(value)
}
.dsvert_dp_analysis_frequency_fraction_v1 <- function(value, positive = FALSE) {
  if (!.dsvert_dp_analysis_frequency_object_v1(
      value, c("numerator", "denominator")))
    stop("Invalid Frequency rational", call. = FALSE)
  numerator <- .dsvert_dp_analysis_frequency_uint_v1(
    value$numerator, positive)
  denominator <- .dsvert_dp_analysis_frequency_uint_v1(
    value$denominator, TRUE)
  left <- numerator
  right <- denominator
  while (!identical(as.character(right), "0")) {
    remainder <- left %% right
    left <- right
    right <- remainder
  }
  if (!identical(as.character(left), "1"))
    stop("Frequency rationals must be reduced", call. = FALSE)
  list(numerator = numerator, denominator = denominator)
}
.dsvert_dp_analysis_frequency_decimal_fraction_v1 <- function(value) {
  text <- if (is.character(value) && length(value) == 1L && !is.na(value) &&
              nchar(value, type = "bytes") <= 64L &&
              grepl("^[0-9]+(\\.[0-9]+)?e[+-][0-9]+$", value)) {
    value
  } else {
    .dsvert_dp_analysis_frequency_decimal_v1(value)
  }
  pieces <- strsplit(text, "e", fixed = TRUE)[[1L]]
  decimal <- strsplit(pieces[[1L]], ".", fixed = TRUE)[[1L]]
  fractional <- if (length(decimal) == 2L) decimal[[2L]] else ""
  digits <- sub("^0+", "", paste0(decimal[[1L]], fractional))
  if (!nzchar(digits)) digits <- "0"
  numerator <- openssl::bignum(digits)
  scale <- nchar(fractional) - as.integer(pieces[[2L]])
  denominator <- openssl::bignum("1")
  if (scale > 0L) denominator <- openssl::bignum("10") ^ scale
  if (scale < 0L) numerator <- numerator * openssl::bignum("10") ^ (-scale)
  left <- numerator
  right <- denominator
  while (!identical(as.character(right), "0")) {
    remainder <- left %% right
    left <- right
    right <- remainder
  }
  list(numerator = numerator %/% left, denominator = denominator %/% left)
}
.dsvert_dp_analysis_frequency_decimal_v1 <- function(
    value, direction = c("none", "inward", "outward")) {
  direction <- match.arg(direction)
  if (!.dsvert_dp_analysis_frequency_number_v1(value) || value <= 0)
    stop("Invalid Frequency planner decimal", call. = FALSE)
  margin <- 128 * .Machine$double.eps
  guarded <- switch(direction, none = value,
    inward = value * (1 - margin), outward = value * (1 + margin))
  encoded <- format(guarded, digits = 17L, scientific = TRUE, trim = TRUE,
                    decimal.mark = ".")
  decoded <- suppressWarnings(as.numeric(encoded))
  conservative <- switch(direction, none = identical(decoded, value),
    inward = is.finite(decoded) && decoded > 0 && decoded < value,
    outward = is.finite(decoded) && decoded > value)
  if (!isTRUE(conservative))
    stop("Non-conservative Frequency planner decimal", call. = FALSE)
  encoded
}
.dsvert_dp_analysis_frequency_planner_request_v1 <- function(
    profile, privacy, calibration, sensitivity, dimension) {
  if (profile$gaussian) list(
    epsilon = .dsvert_dp_analysis_frequency_decimal_v1(privacy$epsilon, "inward"),
    delta = .dsvert_dp_analysis_frequency_decimal_v1(calibration$implementation_delta, "inward"),
    l2_sensitivity_steps = .dsvert_dp_analysis_frequency_decimal_v1(sensitivity$value, "outward"),
    total_coordinate_count = as.integer(dimension)) else list(
      epsilon = .dsvert_dp_analysis_frequency_decimal_v1(privacy$epsilon),
      delta = .dsvert_dp_analysis_frequency_decimal_v1(
        calibration$implementation_delta),
      sensitivity_steps = format(sensitivity$value, scientific = FALSE,
                                 trim = TRUE, digits = 22L),
      total_coordinate_count = as.integer(dimension))
}
.dsvert_dp_analysis_frequency_fraction_leq_v1 <- function(left, right) {
  isTRUE(left$numerator * right$denominator <=
           right$numerator * left$denominator)
}
.dsvert_dp_analysis_frequency_primitives_v2 <- function() list(
  convolution = "independent_full_global_draw_convolution_ring128_v3",
  gaussian = paste0("independent_full_global_dyadic_discrete_gaussian_",
                    "tv_bounded_ring128_v2"))

.dsvert_dp_analysis_frequency_candidate_requests_v2 <- function(
    privacy, calibration, dimension) {
  if (!is.list(privacy) || !is.list(calibration) ||
      !.dsvert_dp_analysis_frequency_number_v1(dimension) ||
      dimension < 1 || dimension != floor(dimension) || dimension > 1000000) {
    stop("Invalid Frequency backend-selection request", call. = FALSE)
  }
  sensitivities <- switch(privacy$adjacency,
    add_remove_patient = list(convolution = 1, gaussian = 1),
    replace_one_fixed_cohort = list(convolution = 2, gaussian = sqrt(2)),
    stop("Invalid Frequency backend-selection adjacency", call. = FALSE))
  primitives <- .dsvert_dp_analysis_frequency_primitives_v2()
  stats::setNames(lapply(names(primitives), function(kind) {
    .dsvert_dp_analysis_frequency_planner_request_v1(
      .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]]),
      privacy, calibration, list(value = sensitivities[[kind]]), dimension)
  }), names(primitives))
}

.dsvert_dp_analysis_frequency_policy_sha256_v2 <- function() {
  primitives <- .dsvert_dp_analysis_frequency_primitives_v2()
  .dsvert_dp_analysis_frequency_hash_v1(
    .DSVERT_DP_ANALYSIS_FREQUENCY_POLICY_DOMAIN_V2, list(
      version = "dsvert-frequency-backend-selection-policy-v2",
      oracle_policy =
        "minimum_certified_simultaneous_95_abs_convolution_tie_v1",
      candidate_primitives = unname(primitives),
      objective = "minimum_certified_simultaneous_95_abs",
      accuracy_event = "max_j_abs_error_gt_radius",
      tie_break = "convolution_laplace_v3_on_equal_certified_radius",
      input_scope = paste0(
        "public_adjacency_planner_requests_and_coordinate_upper_bound_only"),
      source_material_consulted = FALSE,
      private_randomness_consulted = FALSE,
      runtime_failure_consulted = FALSE,
      automatic_fallback = FALSE,
      utility_optimality_claimed = FALSE))
}

.dsvert_dp_analysis_frequency_selection_validate_v2 <- function(
    selection, selected_primitive, plan, privacy, calibration,
    dimension, bound) {
  fail <- function() stop("Invalid Frequency backend selection", call. = FALSE)
  fields <- c("version", "policy_sha256", "selection_certificate_sha256",
    "objective", "tie_break", "candidates", "selected_primitive",
    "selected_simultaneous_95_abs")
  if (!.dsvert_dp_analysis_frequency_object_v1(selection, fields, list(
      version = "dsvert-frequency-backend-selection-v2",
      policy_sha256 = .dsvert_dp_analysis_frequency_policy_sha256_v2(),
      objective = "minimum_certified_simultaneous_95_abs",
      tie_break = "convolution_laplace_v3_on_equal_certified_radius")) ||
      !.dsvert_dp_analysis_frequency_hex_v1(
        selection$selection_certificate_sha256)) fail()
  primitives <- .dsvert_dp_analysis_frequency_primitives_v2()
  candidates <- selection$candidates
  candidate_fields <- c("planner_request_sha256", "full_plan_sha256",
    "accuracy_certificate_sha256", "simultaneous_95_abs",
    "absolute_support")
  if (!.dsvert_dp_analysis_frequency_object_v1(
      candidates, names(primitives))) fail()
  requests <- tryCatch(
    .dsvert_dp_analysis_frequency_candidate_requests_v2(
      privacy, calibration, dimension), error = function(error) NULL)
  parsed <- lapply(names(primitives), function(kind) {
    candidate <- candidates[[kind]]
    profile <- .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]])
    if (!.dsvert_dp_analysis_frequency_object_v1(candidate,
        candidate_fields) ||
        !.dsvert_dp_analysis_frequency_hex_v1(candidate$full_plan_sha256) ||
        !.dsvert_dp_analysis_frequency_hex_v1(
          candidate$accuracy_certificate_sha256) || is.null(requests) ||
        !identical(candidate$planner_request_sha256,
          .dsvert_dp_analysis_frequency_hash_v1(
            profile$request_domain, requests[[kind]]))) fail()
    values <- tryCatch(list(
      radius = .dsvert_dp_analysis_frequency_uint_v1(
        candidate$simultaneous_95_abs),
      support = .dsvert_dp_analysis_frequency_uint_v1(
        candidate$absolute_support, TRUE)), error = function(error) NULL)
    if (is.null(values) || !isTRUE(values$radius <= values$support)) fail()
    values
  })
  names(parsed) <- names(primitives)
  bound_text <- format(bound, scientific = FALSE, trim = TRUE, digits = 22L)
  upper <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
    bound_text, TRUE), error = function(error) NULL)
  max_signed <- openssl::bignum("2") ^ 127 - 1
  if (is.null(upper) || !all(vapply(parsed, function(candidate) isTRUE(
      upper + candidate$support <= max_signed), logical(1L)))) fail()
  winner <- if (isTRUE(parsed$gaussian$radius <
                       parsed$convolution$radius)) "gaussian" else "convolution"
  if (!identical(selection$selected_primitive, primitives[[winner]]) ||
      !identical(selected_primitive, primitives[[winner]]) ||
      !identical(selection$selected_simultaneous_95_abs,
                 candidates[[winner]]$simultaneous_95_abs) ||
      !identical(plan$full_plan_sha256,
                 candidates[[winner]]$full_plan_sha256) ||
      !identical(plan$planner_request_sha256,
                 candidates[[winner]]$planner_request_sha256)) fail()
  peer_noise <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
    plan$maximum_noise_per_peer, TRUE), error = function(error) NULL)
  if (is.null(peer_noise) || !identical(
      candidates[[winner]]$absolute_support,
      as.character(2 * peer_noise))) fail()
  invisible(TRUE)
}

.dsvert_dp_analysis_frequency_reduce_v2 <- function(numerator, denominator) {
  left <- numerator
  right <- denominator
  while (!identical(as.character(right), "0")) {
    remainder <- left %% right
    left <- right
    right <- remainder
  }
  list(numerator = as.character(numerator %/% left),
       denominator = as.character(denominator %/% left))
}

.dsvert_dp_analysis_frequency_backend_selection_v2 <- function(
    privacy, calibration, dimension, coordinate_upper_bound,
    .selector = NULL) {
  fail <- function() stop("Invalid Frequency backend selector output",
                          call. = FALSE)
  if (!.dsvert_dp_analysis_frequency_number_v1(coordinate_upper_bound) ||
      coordinate_upper_bound < 1 ||
      coordinate_upper_bound != floor(coordinate_upper_bound) ||
      coordinate_upper_bound > 1000000) fail()
  requests <- .dsvert_dp_analysis_frequency_candidate_requests_v2(
    privacy, calibration, dimension)
  request <- list(
    version = "dsvert-joint-dp-frequency-backend-selection-request-v1",
    adjacency = privacy$adjacency,
    coordinate_upper_bound = format(
      coordinate_upper_bound, scientific = FALSE, trim = TRUE, digits = 22L),
    convolution_request = requests$convolution,
    gaussian_request = requests$gaussian)
  if (is.null(.selector)) .selector <- function(value) {
    .callMpcTool("joint-dp-frequency-backend-select-v1", value,
                 simplify_output = FALSE)
  }
  if (!is.function(.selector)) fail()
  output <- tryCatch(.selector(request), error = function(error) fail())
  if (!.dsvert_dp_analysis_frequency_object_v1(output, c(
      "version", "request", "convolution_plan", "gaussian_plan",
      "convolution_certificate", "gaussian_certificate",
      "selection_certificate"), list(
        version = "dsvert-joint-dp-frequency-backend-selection-v1")) ||
      !identical(output$request, request)) fail()
  primitives <- .dsvert_dp_analysis_frequency_primitives_v2()
  plans <- list(convolution = output$convolution_plan,
                gaussian = output$gaussian_plan)
  certificates <- list(convolution = output$convolution_certificate,
                       gaussian = output$gaussian_certificate)
  certificate_fields <- c("primitive", "plan_sha256", "event", "method",
    "release_tv_upper_numerator", "release_tv_upper_denominator",
    "simultaneous_95_abs", "absolute_support")
  methods <- list(
    convolution = c("exact_two_discrete_laplace_convolution_tail_v1",
      "dyadic_exponential_envelope_v1", "finite_support_v1"),
    gaussian = "gaussian_plan_v2_subgaussian_mgf_tv_transfer")
  plan_fields <- list(
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
  integer_is <- function(value, expected) {
    .dsvert_dp_analysis_frequency_number_v1(value) &&
      value == floor(value) && identical(as.numeric(value), as.numeric(expected))
  }
  expected_support <- expected_tv <- plan_hashes <- parsed <- list()
  accuracy_exhausted <- list()
  for (kind in names(primitives)) {
    plan <- plans[[kind]]
    certificate <- certificates[[kind]]
    profile <- .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]])
    if (!.dsvert_dp_analysis_frequency_object_v1(
          plan, plan_fields[[kind]]) || anyDuplicated(names(plan)) ||
        !identical(plan$version, profile$plan) ||
        !identical(plan$sampler, profile$sampler) ||
        !integer_is(plan$total_coordinate_count, dimension) ||
        !integer_is(plan$maximum_chunk_coordinates,
                    min(profile$max_chunk_coordinates, dimension)) ||
        !integer_is(plan$independent_noise_peer_count, profile$draw_count) ||
        !identical(plan$complete_epsilon_per_peer, TRUE) ||
        !identical(plan$epsilon_divided_by_peer_count, FALSE) ||
        !identical(plan$capability_available, TRUE)) fail()
    if (kind == "convolution") {
      thresholds <- plan$bernoulli_thresholds
      bits <- plan$binary_geometric_bits
      threshold_shape <-
        .dsvert_dp_analysis_frequency_number_v1(bits) &&
        bits == floor(bits) && bits >= 1 && bits <= 63 &&
        is.list(thresholds) && is.null(names(thresholds)) &&
        identical(as.numeric(length(thresholds)), as.numeric(bits)) &&
        all(vapply(thresholds, function(value) {
          is.character(value) && length(value) == 1L && !is.na(value) &&
            grepl("^(0|[1-9][0-9]*)$", value)
        }, logical(1L)))
      if (!isTRUE(threshold_shape) ||
          !identical(plan$sensitivity_steps,
                     requests$convolution$sensitivity_steps) ||
          !integer_is(plan$geometric_variables_per_peer_per_coordinate, 2) ||
          !integer_is(plan$geometric_variables_total_per_coordinate, 4) ||
          !identical(plan$release_implementation_delta_aggregation,
                     profile$delta_aggregation)) fail()
      peer <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
        plan$maximum_noise_magnitude, TRUE), error = function(error) NULL)
      tv <- tryCatch(.dsvert_dp_analysis_frequency_fraction_v1(list(
        numerator = plan$one_geometric_tv_numerator,
        denominator = plan$one_geometric_tv_denominator), TRUE),
        error = function(error) NULL)
      if (is.null(peer) || is.null(tv)) fail()
      numerator <- tv$numerator * (4 * as.numeric(dimension))
      denominator <- tv$denominator
      accuracy_exhausted[[kind]] <- isTRUE(20 * numerator >= denominator)
      expected_tv[[kind]] <- if (isTRUE(numerator >= denominator)) {
        list(numerator = "1", denominator = "1")
      } else .dsvert_dp_analysis_frequency_reduce_v2(numerator, denominator)
      expected_support[[kind]] <- as.character(2 * peer)
    } else {
      if (!identical(plan$mechanism,
                     "dyadic_discrete_gaussian_truncated_tv_bounded") ||
          !identical(plan$release_delta_aggregation,
                     profile$delta_aggregation)) fail()
      peer <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
        plan$maximum_noise_magnitude_per_peer, TRUE),
        error = function(error) NULL)
      release <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
        plan$maximum_noise_magnitude_two_peers, TRUE),
        error = function(error) NULL)
      tv <- tryCatch(.dsvert_dp_analysis_frequency_fraction_v1(list(
        numerator = plan$vector_total_tv_upper_numerator,
        denominator = plan$vector_total_tv_upper_denominator), TRUE),
        error = function(error) NULL)
      sensitivity <- tryCatch(.dsvert_dp_analysis_frequency_fraction_v1(list(
        numerator = plan$l2_sensitivity_numerator,
        denominator = plan$l2_sensitivity_denominator), TRUE),
        error = function(error) NULL)
      requested_sensitivity <- tryCatch(
        .dsvert_dp_analysis_frequency_decimal_fraction_v1(
          requests$gaussian$l2_sensitivity_steps),
        error = function(error) NULL)
      if (is.null(peer) || is.null(release) || is.null(tv) ||
          is.null(sensitivity) || is.null(requested_sensitivity) ||
          !isTRUE(sensitivity$numerator * requested_sensitivity$denominator ==
            requested_sensitivity$numerator * sensitivity$denominator) ||
          !isTRUE(release == 2 * peer)) fail()
      expected_tv[[kind]] <- .dsvert_dp_analysis_frequency_reduce_v2(
        2 * tv$numerator, tv$denominator)
      if (!isTRUE(40 * tv$numerator < tv$denominator)) fail()
      expected_support[[kind]] <- as.character(release)
    }
    plan_hashes[[kind]] <- .dsvert_dp_analysis_frequency_hash_v1(
      .DSVERT_DP_ANALYSIS_FREQUENCY_PLAN_DOMAIN_V1, plan)
    if (!.dsvert_dp_analysis_frequency_object_v1(
        certificate, certificate_fields, list(
          primitive = primitives[[kind]], plan_sha256 = plan_hashes[[kind]],
          event = "max_j_abs_error_gt_radius")) ||
        !certificate$method %in% methods[[kind]] ||
        !identical(certificate$release_tv_upper_numerator,
                   expected_tv[[kind]]$numerator) ||
        !identical(certificate$release_tv_upper_denominator,
                   expected_tv[[kind]]$denominator) ||
        !identical(certificate$absolute_support,
                   expected_support[[kind]])) fail()
    values <- tryCatch(list(
      radius = .dsvert_dp_analysis_frequency_uint_v1(
        certificate$simultaneous_95_abs),
      support = .dsvert_dp_analysis_frequency_uint_v1(
        certificate$absolute_support, TRUE)), error = function(error) NULL)
    if (is.null(values) || !isTRUE(values$radius <= values$support) ||
        (kind == "convolution" &&
         ((isTRUE(accuracy_exhausted[[kind]]) &&
           !identical(certificate$method, "finite_support_v1")) ||
          (identical(certificate$method, "finite_support_v1") &&
           !isTRUE(values$radius == values$support)) ||
          (!identical(certificate$method, "finite_support_v1") &&
           !isTRUE(values$radius < values$support)))) ||
        (kind == "gaussian" && !identical(
          certificate$simultaneous_95_abs, plan$simultaneous_95_abs))) fail()
    parsed[[kind]] <- values
  }
  upper <- openssl::bignum(request$coordinate_upper_bound)
  max_signed <- openssl::bignum("2") ^ 127 - 1
  if (!all(vapply(parsed, function(value) isTRUE(
      upper + value$support <= max_signed), logical(1L)))) fail()
  winner <- if (isTRUE(parsed$gaussian$radius <
                       parsed$convolution$radius)) "gaussian" else "convolution"
  selection <- output$selection_certificate
  selection_fields <- c("version", "policy", "objective",
    "selected_primitive", "selected_plan_sha256",
    "selected_simultaneous_95_abs", "tie_break", "input_scope",
    "source_material_consulted", "private_randomness_consulted",
    "runtime_failure_consulted", "automatic_fallback",
    "utility_optimality_claimed")
  if (!.dsvert_dp_analysis_frequency_object_v1(selection,
      selection_fields, list(
        version = paste0("dsvert-joint-dp-frequency-backend-selection-",
                         "certificate-v1"),
        policy = "minimum_certified_simultaneous_95_abs_convolution_tie_v1",
        objective = "minimum_certified_simultaneous_95_abs",
        selected_primitive = primitives[[winner]],
        selected_plan_sha256 = plan_hashes[[winner]],
        selected_simultaneous_95_abs =
          certificates[[winner]]$simultaneous_95_abs,
        tie_break = "convolution_laplace_v3_on_equal_certified_radius",
        input_scope = paste0(
          "public_adjacency_planner_requests_and_coordinate_upper_bound_only"),
        source_material_consulted = FALSE,
        private_randomness_consulted = FALSE,
        runtime_failure_consulted = FALSE,
        automatic_fallback = FALSE,
        utility_optimality_claimed = FALSE))) fail()
  candidates <- stats::setNames(lapply(names(primitives), function(kind) {
    profile <- .dsvert_dp_analysis_frequency_profile_v1(primitives[[kind]])
    list(
      planner_request_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
        profile$request_domain, requests[[kind]]),
      full_plan_sha256 = plan_hashes[[kind]],
      accuracy_certificate_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
        .DSVERT_DP_ANALYSIS_FREQUENCY_ACCURACY_DOMAIN_V1,
        certificates[[kind]]),
      simultaneous_95_abs = certificates[[kind]]$simultaneous_95_abs,
      absolute_support = certificates[[kind]]$absolute_support)
  }), names(primitives))
  summary <- list(
    version = "dsvert-frequency-backend-selection-v2",
    policy_sha256 = .dsvert_dp_analysis_frequency_policy_sha256_v2(),
    selection_certificate_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
      .DSVERT_DP_ANALYSIS_FREQUENCY_SELECTION_DOMAIN_V1, selection),
    objective = "minimum_certified_simultaneous_95_abs",
    tie_break = "convolution_laplace_v3_on_equal_certified_radius",
    candidates = candidates, selected_primitive = primitives[[winner]],
    selected_simultaneous_95_abs =
      certificates[[winner]]$simultaneous_95_abs)
  list(summary = summary, selected_request = requests[[winner]],
       selected_plan = plans[[winner]],
       selected_accuracy_certificate = certificates[[winner]],
       selection_certificate = selection)
}
.dsvert_dp_analysis_frequency_plan_validate_v1 <- function(
    plan, profile, privacy, sensitivity, dimension, bound, calibration) {
  fail <- function() stop("Invalid Frequency plan summary", call. = FALSE)
  fields <- c("version", "physical_plan_version", "full_plan_sha256",
    "planner_request_sha256", "coordinate_order_sha256", "d",
    "chunk_coordinates", "allocated_delta", "core_delta", "implementation_delta",
    "maximum_noise_per_peer", "no_wrap_sha256",
    "profile_sha256", "backend_selection")
  canonical_chunk <- min(profile$max_chunk_coordinates, dimension)
  if (!.dsvert_dp_analysis_frequency_object_v1(plan, fields, list(
      version = "dsvert-frequency-plan-summary-v1",
      physical_plan_version = profile$plan, d = dimension,
      chunk_coordinates = canonical_chunk)) ||
      !.dsvert_dp_analysis_frequency_hex_v1(plan$full_plan_sha256) ||
      !.dsvert_dp_analysis_frequency_hex_v1(plan$coordinate_order_sha256) ||
      !identical(plan$profile_sha256,
        .dsvert_dp_analysis_frequency_hash_v1(
          "dsVert/frequency/physical-profile/v1|", profile))) fail()
  request <- .dsvert_dp_analysis_frequency_planner_request_v1(
    profile, privacy, calibration, sensitivity, dimension)
  expected_request <- .dsvert_dp_analysis_frequency_hash_v1(
    profile$request_domain, request)
  if (!identical(plan$planner_request_sha256, expected_request)) fail()
  fractions <- tryCatch(list(
    implementation = .dsvert_dp_analysis_frequency_fraction_v1(
      plan$implementation_delta, TRUE),
    allocated = .dsvert_dp_analysis_frequency_fraction_v1(
      plan$allocated_delta, TRUE),
    core = .dsvert_dp_analysis_frequency_fraction_v1(plan$core_delta,
      profile$gaussian),
    request = .dsvert_dp_analysis_frequency_decimal_fraction_v1(
      request$delta),
    calibration = .dsvert_dp_analysis_frequency_decimal_fraction_v1(
      calibration$implementation_delta)), error = function(error) NULL)
  leq <- .dsvert_dp_analysis_frequency_fraction_leq_v1
  equal <- function(left, right) leq(left, right) && leq(right, left)
  if (is.null(fractions) || !leq(fractions$implementation,
                                 fractions$allocated) ||
      !equal(fractions$allocated, fractions$request) ||
      !leq(fractions$allocated, fractions$calibration) ||
      (!profile$gaussian &&
       !isTRUE(fractions$core$numerator == openssl::bignum("0")))) fail()
  if (profile$gaussian && !isTRUE(
      (fractions$core$numerator * fractions$implementation$denominator +
       fractions$implementation$numerator * fractions$core$denominator) *
        fractions$allocated$denominator <=
      fractions$allocated$numerator * fractions$core$denominator *
        fractions$implementation$denominator)) fail()
  selection <- plan$backend_selection
  tryCatch(.dsvert_dp_analysis_frequency_selection_validate_v2(
    selection, selected_primitive =
      .dsvert_dp_analysis_frequency_primitives_v2()[[
        if (profile$gaussian) "gaussian" else "convolution"]], plan = plan,
    privacy = privacy, calibration = calibration, dimension = dimension,
    bound = bound), error = function(error) fail())
  peer_noise <- tryCatch(.dsvert_dp_analysis_frequency_uint_v1(
    plan$maximum_noise_per_peer, TRUE), error = function(error) NULL)
  max_signed <- openssl::bignum("2") ^ 127 - 1
  bound_text <- format(bound, scientific = FALSE, trim = TRUE, digits = 22L)
  if (is.null(peer_noise) || !isTRUE(
      openssl::bignum(bound_text) + 2 * peer_noise <= max_signed))
    fail()
  no_wrap <- list(
    version = "dsvert-frequency-ring128-no-wrap-v1",
    coordinate_upper_bound = bound_text,
    maximum_noise_per_peer = plan$maximum_noise_per_peer,
    maximum_noise_release = as.character(2 * peer_noise))
  expected_no_wrap <- .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/ring128-no-wrap/v1|", no_wrap)
  if (!identical(plan$no_wrap_sha256, expected_no_wrap)) fail()
  invisible(TRUE)
}
.dsvert_dp_analysis_frequency_semantic_validate_v1 <- function(value) {
  fail <- function() stop("Invalid fixed categorical Frequency semantic contract", call. = FALSE)
  raw_arguments <- tryCatch(value$analysis$effective_arguments,
    error = function(error) NULL)
  raw_levels <- if (is.list(raw_arguments)) raw_arguments$levels else NULL
  dimension <- if (is.list(raw_arguments)) {
    .dsvert_dp_analysis_frequency_levels_dimension_v1(
      raw_levels, raw_arguments$dimension)
  } else NULL
  if (is.null(dimension)) fail()
  utf8_exact <- all(vapply(raw_levels, function(level) {
      is.character(level) && length(level) == 1L && !is.na(level) &&
        nzchar(level) && nchar(level, type = "bytes") <= 1024L &&
        isTRUE(validUTF8(level)) &&
        tryCatch(identical(charToRaw(level), charToRaw(enc2utf8(level))),
                 error = function(error) FALSE)
    }, logical(1L)))
  canonical_levels <- if (utf8_exact) {
    as.list(sort(unlist(raw_levels, use.names = FALSE), method = "radix"))
  } else NULL
  if (!utf8_exact || anyDuplicated(unlist(raw_levels, use.names = FALSE)) ||
      !identical(raw_levels, canonical_levels)) fail()
  value <- tryCatch(.dsvert_dp_analysis_canonical_value_v1(value),
    error = function(error) fail())
  if (!.dsvert_dp_analysis_frequency_object_v1(value, c(
      "version", "domain", "cohort_id", "owner_snapshots",
      "noise_authority_roles", "analysis", "privacy", "numeric",
      "public_shape"), list(
        version = .DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION)) ||
      !.dsvert_dp_analysis_frequency_scalar_id_v1(value$domain) ||
      !.dsvert_dp_analysis_frequency_scalar_id_v1(value$cohort_id)) fail()
  .dsvert_dp_analysis_reject_operational_fields(value)
  analysis <- value$analysis
  arguments <- if (is.list(analysis)) analysis$effective_arguments else NULL
  if (!.dsvert_dp_analysis_frequency_object_v1(
      analysis, c("primitive", "formula", "effective_arguments"),
      list(formula = NULL)) ||
      !.dsvert_dp_analysis_frequency_object_v1(arguments, c(
        "version", "statistic", "source_owner", "dataset_id",
        "dataset_version", "variable_id", "levels", "dimension",
        "repeated_record_policy", "missingness_policy", "coordinate_bounds",
        "sampler_plan"), list(
          version = "dsvert-fixed-domain-categorical-frequency-v2",
          statistic = "aligned_fixed_domain_categorical_frequency",
          repeated_record_policy =
            "psi_v4_first_eligible_source_record_per_privacy_unit_v1",
          missingness_policy =
            "missing_or_out_of_domain_rows_are_ignored"))) fail()
  profile <- .dsvert_dp_analysis_frequency_profile_v1(analysis$primitive)
  if (is.null(profile) ||
      !all(vapply(arguments[c("dataset_id", "dataset_version", "variable_id")],
                  .dsvert_dp_analysis_frequency_scalar_id_v1, logical(1L)))) fail()
  bounds <- arguments$coordinate_bounds
  bound <- tryCatch(.dsvert_dp_analysis_frequency_positive_integer_v1(bounds$upper),
                    error = function(error) NULL)
  if (!.dsvert_dp_analysis_frequency_object_v1(
        bounds, c("lower", "upper"), list(lower = 0)) ||
      is.null(bound) || bound > 1000000) fail()
  snapshots <- value$owner_snapshots
  if (!.dsvert_dp_analysis_frequency_named_list_v1(snapshots) ||
      length(snapshots) < 2L || length(snapshots) > 4096L) fail()
  owner_ids <- tryCatch(vapply(
    names(snapshots), .dsvert_dp_analysis_frequency_identity_pk_v1, character(1L)),
    error = function(error) character())
  if (length(owner_ids) != length(snapshots) || anyDuplicated(owner_ids)) fail()
  names(snapshots) <- owner_ids
  snapshots <- snapshots[order(names(snapshots), method = "radix")]
  snapshot_valid <- all(vapply(snapshots, function(snapshot) {
    .dsvert_dp_analysis_frequency_object_v1(
      snapshot, c("version", "dataset_id", "dataset_version",
                  "snapshot_commitment"), list(
        version = .DSVERT_DP_ANALYSIS_SNAPSHOT_VERSION)) &&
      .dsvert_dp_analysis_frequency_scalar_id_v1(snapshot$dataset_id) &&
      .dsvert_dp_analysis_frequency_scalar_id_v1(snapshot$dataset_version) &&
      .dsvert_dp_analysis_frequency_hex_v1(snapshot$snapshot_commitment)
  }, logical(1L)))
  source <- tryCatch(.dsvert_dp_analysis_frequency_identity_pk_v1(
    arguments$source_owner),
    error = function(error) NULL)
  if (!snapshot_valid || is.null(source) || !source %in% names(snapshots) ||
      !identical(snapshots[[source]]$dataset_id, arguments$dataset_id) ||
      !identical(snapshots[[source]]$dataset_version,
                 arguments$dataset_version)) fail()
  roles <- value$noise_authority_roles
  authority_ids <- tryCatch(vapply(
    roles$authority_ids, .dsvert_dp_analysis_frequency_identity_pk_v1, character(1L)),
    error = function(error) character())
  expected_authorities <- c(
    source, sort(setdiff(names(snapshots), source), method = "radix")[[1L]])
  if (!.dsvert_dp_analysis_frequency_object_v1(
      roles, c("version", "role_order", "authority_ids"), list(
        version = "dsvert-frequency-noise-authority-roles-v1",
        role_order = list("source_owner", "secondary_noise_authority"))) ||
      !is.list(roles$authority_ids) || !is.null(names(roles$authority_ids)) ||
      !identical(unname(authority_ids), unname(expected_authorities))) fail()
  privacy <- value$privacy
  if (!.dsvert_dp_analysis_frequency_object_v1(privacy, c(
      "version", "adjacency", "privacy_unit", "contribution", "mechanism",
      "epsilon", "delta"), list(
        version = "dsvert-per-analysis-dp-v1", privacy_unit = "patient")) ||
      !.dsvert_dp_analysis_frequency_scalar_id_v1(privacy$adjacency) ||
      !privacy$adjacency %in%
        c("add_remove_patient", "replace_one_fixed_cohort") ||
      !.dsvert_dp_analysis_frequency_number_v1(privacy$epsilon) ||
      privacy$epsilon <= 0 || privacy$epsilon > 8 ||
      !.dsvert_dp_analysis_frequency_number_v1(privacy$delta) ||
      privacy$delta <= 0 || privacy$delta >= 1)
    fail()
  contribution <- privacy$contribution
  constraints <- if (is.list(contribution)) contribution$constraints else NULL
  if (!.dsvert_dp_analysis_frequency_object_v1(
      contribution, c("version", "max_records_per_unit", "overflow_policy",
                      "constraints"), list(
        version = "dsvert-contribution-policy-v1", max_records_per_unit = 1,
        overflow_policy =
          "clip_to_psi_v4_first_eligible_source_record_v1")) ||
      !.dsvert_dp_analysis_frequency_object_v1(
        constraints, c("version", "policy_sha256"), list(
          version = "dsvert-contribution-constraints-v1")) ||
      !identical(constraints$policy_sha256,
                 .dsvert_dp_analysis_frequency_contribution_sha256_v1())) fail()
  mechanism <- privacy$mechanism
  sensitivity <- if (is.list(mechanism)) mechanism$sensitivity else NULL
  calibration <- if (is.list(mechanism)) mechanism$calibration else NULL
  randomness <- if (is.list(mechanism)) mechanism$randomness else NULL
  lane <- if (is.list(randomness) && is.list(randomness$lanes)) {
    randomness$lanes$final_noise
  } else NULL
  adjacency_l1 <- if (identical(
      privacy$adjacency, "replace_one_fixed_cohort")) 2 else 1
  expected_sensitivity <- if (profile$gaussian) sqrt(adjacency_l1) else
    adjacency_l1
  sensitivity_valid <- .dsvert_dp_analysis_frequency_object_v1(
    sensitivity, c("version", "norm", "value"), list(
      version = "dsvert-sensitivity-v1", norm = profile$sensitivity_norm)) &&
    .dsvert_dp_analysis_frequency_number_v1(sensitivity$value) &&
    identical(sensitivity$value, expected_sensitivity)
  calibration_valid <- .dsvert_dp_analysis_frequency_object_v1(
    calibration, c("version", "sampler", "implementation_delta"), list(
      version = "dsvert-calibration-v1", sampler = profile$sampler)) &&
    .dsvert_dp_analysis_frequency_number_v1(
      calibration$implementation_delta) &&
    calibration$implementation_delta > 0 &&
    calibration$implementation_delta <= privacy$delta
  mechanism_valid <- .dsvert_dp_analysis_frequency_object_v1(
    mechanism, c("family", "version", "sensitivity", "calibration",
                 "randomness"), list(
      family = profile$mechanism_family, version = profile$mechanism)) &&
    sensitivity_valid && calibration_valid &&
    .dsvert_dp_analysis_frequency_object_v1(
      randomness, c("version", "lanes"), list(
        version = "dsvert-randomness-plan-v1")) &&
    identical(names(randomness$lanes), "final_noise") &&
    .dsvert_dp_analysis_frequency_object_v1(
      lane, c("version", "purpose", "primitive", "coordinates"), list(
        version = "dsvert-randomness-lane-v1",
        purpose = "privatize_final_vector", primitive = profile$sampler,
        coordinates = dimension))
  if (!mechanism_valid) fail()
  expected_order <- .dsvert_dp_analysis_frequency_coordinate_order_sha256_v1(
    arguments$levels)
  if (!identical(arguments$sampler_plan$coordinate_order_sha256,
                 expected_order)) fail()
  .dsvert_dp_analysis_frequency_plan_validate_v1(
    arguments$sampler_plan, profile, privacy, sensitivity, dimension, bound,
    calibration)
  if (!.dsvert_dp_analysis_frequency_object_v1(
      value$numeric, c("version", "value_bits", "fractional_bits", "rounding",
                       "overflow", "output_encoding"), list(
        version = "dsvert-numeric-semantics-v1", value_bits = 128,
        fractional_bits = 0, rounding = "toward_zero", overflow = "reject",
        output_encoding = "twos_complement_integer_v1")) ||
      !identical(value$public_shape, list(counts = dimension))) fail()
  arguments$source_owner <- source
  analysis$effective_arguments <- arguments
  value$owner_snapshots <- snapshots
  roles$authority_ids <- as.list(unname(authority_ids))
  value$noise_authority_roles <- roles
  value$analysis <- analysis
  .dsvert_dp_analysis_canonical_value_v1(value)
}

.dsvert_dp_analysis_gaussian_impl_delta_v1 <- function(
    coordinates, epsilon) {
  log_bound <- log(coordinates) +
    log(.DSVERT_DP_ANALYSIS_GAUSSIAN_TV_PER_COORDINATE) +
    epsilon + log1p(exp(-epsilon))
  if (!is.finite(log_bound) || log_bound >= 0) return(Inf)
  exp(log_bound)
}

.dsvert_dp_analysis_gaussian_achieved_delta_v1 <- function(
    sigma, sensitivity, epsilon) {
  exponential <- exp(epsilon)
  if (!is.finite(exponential)) return(NA_real_)
  ratio <- sensitivity / sigma
  if (!is.finite(ratio) || ratio <= 0) return(NA_real_)
  a <- 0.5 * ratio
  b <- epsilon / ratio
  if (!is.finite(a) || !is.finite(b)) return(NA_real_)
  achieved <- stats::pnorm(a - b) - exponential * stats::pnorm(-a - b)
  if (!is.finite(achieved) || achieved < -1e-15) return(NA_real_)
  max(0, achieved)
}

.dsvert_dp_analysis_calibration_validate_v1 <- function(
    mechanism, epsilon, delta, coordinates) {
  calibration <- mechanism$calibration
  sensitivity <- mechanism$sensitivity$value
  count_tv <- identical(
    mechanism$version, .DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM)
  expected <- switch(mechanism$family,
    gaussian = c(
      version = "gaussian-output-perturbation-v1",
      sampler = "gaussian-one-draw-v1"),
    laplace = c(
      version = "laplace-output-perturbation-v1",
      sampler = "laplace-one-draw-v1"),
    discrete_laplace = if (count_tv) c(
      version = .DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM,
      sampler = .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER) else c(
        version = "discrete-laplace-output-perturbation-v1",
        sampler = "discrete-laplace-one-draw-v1"))
  if (!identical(mechanism$version, unname(expected[["version"]])) ||
      !identical(calibration$sampler, unname(expected[["sampler"]]))) {
    stop("The DP mechanism and sampler are not an audited pair",
         call. = FALSE)
  }
  if (identical(mechanism$family, "gaussian")) {
    implementation_floor <- .dsvert_dp_analysis_gaussian_impl_delta_v1(
      coordinates, epsilon)
    achieved <- .dsvert_dp_analysis_gaussian_achieved_delta_v1(
      calibration$noise_scale, sensitivity, epsilon)
    tolerance <- 4096 * .Machine$double.eps *
      max(delta, .Machine$double.xmin)
    if (!is.finite(implementation_floor) ||
        !is.finite(achieved) || delta <= 0 ||
        calibration$implementation_delta + tolerance <
          implementation_floor ||
        achieved + calibration$implementation_delta > delta + tolerance) {
      stop("The Gaussian calibration does not prove its declared privacy",
           call. = FALSE)
    }
  } else if (count_tv) {
    minimum_scale <- sensitivity / epsilon
    if (!is.finite(minimum_scale) || minimum_scale <= 0 ||
        calibration$noise_scale < minimum_scale || delta <= 0 ||
        calibration$implementation_delta <= 0 ||
        calibration$implementation_delta > delta || coordinates != 1) {
      stop("The Count TV calibration does not prove its declared privacy",
           call. = FALSE)
    }
  } else {
    minimum_scale <- sensitivity / epsilon
    if (!is.finite(minimum_scale) || minimum_scale <= 0) {
      stop("The Laplace calibration does not prove its declared privacy",
           call. = FALSE)
    }
    tolerance <- 4096 * .Machine$double.eps *
      max(minimum_scale, .Machine$double.xmin)
    if (!identical(calibration$implementation_delta, 0) ||
        calibration$noise_scale + tolerance < minimum_scale) {
      stop("The Laplace calibration does not prove its declared privacy",
           call. = FALSE)
    }
  }
  mechanism
}

.dsvert_dp_analysis_identity_seed_raw_v1 <- function() {
  seed <- tryCatch(
    jsonlite::base64_dec(.get_identity_seed()),
    error = function(error) raw(0L))
  if (!is.raw(seed) || length(seed) != 32L) {
    stop("The persistent identity seed is invalid", call. = FALSE)
  }
  seed
}

.dsvert_dp_analysis_snapshot_key_v1 <- function() {
  digest::hmac(
    key = .dsvert_dp_analysis_identity_seed_raw_v1(),
    object = charToRaw(.DSVERT_DP_ANALYSIS_SNAPSHOT_KEY_DOMAIN),
    algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_dp_sticky_noise_key_v1 <- function() {
  digest::hmac(
    key = .dsvert_dp_analysis_identity_seed_raw_v1(),
    object = charToRaw(.DSVERT_DP_STICKY_NOISE_KEY_DOMAIN),
    algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_dp_analysis_semantic_validate_v1 <- function(value) {
  if (is.list(value) && identical(
      value$version, .DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION)) {
    return(.dsvert_dp_analysis_frequency_semantic_validate_v1(value))
  }
  if (is.list(value) && identical(
      value$version, .DSVERT_DP_ANALYSIS_SYNOPSIS_SEMANTIC_VERSION)) {
    return(.dsvert_dp_analysis_synopsis_semantic_validate_v1(value))
  }
  value <- tryCatch(
    .dsvert_dp_analysis_canonical_value_v1(value),
    error = function(error) stop(
      "Invalid canonical semantic contract: ", conditionMessage(error),
      call. = FALSE))
  fields <- c(
    "version", "domain", "cohort_id", "owner_snapshots",
    "noise_authorities", "analysis", "privacy", "numeric",
    "public_shape")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_ANALYSIS_SEMANTIC_VERSION)) {
    stop("Invalid semantic contract", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(value$domain, "domain")
  .dsvert_dp_analysis_scalar_id(value$cohort_id, "cohort ID")
  .dsvert_dp_analysis_reject_operational_fields(value)

  snapshots <- .dsvert_dp_analysis_named_list(
    value$owner_snapshots, "owner snapshots")
  owner_ids <- vapply(names(snapshots), function(owner) {
    .dsvert_dp_analysis_identity_pk(owner, "owner identity")
  }, character(1L))
  if (length(snapshots) < 2L || length(snapshots) > 4096L ||
      anyDuplicated(owner_ids)) {
    stop("Invalid owner snapshots in the analysis contract", call. = FALSE)
  }
  names(snapshots) <- owner_ids
  snapshots <- snapshots[order(names(snapshots), method = "radix")]
  snapshot_fields <- c(
    "version", "dataset_id", "dataset_version", "snapshot_commitment")
  for (snapshot in snapshots) {
    if (!is.list(snapshot) || is.null(names(snapshot)) ||
        !setequal(names(snapshot), snapshot_fields) ||
        !identical(snapshot$version, .DSVERT_DP_ANALYSIS_SNAPSHOT_VERSION)) {
      stop("Invalid owner snapshot in the analysis contract", call. = FALSE)
    }
    .dsvert_dp_analysis_scalar_id(snapshot$dataset_id, "dataset ID")
    .dsvert_dp_analysis_scalar_id(snapshot$dataset_version, "dataset version")
    if (!is.character(snapshot$snapshot_commitment) ||
        length(snapshot$snapshot_commitment) != 1L ||
        is.na(snapshot$snapshot_commitment) ||
        !grepl("^[0-9a-f]{64}$", snapshot$snapshot_commitment)) {
      stop("Invalid snapshot commitment in the analysis contract",
           call. = FALSE)
    }
  }
  value$owner_snapshots <- snapshots

  authorities <- value$noise_authorities
  if (!is.list(authorities) || !is.null(names(authorities)) ||
      length(authorities) != 2L) {
    stop("Invalid noise authorities in the semantic contract",
         call. = FALSE)
  }
  authorities <- vapply(authorities, function(authority) {
    .dsvert_dp_analysis_identity_pk(authority, "noise authority")
  }, character(1L))
  authorities <- unname(sort(authorities, method = "radix"))
  expected_authorities <- unname(sort(owner_ids, method = "radix")[1:2])
  if (anyDuplicated(authorities) || !all(authorities %in% owner_ids) ||
      !identical(authorities, expected_authorities)) {
    stop("Invalid noise authorities in the semantic contract",
         call. = FALSE)
  }
  value$noise_authorities <- as.list(authorities)

  analysis <- value$analysis
  if (!is.list(analysis) || is.null(names(analysis)) || !setequal(
      names(analysis), c("primitive", "formula", "effective_arguments")) ||
      !is.list(analysis$effective_arguments) ||
      (length(analysis$effective_arguments) &&
       is.null(names(analysis$effective_arguments))) ||
      !(is.null(analysis$formula) || is.list(analysis$formula))) {
    stop("Invalid analysis definition in the semantic contract",
         call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(analysis$primitive, "analysis primitive")

  privacy <- value$privacy
  privacy_fields <- c(
    "version", "adjacency", "privacy_unit", "contribution", "mechanism",
    "epsilon", "delta")
  if (!is.list(privacy) || is.null(names(privacy)) ||
      !setequal(names(privacy), privacy_fields) ||
      !identical(privacy$version, "dsvert-per-analysis-dp-v1") ||
      !is.numeric(privacy$epsilon) || length(privacy$epsilon) != 1L ||
      is.na(privacy$epsilon) || !is.finite(privacy$epsilon) ||
      privacy$epsilon <= 0 ||
      !is.numeric(privacy$delta) || length(privacy$delta) != 1L ||
      is.na(privacy$delta) || !is.finite(privacy$delta) ||
      privacy$delta < 0 || privacy$delta >= 1) {
    stop("Invalid per-analysis privacy contract", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(privacy$adjacency, "adjacency")
  .dsvert_dp_analysis_scalar_id(privacy$privacy_unit, "privacy unit")
  contribution <- privacy$contribution
  contribution_fields <- c(
    "version", "max_records_per_unit", "overflow_policy", "constraints")
  if (!is.list(contribution) || is.null(names(contribution)) ||
      !setequal(names(contribution), contribution_fields) ||
      !identical(contribution$version, "dsvert-contribution-policy-v1")) {
    stop("Invalid contribution policy in the analysis contract",
         call. = FALSE)
  }
  contribution$max_records_per_unit <-
    .dsvert_dp_analysis_positive_integer(
      contribution$max_records_per_unit, "maximum records per privacy unit")
  .dsvert_dp_analysis_scalar_id(
    contribution$overflow_policy, "contribution overflow policy")
  if (!contribution$overflow_policy %in%
      c("reject_operation", "clip_to_declared_bounds")) {
    stop("Invalid contribution overflow policy in the analysis contract",
         call. = FALSE)
  }
  constraints <- contribution$constraints
  if (!is.list(constraints) || is.null(names(constraints)) ||
      !setequal(names(constraints), c("version", "policy_sha256")) ||
      !identical(constraints$version,
                 "dsvert-contribution-constraints-v1") ||
      !is.character(constraints$policy_sha256) ||
      length(constraints$policy_sha256) != 1L ||
      is.na(constraints$policy_sha256) ||
      !grepl("^[0-9a-f]{64}$", constraints$policy_sha256)) {
    stop("Invalid contribution constraints in the analysis contract",
         call. = FALSE)
  }
  privacy$contribution <- contribution

  mechanism <- .dsvert_dp_analysis_named_list(
    privacy$mechanism, "DP mechanism")
  mechanism_fields <- c(
    "family", "version", "sensitivity", "calibration", "randomness")
  if (!setequal(names(mechanism), mechanism_fields)) {
    stop("Invalid DP mechanism in the analysis contract", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(mechanism$family, "DP mechanism family")
  if (!mechanism$family %in% c("gaussian", "laplace", "discrete_laplace")) {
    stop("Invalid DP mechanism family in the analysis contract",
         call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(mechanism$version, "DP mechanism version")
  sensitivity <- mechanism$sensitivity
  if (!is.list(sensitivity) || is.null(names(sensitivity)) ||
      !setequal(names(sensitivity), c("version", "norm", "value")) ||
      !identical(sensitivity$version, "dsvert-sensitivity-v1") ||
      !is.character(sensitivity$norm) || length(sensitivity$norm) != 1L ||
      is.na(sensitivity$norm) ||
      !sensitivity$norm %in% c("l1", "l2") ||
      !is.numeric(sensitivity$value) || length(sensitivity$value) != 1L ||
      is.na(sensitivity$value) || !is.finite(sensitivity$value) ||
      sensitivity$value <= 0 ||
      (identical(mechanism$family, "gaussian") &&
       !identical(sensitivity$norm, "l2")) ||
      (!identical(mechanism$family, "gaussian") &&
       !identical(sensitivity$norm, "l1"))) {
    stop("Invalid sensitivity in the analysis contract", call. = FALSE)
  }
  calibration <- mechanism$calibration
  if (!is.list(calibration) || is.null(names(calibration)) ||
      !setequal(names(calibration), c(
        "version", "noise_scale", "sampler", "implementation_delta")) ||
      !identical(calibration$version, "dsvert-calibration-v1") ||
      !is.numeric(calibration$noise_scale) ||
      length(calibration$noise_scale) != 1L ||
      is.na(calibration$noise_scale) || !is.finite(calibration$noise_scale) ||
      calibration$noise_scale <= 0 ||
      !is.numeric(calibration$implementation_delta) ||
      length(calibration$implementation_delta) != 1L ||
      is.na(calibration$implementation_delta) ||
      !is.finite(calibration$implementation_delta) ||
      calibration$implementation_delta < 0 ||
      calibration$implementation_delta > privacy$delta) {
    stop("Invalid mechanism calibration in the analysis contract",
         call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(calibration$sampler, "DP sampler")
  randomness <- mechanism$randomness
  if (!is.list(randomness) || is.null(names(randomness)) ||
      !setequal(names(randomness), c("version", "lanes")) ||
      !identical(randomness$version, "dsvert-randomness-plan-v1")) {
    stop("Invalid randomness plan in the analysis contract",
         call. = FALSE)
  }
  lanes <- .dsvert_dp_analysis_named_list(
    randomness$lanes, "randomness lanes")
  if (!"final_noise" %in% names(lanes)) {
    stop("Invalid randomness lanes in the analysis contract",
         call. = FALSE)
  }
  for (lane_name in names(lanes)) {
    .dsvert_dp_analysis_scalar_id(lane_name, "randomness lane")
    lane <- lanes[[lane_name]]
    if (!is.list(lane) || is.null(names(lane)) ||
        !setequal(names(lane), c(
          "version", "purpose", "primitive", "coordinates")) ||
        !identical(lane$version, "dsvert-randomness-lane-v1")) {
      stop("Invalid randomness lane in the analysis contract",
           call. = FALSE)
    }
    .dsvert_dp_analysis_scalar_id(lane$purpose, "randomness purpose")
    .dsvert_dp_analysis_scalar_id(lane$primitive, "randomness primitive")
    expected_purpose <- if (identical(lane_name, "final_noise")) {
      "privatize_final_vector"
    } else {
      "confidential_internal_randomness"
    }
    if (!identical(lane$purpose, expected_purpose)) {
      stop("Invalid randomness purpose in the analysis contract",
           call. = FALSE)
    }
    if (identical(lane_name, "final_noise") &&
        !identical(lane$primitive, calibration$sampler)) {
      stop("The final randomness primitive does not match the DP sampler",
           call. = FALSE)
    }
    lane$coordinates <- .dsvert_dp_analysis_positive_integer(
      lane$coordinates, "randomness coordinates")
    lanes[[lane_name]] <- lane
  }
  randomness$lanes <- lanes
  mechanism$randomness <- randomness
  mechanism <- .dsvert_dp_analysis_calibration_validate_v1(
    mechanism, privacy$epsilon, privacy$delta,
    lanes$final_noise$coordinates)
  count_tv <- identical(
    mechanism$version, .DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM)
  if (!identical(count_tv,
                 identical(analysis$primitive, "joint-dp-laplace-v2"))) {
    stop("The exact Count primitive and TV mechanism must be paired",
         call. = FALSE)
  }
  if (count_tv &&
      (!identical(sensitivity$value, 1) ||
       !identical(names(lanes), "final_noise"))) {
    stop("The Count TV mechanism does not match the audited worker",
         call. = FALSE)
  }
  privacy$mechanism <- mechanism
  value$privacy <- privacy

  numeric <- value$numeric
  if (!is.list(numeric) || is.null(names(numeric)) ||
      !setequal(names(numeric), c(
        "version", "value_bits", "fractional_bits", "rounding", "overflow",
        "sampler_encoding", "output_encoding")) ||
      !identical(numeric$version, "dsvert-numeric-semantics-v1") ||
      !is.character(numeric$rounding) || length(numeric$rounding) != 1L ||
      is.na(numeric$rounding) ||
      !numeric$rounding %in% c("nearest_even", "toward_zero") ||
      !is.character(numeric$overflow) || length(numeric$overflow) != 1L ||
      is.na(numeric$overflow) ||
      !numeric$overflow %in% c("reject", "saturate")) {
    stop("Invalid numeric semantics in the analysis contract",
         call. = FALSE)
  }
  numeric$value_bits <- .dsvert_dp_analysis_positive_integer(
    numeric$value_bits, "numeric value bits")
  numeric$fractional_bits <- .dsvert_dp_analysis_nonnegative_integer(
    numeric$fractional_bits, "numeric fractional bits")
  if (numeric$fractional_bits >= numeric$value_bits) {
    stop("Invalid numeric scale in the analysis contract", call. = FALSE)
  }
  if (count_tv &&
      (!identical(numeric$value_bits, 127) ||
       !identical(numeric$fractional_bits, 0) ||
       !identical(numeric$rounding, "toward_zero") ||
       !identical(numeric$overflow, "reject") ||
       !identical(numeric$sampler_encoding,
                  "aes128ctr_integer_coordinate_v2") ||
       !identical(numeric$output_encoding,
                  "twos_complement_integer_v1"))) {
    stop("The exact Count numeric contract must fail closed",
         call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(
    numeric$sampler_encoding, "sampler encoding")
  .dsvert_dp_analysis_scalar_id(numeric$output_encoding, "output encoding")
  value$numeric <- numeric
  .dsvert_dp_analysis_named_list(value$public_shape, "public result shape")
  if (count_tv && !identical(value$public_shape, list(count = 1))) {
    stop("The exact Count public shape is invalid", call. = FALSE)
  }
  .dsvert_dp_analysis_canonical_value_v1(value)
}

.dsvert_dp_analysis_artifact_key_v1 <- function(semantic) {
  semantic <- .dsvert_dp_analysis_semantic_validate_v1(semantic)
  digest::digest(
    object = charToRaw(paste0(
      .DSVERT_DP_ANALYSIS_ARTIFACT_DOMAIN,
      .dsvert_dp_canonical_json(semantic))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_analysis_execution_validate_v1 <- function(value, semantic) {
  value <- tryCatch(
    .dsvert_dp_analysis_canonical_value_v1(value),
    error = function(error) stop(
      "Invalid canonical execution contract: ", conditionMessage(error),
      call. = FALSE))
  fields <- c(
    "version", "peer_pins", "backend", "transport")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_ANALYSIS_EXECUTION_VERSION)) {
    stop("Invalid execution contract", call. = FALSE)
  }
  pins <- .dsvert_dp_analysis_named_list(value$peer_pins, "peer pins")
  normalized_pins <- vapply(pins, function(pin) {
    .dsvert_dp_analysis_identity_pk(pin, "peer pin")
  }, character(1L))
  owners <- names(semantic$owner_snapshots)
  if (length(normalized_pins) != length(owners) ||
      anyDuplicated(normalized_pins) ||
      !setequal(unname(normalized_pins), owners)) {
    stop("Invalid peer pins in the execution contract", call. = FALSE)
  }
  value$peer_pins <- as.list(normalized_pins)
  backend <- value$backend
  if (!is.list(backend) || is.null(names(backend)) ||
      !setequal(names(backend), c("kernel", "build_sha256", "ring")) ||
      !identical(backend$kernel, semantic$analysis$primitive) ||
      !is.character(backend$ring) || length(backend$ring) != 1L ||
      is.na(backend$ring) ||
      !backend$ring %in% c("ring127", "ring128") ||
      !is.character(backend$build_sha256) ||
      length(backend$build_sha256) != 1L || is.na(backend$build_sha256) ||
      !grepl("^[0-9a-f]{64}$", backend$build_sha256)) {
    stop("Invalid execution backend", call. = FALSE)
  }
  physical_ring_bits <- switch(
    backend$ring, ring127 = 127, ring128 = 128)
  if (physical_ring_bits < semantic$numeric$value_bits) {
    stop("The execution ring is too small for the semantic value domain",
         call. = FALSE)
  }
  if (identical(
      semantic$privacy$mechanism$version,
      .DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM) &&
      !identical(backend$ring, "ring127")) {
    stop("The execution ring does not support the exact Count backend",
         call. = FALSE)
  }
  transport <- value$transport
  if (!is.list(transport) || is.null(names(transport)) ||
      !identical(names(transport), "chunk_coordinates")) {
    stop("Invalid execution transport", call. = FALSE)
  }
  transport$chunk_coordinates <- .dsvert_dp_analysis_positive_integer(
    transport$chunk_coordinates, "transport chunk coordinates")
  if (identical(
      semantic$version, .DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION) &&
      !identical(transport$chunk_coordinates,
        semantic$analysis$effective_arguments$sampler_plan$chunk_coordinates)) {
    stop("Invalid execution transport", call. = FALSE)
  }
  value$transport <- transport
  .dsvert_dp_analysis_canonical_value_v1(value)
}

.dsvert_dp_analysis_contract_v1 <- function(semantic, execution) {
  semantic <- .dsvert_dp_analysis_semantic_validate_v1(semantic)
  execution <- .dsvert_dp_analysis_execution_validate_v1(
    execution, semantic)
  .dsvert_dp_analysis_canonical_value_v1(list(
    version = .DSVERT_DP_ANALYSIS_CONTRACT_VERSION,
    artifact_key = .dsvert_dp_analysis_artifact_key_v1(semantic),
    semantic = semantic,
    execution = execution))
}

.dsvert_dp_analysis_contract_validate_v1 <- function(value) {
  value <- tryCatch(
    .dsvert_dp_analysis_canonical_value_v1(value),
    error = function(error) stop(
      "Invalid canonical analysis contract: ", conditionMessage(error),
      call. = FALSE))
  fields <- c("version", "artifact_key", "semantic", "execution")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_ANALYSIS_CONTRACT_VERSION) ||
      !is.character(value$artifact_key) ||
      length(value$artifact_key) != 1L || is.na(value$artifact_key) ||
      !grepl("^[0-9a-f]{64}$", value$artifact_key)) {
    stop("Invalid analysis contract", call. = FALSE)
  }
  semantic <- .dsvert_dp_analysis_semantic_validate_v1(value$semantic)
  execution <- .dsvert_dp_analysis_execution_validate_v1(
    value$execution, semantic)
  expected <- .dsvert_dp_analysis_artifact_key_v1(semantic)
  if (!identical(value$artifact_key, expected)) {
    stop("The analysis artifact key does not match its semantic contract",
         call. = FALSE)
  }
  .dsvert_dp_analysis_canonical_value_v1(list(
    version = .DSVERT_DP_ANALYSIS_CONTRACT_VERSION,
    artifact_key = expected,
    semantic = semantic,
    execution = execution))
}

.dsvert_dp_analysis_snapshot_commitment_v1 <- function(descriptor) {
  descriptor <- tryCatch(
    .dsvert_dp_analysis_canonical_value_v1(descriptor),
    error = function(error) stop(
      "Invalid snapshot commitment descriptor: ", conditionMessage(error),
      call. = FALSE))
  fields <- c(
    "domain", "cohort_id", "owner_identity_pk", "dataset_id",
    "dataset_version", "snapshot_sha256", "alignment_version",
    "alignment_sha256")
  if (!is.list(descriptor) || is.null(names(descriptor)) ||
      !setequal(names(descriptor), fields)) {
    stop("Invalid snapshot commitment descriptor", call. = FALSE)
  }
  for (field in c(
      "domain", "cohort_id", "dataset_id", "dataset_version",
      "alignment_version")) {
    .dsvert_dp_analysis_scalar_id(
      descriptor[[field]], paste("snapshot", field))
  }
  descriptor$owner_identity_pk <- .dsvert_dp_analysis_identity_pk(
    descriptor$owner_identity_pk, "snapshot owner identity")
  local_identity <- .dsvert_dp_analysis_identity_pk(
    .get_identity_keypair()$identity_pk, "local identity")
  if (!identical(descriptor$owner_identity_pk, local_identity)) {
    stop("The snapshot commitment owner is not the local identity",
         call. = FALSE)
  }
  for (field in c("snapshot_sha256", "alignment_sha256")) {
    if (!is.character(descriptor[[field]]) ||
        length(descriptor[[field]]) != 1L ||
        is.na(descriptor[[field]]) ||
        !grepl("^[0-9a-f]{64}$", descriptor[[field]])) {
      stop("Invalid snapshot commitment descriptor", call. = FALSE)
    }
  }
  digest::hmac(
    key = .dsvert_dp_analysis_snapshot_key_v1(),
    object = charToRaw(paste0(
      .DSVERT_DP_ANALYSIS_SNAPSHOT_DOMAIN,
      .dsvert_dp_canonical_json(descriptor))),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_sticky_subseed_from_artifact_v1 <- function(
    artifact_key, lanes, noise_authorities, lane) {
  .dsvert_dp_analysis_scalar_id(lane, "sticky randomness lane")
  if (!lane %in% names(lanes)) {
    stop("The sticky randomness lane is not declared by the analysis",
         call. = FALSE)
  }
  noise_authority <- .dsvert_dp_analysis_identity_pk(
    .get_identity_keypair()$identity_pk, "local noise authority")
  if (!noise_authority %in% unlist(noise_authorities, use.names = FALSE)) {
    stop("The local identity is not a designated noise authority",
         call. = FALSE)
  }
  message <- .dsvert_dp_canonical_json(
    .dsvert_dp_analysis_canonical_value_v1(list(
      version = "dsvert-sticky-artifact-subseed-v1",
      artifact_key = artifact_key,
      lane = lane,
      lane_descriptor = lanes[[lane]],
      noise_authority = noise_authority)))
  digest::hmac(
    key = .dsvert_dp_sticky_noise_key_v1(),
    object = charToRaw(paste0(.DSVERT_DP_STICKY_SUBSEED_DOMAIN, message)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_sticky_subseed_v1 <- function(
    contract, lane) {
  contract <- .dsvert_dp_analysis_contract_validate_v1(contract)
  noise_authorities <- if (identical(
      contract$semantic$version,
      .DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION)) {
    contract$semantic$noise_authority_roles$authority_ids
  } else {
    contract$semantic$noise_authorities
  }
  .dsvert_dp_sticky_subseed_from_artifact_v1(
    contract$artifact_key,
    contract$semantic$privacy$mechanism$randomness$lanes,
    noise_authorities, lane)
}
