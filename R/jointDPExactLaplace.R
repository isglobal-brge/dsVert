# Public, exact arithmetic checks for the unbounded v4 Laplace contract.
.DSVERT_JOINT_DP_PURE_CERTIFICATE_FIELDS <- c(
  "guarantee", "randomness", "noise_support", "noise_commitment",
  "representability_bound", "wrap_bound_certified", "wrap_bound",
  "wrap_bound_event", "admitted_ranges")

.dsvert_joint_dp_exact_exponential_bound <- function(numerator, denominator,
                                                    multiplicity) {
  # exp(3)>10; decimal exponents stay integers, never floating probabilities.
  power <- 0L
  factor <- 1
  while (factor < multiplicity) {
    power <- power + 1L
    factor <- factor * 10
  }
  exponent <- numerator %/% (3 * denominator)
  if (exponent <= power) return("1")
  paste0("1e-", as.character(exponent - power))
}

.dsvert_joint_dp_exact_decimal_fraction <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value) > 512L ||
      !grepl("^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$", value)) {
    stop("Invalid exact Laplace decimal.", call. = FALSE)
  }
  parts <- strsplit(tolower(value), "e", fixed = TRUE)[[1L]]
  exponent <- if (length(parts) == 2L) as.numeric(parts[[2L]]) else 0
  if (!is.finite(exponent) || abs(exponent) > 10000) {
    stop("Invalid exact Laplace decimal exponent.", call. = FALSE)
  }
  normalized <- paste0(parts[[1L]], "e", if (exponent >= 0) "+" else "-",
                       abs(exponent))
  .dsvert_dp_analysis_frequency_decimal_fraction_v1(normalized)
}

.dsvert_joint_dp_pure_request <- function(request) {
  fail <- function() stop("Invalid exact Laplace admitted ranges.", call. = FALSE)
  if (!is.list(request) || !setequal(names(request), c(
      "epsilon", "delta", "sensitivity_steps", "total_coordinate_count")) ||
      !is.character(request$sensitivity_steps) ||
      length(request$sensitivity_steps) != 1L ||
      is.na(request$sensitivity_steps) ||
      nchar(request$sensitivity_steps) > 512L ||
      !grepl("^[1-9][0-9]*$", request$sensitivity_steps) ||
      !is.numeric(request$total_coordinate_count) ||
      length(request$total_coordinate_count) != 1L ||
      is.na(request$total_coordinate_count) ||
      request$total_coordinate_count < 1 ||
      request$total_coordinate_count > 1000000 ||
      request$total_coordinate_count != floor(request$total_coordinate_count)) fail()
  epsilon <- tryCatch(.dsvert_joint_dp_exact_decimal_fraction(
    request$epsilon), error = function(e) NULL)
  delta <- tryCatch(.dsvert_joint_dp_exact_decimal_fraction(
    request$delta), error = function(e) NULL)
  if (is.null(epsilon) || is.null(delta) || epsilon$numerator == 0 ||
      epsilon$numerator > 10000 * epsilon$denominator ||
      delta$numerator >= delta$denominator) fail()
  sensitivity <- openssl::bignum(request$sensitivity_steps)
  denominator <- epsilon$denominator * sensitivity
  if (epsilon$numerator * (openssl::bignum(2)^100) < denominator) fail()
  list(numerator = epsilon$numerator, denominator = denominator,
       epsilon = epsilon, dimension = request$total_coordinate_count)
}

.dsvert_joint_dp_pure_certificate <- function(request) {
  rate <- .dsvert_joint_dp_pure_request(request)
  bound <- .dsvert_joint_dp_exact_exponential_bound(
    rate$numerator * (openssl::bignum(2)^127), rate$denominator,
    2 * rate$dimension)
  list(guarantee = "pure-dp-under-ideal-bits",
    randomness = "keyed-stream-computational",
    noise_support = "unbounded_integer", noise_commitment = "modulo_2^128",
    representability_bound = bound, wrap_bound_certified = TRUE,
    wrap_bound = bound,
    wrap_bound_event = "at_least_one_peer_draw_outside_signed_Ring128",
    admitted_ranges = list(epsilon_minimum_exclusive = "0",
      epsilon_maximum = "10000", sensitivity_steps = "positive_integer",
      epsilon_over_sensitivity_minimum = "2^-100",
      total_coordinate_count_minimum = 1L,
      total_coordinate_count_maximum = 1000000L, ring_bits = 128L))
}

.dsvert_joint_dp_pure_plan_validate <- function(plan, request) {
  fail <- function() stop("Invalid exact Laplace plan certificate.", call. = FALSE)
  expected <- .dsvert_joint_dp_pure_certificate(request)
  if (!is.list(plan) || anyDuplicated(names(plan)) ||
      !all(names(expected) %in% names(plan)) ||
      !identical(.dsvert_dp_canonical_query_value(plan[names(expected)]),
                 .dsvert_dp_canonical_query_value(expected)) ||
      !identical(plan$version, .DSVERT_JOINT_DP_VECTOR_PURE_PLAN_VERSION) ||
      !identical(plan$sampler, .DSVERT_JOINT_DP_VECTOR_PURE_SAMPLER) ||
      !identical(plan$sensitivity_steps, request$sensitivity_steps) ||
      !identical(as.numeric(plan$total_coordinate_count),
                 as.numeric(request$total_coordinate_count)) ||
      !identical(plan$maximum_noise_magnitude, "unbounded") ||
      !identical(plan$complete_epsilon_per_peer, TRUE) ||
      !identical(plan$epsilon_divided_by_peer_count, FALSE) ||
      !identical(plan$release_implementation_delta_aggregation, "max_per_peer_not_sum") ||
      !identical(as.numeric(plan$stop_bits), 0) ||
      !identical(plan$stop_numerator, "0") ||
      !identical(as.numeric(plan$uniform_bits), 0) ||
      !identical(as.numeric(plan$binary_geometric_bits), 0) ||
      length(plan$bernoulli_thresholds) != 0L ||
      !identical(as.numeric(plan$independent_noise_peer_count), 2) ||
      !identical(as.numeric(plan$geometric_variables_per_peer_per_coordinate), 2) ||
      !identical(as.numeric(plan$geometric_variables_total_per_coordinate), 4)) fail()
  for (prefix in c("one_geometric_tv", "tail_upper", "rounding_upper",
      "implementation_delta", "per_peer_implementation_delta",
      "two_peer_ideal_transfer_delta")) {
    if (!identical(plan[[paste0(prefix, "_numerator")]], "0") ||
        !identical(plan[[paste0(prefix, "_denominator")]], "1")) fail()
  }
  epsilon <- .dsvert_joint_dp_pure_request(request)$epsilon
  if (!identical(plan$epsilon_effective_upper_numerator,
                 as.character(epsilon$numerator)) ||
      !identical(plan$epsilon_effective_upper_denominator,
                 as.character(epsilon$denominator))) fail()
  invisible(.dsvert_dp_canonical_query_value(plan))
}

.dsvert_joint_dp_pure_sum_certificate <- function(plan, maximum) {
  boundary <- openssl::bignum(2)^127
  if (maximum >= boundary) stop("Invalid exact Laplace source bound.", call. = FALSE)
  threshold <- (boundary - maximum) %/% openssl::bignum(2)
  numerator <- openssl::bignum(plan$epsilon_effective_upper_numerator)
  denominator <- openssl::bignum(plan$epsilon_effective_upper_denominator) *
    openssl::bignum(plan$sensitivity_steps)
  list(sum_wrap_bound = .dsvert_joint_dp_exact_exponential_bound(
    numerator * threshold, denominator, 2 * plan$total_coordinate_count),
    sum_wrap_threshold = as.character(threshold))
}

.dsvert_joint_dp_pure_output_certificate <- function(plan, bounds, shifts) {
  maximum <- openssl::bignum(0)
  for (index in seq_along(bounds)) {
    value <- openssl::bignum(bounds[[index]]) * (openssl::bignum(2)^shifts[[index]])
    if (value > maximum) maximum <- value
  }
  c(plan[.DSVERT_JOINT_DP_PURE_CERTIFICATE_FIELDS],
    .dsvert_joint_dp_pure_sum_certificate(plan, maximum))
}
