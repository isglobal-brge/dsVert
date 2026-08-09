# Numeric-safety policy published by each data custodian.
#
# Bounds and backend allowlists are server options.  The analyst can inspect
# them but cannot override them through an aggregate-method argument.

.dsvert_numeric_option <- function(name, default = NULL) {
  value <- getOption(paste0("dsvert.numeric.", name))
  if (is.null(value)) {
    value <- getOption(paste0("default.dsvert.numeric.", name))
  }
  if (is.null(value)) default else value
}

.dsvert_numeric_scalar <- function(value, name, lower = 0,
                                   integer = FALSE,
                                   lower_inclusive = FALSE) {
  below_lower <- if (isTRUE(lower_inclusive)) value < lower else value <= lower
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || below_lower ||
      (isTRUE(integer) &&
       (value != floor(value) || value > .Machine$integer.max))) {
    qualifier <- if (isTRUE(integer)) "integer" else "number"
    comparison <- if (isTRUE(lower_inclusive)) "at least " else "greater than "
    stop(name, " must be one finite ", qualifier, " ", comparison, lower,
         call. = FALSE)
  }
  if (isTRUE(integer)) as.integer(value) else as.numeric(value)
}

.dsvert_numeric_family_values <- function(value, name, lower = 0) {
  families <- c("gaussian", "binomial", "poisson")
  if (!is.list(value) || !identical(sort(names(value)), sort(families))) {
    stop(name, " must be a list with gaussian, binomial, and poisson",
         call. = FALSE)
  }
  stats::setNames(vapply(families, function(family) {
    .dsvert_numeric_scalar(value[[family]], paste0(name, "$", family), lower)
  }, numeric(1L)), families)
}

.dsvert_numeric_glm_bounds <- function() {
  defaults <- list(
    # Raw host-language inputs are checked before centring/scaling so that
    # IEEE-754 overflow cannot be hidden by a later transformation.  The
    # tighter max_abs_predictor/max_abs_response bounds below apply to the
    # values that are actually fixed-point encoded.
    max_abs_predictor_input = 1e12,
    max_abs_predictor = 16,
    max_abs_response_input = list(
      gaussian = 1e12, binomial = 1, poisson = 1e6),
    max_abs_response = list(
      gaussian = 16, binomial = 1, poisson = 1e6),
    max_abs_linear_predictor = list(
      gaussian = 64, binomial = 8, poisson = 5),
    # Rigorous Clenshaw bounds use |U_j(x)| <= j+1 on |x| <= 1.
    # The shipped coefficient sets remain below 4 (sigmoid degree 29) and
    # 407 (exp degree 30); rounded powers leave explicit implementation
    # headroom without relying on observed patient values.
    max_abs_approximation_intermediate = list(
      gaussian = 64, binomial = 8, poisson = 1024),
    max_abs_offset = 16,
    max_abs_weight = 100,
    max_observations = 1e7,
    max_predictors = 10000L,
    max_iterations = 10000L,
    max_numeric_error = 1e-4
  )
  configured <- .dsvert_numeric_option("glm_bounds", defaults)
  if (!is.list(configured)) {
    stop("dsvert.numeric.glm_bounds must be a list", call. = FALSE)
  }
  bounds <- utils::modifyList(defaults, configured, keep.null = TRUE)
  list(
    max_abs_predictor_input = .dsvert_numeric_scalar(
      bounds$max_abs_predictor_input,
      "dsvert.numeric.glm_bounds$max_abs_predictor_input"),
    max_abs_predictor = .dsvert_numeric_scalar(
      bounds$max_abs_predictor,
      "dsvert.numeric.glm_bounds$max_abs_predictor"),
    max_abs_response_input = .dsvert_numeric_family_values(
      bounds$max_abs_response_input,
      "dsvert.numeric.glm_bounds$max_abs_response_input"),
    max_abs_response = .dsvert_numeric_family_values(
      bounds$max_abs_response,
      "dsvert.numeric.glm_bounds$max_abs_response"),
    max_abs_linear_predictor = .dsvert_numeric_family_values(
      bounds$max_abs_linear_predictor,
      "dsvert.numeric.glm_bounds$max_abs_linear_predictor"),
    max_abs_approximation_intermediate = .dsvert_numeric_family_values(
      bounds$max_abs_approximation_intermediate,
      paste0("dsvert.numeric.glm_bounds$",
             "max_abs_approximation_intermediate")),
    max_abs_weight = .dsvert_numeric_scalar(
      bounds$max_abs_weight,
      "dsvert.numeric.glm_bounds$max_abs_weight"),
    max_abs_offset = .dsvert_numeric_scalar(
      bounds$max_abs_offset,
      "dsvert.numeric.glm_bounds$max_abs_offset"),
    max_observations = .dsvert_numeric_scalar(
      bounds$max_observations,
      "dsvert.numeric.glm_bounds$max_observations", integer = TRUE),
    max_predictors = .dsvert_numeric_scalar(
      bounds$max_predictors,
      "dsvert.numeric.glm_bounds$max_predictors", integer = TRUE),
    max_iterations = .dsvert_numeric_scalar(
      bounds$max_iterations,
      "dsvert.numeric.glm_bounds$max_iterations", integer = TRUE),
    max_numeric_error = .dsvert_numeric_scalar(
      bounds$max_numeric_error,
      "dsvert.numeric.glm_bounds$max_numeric_error")
  )
}

.dsvert_numeric_exact_gc_probe <- function() {
  if (!exists(".exact_gc_capability_probe", mode = "function",
              inherits = TRUE)) {
    return(NULL)
  }
  tryCatch(.exact_gc_capability_probe(), error = function(e) NULL)
}

.dsvert_numeric_runtime_capabilities <- function() {
  # `available` means the arithmetic exists in the installed helper.  A
  # backend is certifiable only when every stronger boolean is also TRUE.
  # The current fast rings validate public encodings and canonical wire
  # records, but chained local truncation is not exact and intermediate
  # custodian bounds are not yet enforced end-to-end.
  exact_probe <- .dsvert_numeric_exact_gc_probe()
  exact_probe_observed <- !is.null(exact_probe)
  exact_supported <- if (exact_probe_observed &&
                         is.numeric(exact_probe$supported_ring_bits) &&
                         length(exact_probe$supported_ring_bits)) {
    as.integer(exact_probe$supported_ring_bits)
  } else {
    c(63L, 127L)
  }
  exact_max_ring <- if (exact_probe_observed &&
                        is.numeric(exact_probe$max_ring_bits) &&
                        length(exact_probe$max_ring_bits) == 1L &&
                        is.finite(exact_probe$max_ring_bits)) {
    as.integer(exact_probe$max_ring_bits)
  } else {
    127L
  }
  exact_max_frac <- if (exact_probe_observed &&
                        is.numeric(exact_probe$max_frac_bits) &&
                        length(exact_probe$max_frac_bits) == 1L &&
                        is.finite(exact_probe$max_frac_bits)) {
    as.integer(exact_probe$max_frac_bits)
  } else {
    50L
  }
  # A primitive probe is intentionally not a workload attestation.  These
  # adapters stay FALSE until every operation used by the GLM route is bound
  # to the probed backend and covered by execution attestations.
  workload_adapter_verified <- FALSE

  list(
    ring63 = list(
      available = TRUE, e2e_verified = FALSE,
      canonical_encoding = TRUE, fail_closed_overflow = FALSE,
      runtime_bounds_enforced = FALSE, exact_truncation = FALSE,
      workload_adapter_e2e_verified = workload_adapter_verified,
      public_scalar_mul_truncate_e2e_verified = FALSE,
      full_iteration_e2e_verified = FALSE,
      exact_comparison = FALSE, ring_bits = 63L, frac_bits = 20L,
      supported_ring_bits = 63L, max_ring_bits = 63L,
      max_frac_bits = 20L, truncation_semantics = "local_probabilistic",
      runtime_probe_observed = TRUE
    ),
    ring127 = list(
      available = TRUE, e2e_verified = FALSE,
      canonical_encoding = TRUE, fail_closed_overflow = FALSE,
      runtime_bounds_enforced = FALSE, exact_truncation = FALSE,
      workload_adapter_e2e_verified = workload_adapter_verified,
      public_scalar_mul_truncate_e2e_verified = FALSE,
      full_iteration_e2e_verified = FALSE,
      exact_comparison = FALSE, ring_bits = 127L, frac_bits = 50L,
      supported_ring_bits = 127L, max_ring_bits = 127L,
      max_frac_bits = 50L, truncation_semantics = "local_probabilistic",
      runtime_probe_observed = TRUE
    ),
    exact_gc = list(
      available = exact_probe_observed, e2e_verified = FALSE,
      canonical_encoding = exact_probe_observed &&
        isTRUE(exact_probe$canonical_encoding),
      fail_closed_overflow = FALSE,
      runtime_bounds_enforced = FALSE, exact_truncation = FALSE,
      workload_adapter_e2e_verified = workload_adapter_verified,
      public_scalar_mul_truncate_e2e_verified = FALSE,
      full_iteration_e2e_verified = FALSE,
      exact_comparison = FALSE, ring_bits = NA_integer_, frac_bits = NA_integer_,
      supported_ring_bits = exact_supported, max_ring_bits = exact_max_ring,
      max_frac_bits = exact_max_frac,
      truncation_semantics = if (exact_probe_observed &&
        identical(exact_probe$truncation_semantics, "floor")) {
        "floor"
      } else {
        "unavailable"
      },
      runtime_probe_observed = exact_probe_observed
    ),
    multiprecision = list(
      available = FALSE, e2e_verified = FALSE,
      canonical_encoding = FALSE, fail_closed_overflow = FALSE,
      runtime_bounds_enforced = FALSE, exact_truncation = FALSE,
      workload_adapter_e2e_verified = workload_adapter_verified,
      public_scalar_mul_truncate_e2e_verified = FALSE,
      full_iteration_e2e_verified = FALSE,
      exact_comparison = FALSE, ring_bits = NA_integer_, frac_bits = NA_integer_,
      supported_ring_bits = integer(), max_ring_bits = NA_integer_,
      max_frac_bits = NA_integer_, truncation_semantics = "unavailable",
      runtime_probe_observed = FALSE
    )
  )
}

.dsvert_numeric_canonicalize <- function(value) {
  if (is.list(value)) {
    value_names <- names(value)
    if (!is.null(value_names)) {
      if (anyNA(value_names) || anyDuplicated(value_names)) {
        stop("numeric policy objects require unique non-missing names",
             call. = FALSE)
      }
      value <- value[order(value_names)]
    }
    return(lapply(value, .dsvert_numeric_canonicalize))
  }
  value_names <- names(value)
  if (!is.null(value_names)) {
    if (anyNA(value_names) || anyDuplicated(value_names)) {
      stop("numeric policy vectors require unique non-missing names",
           call. = FALSE)
    }
    value <- value[order(value_names)]
  }
  value
}

.dsvert_numeric_hash <- function(value) {
  canonical <- jsonlite::toJSON(
    .dsvert_numeric_canonicalize(value),
    auto_unbox = TRUE, null = "null", na = "null", digits = 17,
    pretty = FALSE)
  digest::digest(canonical, algo = "sha256", serialize = FALSE)
}

.dsvert_numeric_policy_hash <- function(policy) {
  policy$policy_id <- NULL
  .dsvert_numeric_hash(policy)
}

.dsvert_numeric_assert_vector <- function(values, bound, what,
                                           lower = NULL,
                                           integer = FALSE) {
  if (!(is.numeric(values) || is.logical(values))) {
    stop("DSVERT_NUMERIC_BOUND_FAILURE: ", what, " must be numeric",
         call. = FALSE)
  }
  values <- as.numeric(values)
  if (any(!is.finite(values))) {
    stop("DSVERT_NUMERIC_BOUND_FAILURE: ", what,
         " contains NA, NaN, Inf, or -Inf", call. = FALSE)
  }
  if (length(values) && any(abs(values) > bound)) {
    stop("DSVERT_NUMERIC_BOUND_FAILURE: ", what,
         " exceeds the custodian-owned public bound", call. = FALSE)
  }
  if (!is.null(lower) && length(values) && any(values < lower)) {
    stop("DSVERT_NUMERIC_DOMAIN_FAILURE: ", what,
         " is outside its supported domain", call. = FALSE)
  }
  if (isTRUE(integer) && length(values) && any(values != floor(values))) {
    stop("DSVERT_NUMERIC_DOMAIN_FAILURE: ", what,
         " must contain integer-valued observations", call. = FALSE)
  }
  invisible(values)
}

.dsvert_numeric_assert_fp_encoding <- function(values, ring, frac_bits,
                                                what) {
  ring <- .dsvert_numeric_scalar(ring, "ring", lower = 1, integer = TRUE)
  frac_bits <- .dsvert_numeric_scalar(
    frac_bits, "frac_bits", lower = 0, integer = TRUE,
    lower_inclusive = TRUE)
  if (!(is.numeric(values) || is.logical(values)) ||
      any(!is.finite(as.numeric(values)))) {
    stop("DSVERT_NUMERIC_ENCODING_FAILURE: ", what,
         " contains a non-finite or non-numeric value", call. = FALSE)
  }
  nonzero <- abs(as.numeric(values))
  nonzero <- nonzero[nonzero > 0]
  if (length(nonzero) &&
      any(log2(nonzero) + frac_bits >= ring - 1L)) {
    stop("DSVERT_NUMERIC_ENCODING_FAILURE: ", what,
         " is not representable in the requested signed fixed-point ring",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_numeric_attestation_binding <- function(
    kind, policy_id, session_id, data_name, variables, family, ring, n) {
  .dsvert_numeric_hash(list(
    schema_version = 1L,
    kind = kind,
    policy_id = policy_id,
    session_id = session_id,
    data_name = data_name,
    variables = as.character(variables),
    family = family,
    ring = as.integer(ring),
    n = as.integer(n)))
}

.dsvert_numeric_attestation <- function(kind, policy, session_id, data_name,
                                        variables, family, ring, n,
                                        checks) {
  if (!is.character(kind) || length(kind) != 1L || is.na(kind) ||
      !nzchar(kind) || !is.character(session_id) ||
      length(session_id) != 1L || is.na(session_id) || !nzchar(session_id) ||
      !is.character(data_name) || length(data_name) != 1L ||
      is.na(data_name) || !nzchar(data_name) ||
      !is.character(variables) || anyNA(variables) ||
      !is.character(family) || length(family) != 1L || is.na(family) ||
      !family %in% c("gaussian", "binomial", "poisson") ||
      !is.numeric(ring) || length(ring) != 1L || is.na(ring) ||
      !ring %in% c(63L, 127L) ||
      !is.numeric(n) || length(n) != 1L || is.na(n) || !is.finite(n) ||
      n < 1L || n != floor(n) || n > .Machine$integer.max ||
      !is.list(checks) || !length(checks) ||
      any(!vapply(checks, isTRUE, logical(1L)))) {
    stop("Cannot construct a malformed numeric execution attestation",
         call. = FALSE)
  }
  binding_id <- .dsvert_numeric_attestation_binding(
    kind, policy$policy_id, session_id, data_name, variables, family, ring, n)
  list(
    schema_version = 1L,
    kind = kind,
    policy_id = policy$policy_id,
    binding_id = binding_id,
    ring = as.integer(ring),
    n = as.integer(n),
    checks = checks,
    runtime_input_bounds_enforced = TRUE,
    runtime_intermediate_bounds_enforced = FALSE,
    observed_extrema_released = FALSE,
    attestation_scope = paste(
      "finite/domain checks plus pre-transform and encoded-input bounds;",
      "no claim about every arithmetic intermediate"))
}

.dsvert_numeric_policy <- function() {
  enabled <- .dsvert_numeric_option("enabled", TRUE)
  if (!is.logical(enabled) || length(enabled) != 1L || is.na(enabled)) {
    stop("dsvert.numeric.enabled must be TRUE or FALSE", call. = FALSE)
  }

  runtime <- .dsvert_numeric_runtime_capabilities()
  backend_names <- names(runtime)
  allowed <- .dsvert_numeric_option(
    "allowed_backends", c("ring63", "ring127", "exact_gc", "multiprecision"))
  if (!is.character(allowed) || anyNA(allowed)) {
    stop("dsvert.numeric.allowed_backends must be a character vector",
         call. = FALSE)
  }
  allowed <- unique(tolower(trimws(allowed)))
  invalid <- setdiff(allowed, backend_names)
  if (length(invalid)) {
    stop("Unknown numeric backend(s): ", paste(invalid, collapse = ", "),
         call. = FALSE)
  }
  for (backend in backend_names) {
    runtime[[backend]]$allowed <- isTRUE(enabled) && backend %in% allowed
  }

  policy <- list(
    schema_version = 1L,
    policy_version = "dsvert-numeric-policy-v1",
    enabled = isTRUE(enabled),
    workload = "glm",
    bounds = .dsvert_numeric_glm_bounds(),
    approximation = list(
      gaussian = list(domain = NULL, max_abs_error = 0),
      binomial = list(domain = c(-8, 8), max_abs_error = 6.5e-6),
      poisson = list(domain = c(-5, 5), max_abs_error = 5e-10)
    ),
    capabilities = runtime
  )
  policy$policy_id <- .dsvert_numeric_policy_hash(policy)
  policy
}

#' Publish the custodian-owned numeric policy
#'
#' Returns public bounds and runtime capabilities used by the client numeric
#' preflight.  It accepts no analyst-provided bounds or capability overrides.
#'
#' @return A public numeric-policy list.
#' @export
dsvertNumericPolicyDS <- function() {
  .dsvert_numeric_policy()
}
