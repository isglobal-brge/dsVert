# Internal postprocessing boundary for a future formal-GLM/common
# jointDPVector release.  It consumes only the already-DP, exactly-once common
# opening; it cannot receive shares or seeds and performs no second opening.

.DSVERT_FORMAL_GLM_PHASE16_RELEASE_VERSION <-
  "dsvert-formal-glm-phase16-release-adapter-v1"
.DSVERT_FORMAL_GLM_PHASE16_DP_BLOCKER <-
  "formal_glm_productive_joint_dp_release_lifecycle_unavailable"
.DSVERT_FORMAL_GLM_PHASE16_MECHANISM <-
  "joint_discrete_gaussian_one_global_draw"
.DSVERT_FORMAL_GLM_PHASE16_ALLOCATION <-
  "one_stacked_capsule_vector"
.DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_KIND <-
  "machine_proven_integer_lattice_l2_v1"
.DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_VERSION <-
  "dsvert-formal-glm-phase15-l2-sensitivity-certificate-v1"
.DSVERT_FORMAL_GLM_PHASE16_UNIVERSAL_PROOF <-
  "projected-quantized-coefficient-box-global-l2-diameter-v2"
.DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF <-
  "exact-fixed-point-coordinate-recurrence-signed-floor-lattice-l2-v1"

.dsvert_formal_glm_phase16_unsigned_integer <- function(value, what) {
  if (!is.character(value) || !length(value) || anyNA(value) ||
      any(!grepl("^(0|[1-9][0-9]*)$", value))) {
    stop("Invalid formal-GLM ", what, ".", call. = FALSE)
  }
  unname(value)
}

.dsvert_formal_glm_phase16_ceil_sqrt <- function(squared) {
  low <- openssl::bignum(0)
  high <- openssl::bignum(1)
  while (high * high < squared) high <- high * openssl::bignum(2)
  while (high - low > openssl::bignum(1)) {
    middle <- (low + high) %/% openssl::bignum(2)
    if (middle * middle < squared) low <- middle else high <- middle
  }
  if (low * low == squared) low else high
}

.dsvert_formal_glm_phase16_binding_projection <- function(binding) {
  required <- c(
    "version", "binding_sha256", "common_ring_bits",
    "output_lattice_bits", "coordinate_count", "shifted_upper_bounds",
    "signed_lower_bounds", "signed_upper_bounds", "sensitivity_steps",
    "mechanism", "allocation", "sensitivity_norm", "sensitivity_proof",
    "sensitivity_certificate_kind", "sensitivity_certificate_sha256",
    "sensitivity_certificate", "tight_sensitivity_status", "quantization",
    "signed_decode", "quantization_error", "range_certificate",
    "no_wrap_certificate", "opening_count", "production_ready")
  if (!is.list(binding) || is.null(names(binding)) ||
      anyNA(names(binding)) || anyDuplicated(names(binding)) ||
      !all(required %in% names(binding)) ||
      !identical(binding$version,
                 .DSVERT_FORMAL_GLM_PHASE16_RELEASE_VERSION) ||
      !is.character(binding$binding_sha256) ||
      length(binding$binding_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", binding$binding_sha256) ||
      !identical(as.numeric(binding$common_ring_bits), 128) ||
      !is.numeric(binding$output_lattice_bits) ||
      length(binding$output_lattice_bits) != 1L ||
      is.na(binding$output_lattice_bits) ||
      binding$output_lattice_bits < 1L ||
      binding$output_lattice_bits > 62L ||
      binding$output_lattice_bits != floor(binding$output_lattice_bits) ||
      !is.numeric(binding$coordinate_count) ||
      length(binding$coordinate_count) != 1L ||
      is.na(binding$coordinate_count) || binding$coordinate_count < 1L ||
      binding$coordinate_count != floor(binding$coordinate_count) ||
      !identical(binding$mechanism,
                 .DSVERT_FORMAL_GLM_PHASE16_MECHANISM) ||
      !identical(binding$allocation,
                 .DSVERT_FORMAL_GLM_PHASE16_ALLOCATION) ||
      !identical(binding$sensitivity_norm, "l2") ||
      !binding$sensitivity_proof %in% c(
        .DSVERT_FORMAL_GLM_PHASE16_UNIVERSAL_PROOF,
        .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF) ||
      !identical(binding$sensitivity_certificate_kind,
                 .DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_KIND) ||
      !is.character(binding$sensitivity_certificate_sha256) ||
      length(binding$sensitivity_certificate_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", binding$sensitivity_certificate_sha256) ||
      !identical(binding$tight_sensitivity_status, "machine_proven") ||
      !identical(binding$quantization,
        "signed_floor_inside_exact_gc_then_public_translation_v1") ||
      !identical(binding$signed_decode,
        "subtract_public_quantized_box_after_single_dp_opening_v1") ||
      !identical(binding$quantization_error, paste0(
        "0<=exact_coefficient-released_lattice_coefficient<",
        "2^-output_lattice_bits_before_dp_noise_v1")) ||
      !identical(binding$range_certificate, paste0(
        "translated_coordinate_in_[0,2Bq]_and_signed_release_",
        "in_[-Bq,Bq]_v1")) ||
      !identical(binding$no_wrap_certificate, paste0(
        "bridge_coordinates_l2_sensitivity_and_common_gaussian_",
        "saturating_clamp_ring128_checked_v1")) ||
      !identical(as.numeric(binding$opening_count), 1) ||
      !identical(binding$production_ready, FALSE)) {
    stop(paste(
      "The formal-GLM release lacks its selected machine-proven",
      "signed/no-wrap contract."), call. = FALSE)
  }
  upper <- .dsvert_formal_glm_phase16_unsigned_integer(
    unlist(binding$shifted_upper_bounds, use.names = FALSE),
    "translated upper bounds")
  lower <- unlist(binding$signed_lower_bounds, use.names = FALSE)
  signed_upper <- .dsvert_formal_glm_phase16_unsigned_integer(
    unlist(binding$signed_upper_bounds, use.names = FALSE),
    "signed upper bounds")
  if (!is.character(lower) || anyNA(lower) ||
      any(!grepl("^-[1-9][0-9]*$", lower)) ||
      length(upper) != binding$coordinate_count ||
      length(lower) != binding$coordinate_count ||
      length(signed_upper) != binding$coordinate_count) {
    stop("Invalid formal-GLM signed release range.", call. = FALSE)
  }
  centers <- vapply(seq_along(upper), function(index) {
    value <- openssl::bignum(upper[[index]])
    if (value <= 0 || value %% openssl::bignum(2) != 0) {
      stop("Invalid formal-GLM translated release range.", call. = FALSE)
    }
    center <- value %/% openssl::bignum(2)
    if (!identical(lower[[index]], paste0("-", as.character(center))) ||
        !identical(signed_upper[[index]], as.character(center))) {
      stop("The formal-GLM signed bounds do not match their translation.",
           call. = FALSE)
    }
    as.character(center)
  }, character(1L))
  sensitivity <- .dsvert_formal_glm_phase16_unsigned_integer(
    binding$sensitivity_steps, "selected L2 sensitivity")
  if (identical(sensitivity[[1L]], "0")) {
    stop("The formal-GLM L2 sensitivity must be positive.", call. = FALSE)
  }
  squared <- Reduce(`+`, lapply(upper, function(value) {
    value <- openssl::bignum(value)
    value * value
  }), init = openssl::bignum(0))
  universal_root <- .dsvert_formal_glm_phase16_ceil_sqrt(squared)
  certificate <- binding$sensitivity_certificate
  certificate_required <- c(
    "version", "kind", "status", "norm", "selected_proof",
    "selected_bound_steps", "coordinate_count", "output_lattice_bits",
    "shifted_upper_bounds", "universal_coordinate_bounds",
    "universal_l2_squared", "universal_bound_steps",
    "recurrence_quantized_bounds", "recurrence_l2_squared",
    "recurrence_bound_steps", "quantization_inequality", "selection")
  if (!is.list(certificate) || is.null(names(certificate)) ||
      anyNA(names(certificate)) || anyDuplicated(names(certificate)) ||
      !all(certificate_required %in% names(certificate)) ||
      !identical(certificate$version,
                 .DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_VERSION) ||
      !identical(certificate$kind,
                 .DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_KIND) ||
      !identical(certificate$status, "machine_proven") ||
      !identical(certificate$norm, "l2") ||
      !identical(certificate$selected_proof, binding$sensitivity_proof) ||
      !identical(certificate$selected_bound_steps, sensitivity[[1L]]) ||
      !identical(as.numeric(certificate$coordinate_count),
                 as.numeric(binding$coordinate_count)) ||
      !identical(as.numeric(certificate$output_lattice_bits),
                 as.numeric(binding$output_lattice_bits)) ||
      !identical(
        unname(unlist(certificate$shifted_upper_bounds, use.names = FALSE)),
        upper) ||
      !identical(
        unname(unlist(certificate$universal_coordinate_bounds,
                      use.names = FALSE)), upper) ||
      !identical(certificate$universal_l2_squared,
                 as.character(squared)) ||
      !identical(certificate$universal_bound_steps,
                 as.character(universal_root)) ||
      !identical(certificate$quantization_inequality, paste0(
        "abs(floor(x/d)-floor(y/d))<=ceil(abs(x-y)/d)_",
        "per_coordinate_v1")) ||
      !identical(certificate$selection,
        "minimum_of_machine_proven_positive_integer_l2_bounds_v1")) {
    stop("The formal-GLM L2 sensitivity certificate is inconsistent.",
         call. = FALSE)
  }
  recurrence_bounds <- .dsvert_formal_glm_phase16_unsigned_integer(
    unlist(certificate$recurrence_quantized_bounds, use.names = FALSE),
    "recurrence coordinate sensitivity")
  if (length(recurrence_bounds) != binding$coordinate_count) {
    stop("The formal-GLM recurrence certificate has the wrong shape.",
         call. = FALSE)
  }
  recurrence_squared <- Reduce(`+`, lapply(recurrence_bounds, function(value) {
    value <- openssl::bignum(value)
    value * value
  }), init = openssl::bignum(0))
  recurrence_root <- .dsvert_formal_glm_phase16_ceil_sqrt(
    recurrence_squared)
  # The common Gaussian planner requires a positive integer sensitivity even
  # for a constant query; one remains a valid upper bound in that case.
  if (recurrence_root == openssl::bignum(0)) {
    recurrence_root <- openssl::bignum(1)
    recurrence_squared <- openssl::bignum(1)
  }
  if (!identical(certificate$recurrence_l2_squared,
                 as.character(recurrence_squared)) ||
      !identical(certificate$recurrence_bound_steps,
                 as.character(recurrence_root))) {
    stop("The formal-GLM recurrence L2 bound was not reproduced.",
         call. = FALSE)
  }
  expected_proof <- .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF
  expected_bound <- recurrence_root
  if (universal_root < recurrence_root) {
    expected_proof <- .DSVERT_FORMAL_GLM_PHASE16_UNIVERSAL_PROOF
    expected_bound <- universal_root
  }
  if (!identical(binding$sensitivity_proof, expected_proof) ||
      !identical(sensitivity[[1L]], as.character(expected_bound))) {
    stop("The formal-GLM minimum machine-proven L2 bound was not selected.",
         call. = FALSE)
  }
  list(upper = upper, centers = centers,
       output_lattice_bits = as.integer(binding$output_lattice_bits),
       coordinate_count = as.integer(binding$coordinate_count))
}

.dsvert_formal_glm_phase16_signed_postprocess <- function(
    common_opening, binding) {
  checked <- .dsvert_formal_glm_phase16_binding_projection(binding)
  required <- c(
    "release_binding_sha256", "clamped_scaled_values", "validity",
    "preclamp_values_returned", "source_share_exposed",
    "private_seed_exposed", "openings_performed")
  if (!is.list(common_opening) || is.null(names(common_opening)) ||
      anyNA(names(common_opening)) || anyDuplicated(names(common_opening)) ||
      !setequal(names(common_opening), required) ||
      !identical(common_opening$release_binding_sha256,
                 binding$binding_sha256) ||
      !identical(common_opening$validity, TRUE) ||
      !identical(common_opening$preclamp_values_returned, FALSE) ||
      !identical(common_opening$source_share_exposed, FALSE) ||
      !identical(common_opening$private_seed_exposed, FALSE) ||
      !identical(as.numeric(common_opening$openings_performed), 1)) {
    stop("The common DP finalizer did not perform exactly one bound opening.",
         call. = FALSE)
  }
  values <- .dsvert_formal_glm_phase16_unsigned_integer(
    unlist(common_opening$clamped_scaled_values, use.names = FALSE),
    "common DP opening")
  if (length(values) != checked$coordinate_count) {
    stop("The common DP opening has the wrong coordinate shape.",
         call. = FALSE)
  }
  signed <- vapply(seq_along(values), function(index) {
    value <- openssl::bignum(values[[index]])
    upper <- openssl::bignum(checked$upper[[index]])
    center <- openssl::bignum(checked$centers[[index]])
    # This is validation, not a second clamp: an out-of-contract common
    # finalizer result is rejected and never silently changed.
    if (value > upper) {
      stop("The common DP opening is outside its certified range.",
           call. = FALSE)
    }
    if (value >= center) return(as.character(value - center))
    paste0("-", as.character(center - value))
  }, character(1L))
  denominator <- openssl::bignum(2) ^ checked$output_lattice_bits
  .dsvert_dp_canonical_query_value(list(
    version = "dsvert-formal-glm-phase16-signed-release-v1",
    release_binding_sha256 = binding$binding_sha256,
    signed_lattice_values = as.list(signed),
    coefficient_denominator = as.character(denominator),
    coefficient_encoding = "exact_signed_rational_common_power_of_two_v1",
    output_lattice_bits = checked$output_lattice_bits,
    dp_noise_included = TRUE,
    mechanism = binding$mechanism,
    allocation = binding$allocation,
    sensitivity_norm = binding$sensitivity_norm,
    sensitivity_steps = binding$sensitivity_steps,
    signed_decenter = binding$signed_decode,
    quantization = binding$quantization,
    quantization_error = binding$quantization_error,
    range_certificate = binding$range_certificate,
    no_wrap_certificate = binding$no_wrap_certificate,
    total_openings = 1L, additional_openings = 0L,
    common_shifted_values_returned = FALSE,
    exact_beta_returned = FALSE,
    source_share_exposed = FALSE,
    private_seed_exposed = FALSE))
}

.dsvert_formal_glm_phase16_authorize_opening <- function(binding) {
  if (!is.list(binding) ||
      !identical(binding$version,
                 .DSVERT_FORMAL_GLM_PHASE16_RELEASE_VERSION) ||
      !is.character(binding$binding_sha256) ||
      length(binding$binding_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", binding$binding_sha256) ||
      !identical(binding$mechanism,
                 .DSVERT_FORMAL_GLM_PHASE16_MECHANISM) ||
      !identical(binding$allocation,
                 .DSVERT_FORMAL_GLM_PHASE16_ALLOCATION) ||
      !identical(as.numeric(binding$opening_count), 1) ||
      !identical(binding$production_ready, FALSE)) {
    stop("Invalid formal-GLM Phase-1.6 release binding.", call. = FALSE)
  }
  stop(structure(list(
    message = paste(
      "Formal GLM remains sealed: its durable Phase-1.9 output is not yet",
      "wired into the compiled cross-signed productive joint-DP worker and",
      "exactly-once finalizer."),
    call = NULL,
    code = .DSVERT_FORMAL_GLM_PHASE16_DP_BLOCKER,
    missing = paste(
      "durable Phase-1.9 output-to-productive-worker admission and the",
      "common exactly-once joint-DP release lifecycle"),
    openings_performed = 0L,
    production_ready = FALSE),
    class = c("dsvert_formal_glm_phase16_release_unavailable",
              "error", "condition")))
}
