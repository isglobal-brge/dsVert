# Explicit new arithmetic admission. Legacy signed q64 contracts remain valid
# as references, but cannot authorize this producer.
.DSVERT_DP_GLM_GRID_PROFILE_V2 <- "cross-grid-certified-piecewise-k64-v2"
.DSVERT_DP_GLM_GRID_CERTIFICATE_V2 <-
  "47e35ff8ca9368367b9015a5aeb4395c832be1df51ab0b8d25673259000dd80e"

.dsvert_dp_glm_grid_profile_certificate <- function() {
  path <- system.file("cross-grid-v2", "admission_certificate.json",
                      package = "dsVert")
  if (!nzchar(path) || !identical(digest::digest(
      file = path, algo = "sha256"), .DSVERT_DP_GLM_GRID_CERTIFICATE_V2)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  jsonlite::fromJSON(path, simplifyVector = FALSE)
}

.dsvert_dp_glm_grid_profile_spec <- function(spec) {
  certificate <- .dsvert_dp_glm_grid_profile_certificate()
  # Use the exact expansion comparator from V1, scaled by powers of two.
  # A rounded binary64 sum must not select an envelope that is too small.
  envelopes <- c(1, 2, 4, 8, 16)
  fits <- vapply(envelopes, function(a) all(vapply(spec$beta_grid,
    function(beta) .dsvert_dp_glm_grid_cross_beta_l1_valid(
      unlist(beta, use.names = FALSE) * (16 / a)), logical(1L))), logical(1L))
  if (!any(fits)) .dsvert_dp_glm_grid_cross_fail()
  a <- envelopes[which(fits)[[1L]]]
  entry <- certificate$caps18[[which(envelopes == a)]]
  poisson <- identical(spec$family, "poisson")
  cap18 <- if (poisson) entry$poisson_caps18[[spec$max_outcome]] else
    entry$binomial_cap18
  cap <- ceiling(cap18 / 2^(18 - spec$numeric_grid_bits))
  error <- if (poisson) entry$poisson_error else entry$binomial_error
  multiplier <- if (identical(spec$adjacency, "add_remove_patient")) 1 else 2
  caps <- rep(cap, length(spec$beta_grid))
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps)
  maxima <- spec$observation_capacity * caps
  if (any(!is.finite(c(l1, l2, maxima))) ||
      any(c(l1, l2, maxima) > 2^53 - 1)) .dsvert_dp_glm_grid_cross_fail()
  spec$sensitivity$candidate_bounds <- lapply(
    spec$sensitivity$candidate_bounds, function(bound) {
      bound$loss_bound <- cap / 2^spec$numeric_grid_bits
      bound$per_patient_cap <- cap
      bound$profile_envelope <- a
      bound$certified_loss_error <- error
      bound
    })
  spec$sensitivity$maximum_coordinates <- as.list(maxima)
  spec$sensitivity$raw_l1_sensitivity <- l1
  spec$sensitivity$raw_l2_sensitivity <- l2
  spec$sensitivity$natural_l1_sensitivity <- l1 / 2^spec$numeric_grid_bits
  spec$sensitivity$natural_l2_sensitivity <- l2 / 2^spec$numeric_grid_bits
  spec$numeric_contract <- list(
    version = "cross-grid-public-numeric-contract-v2",
    profile_identity = .DSVERT_DP_GLM_GRID_PROFILE_V2,
    profile_sha256 = certificate$kernel_profiles_sha256,
    certificate_sha256 = .DSVERT_DP_GLM_GRID_CERTIFICATE_V2,
    input_fraction_bits = 50, coefficient_fraction_bits = 50,
    coefficient_encoding = "signed_decimal_integer_v1",
    dot_fraction_bits = 100, dot_width_bits = 128,
    nonlinear_word_bits = 32, product_width_bits = 64,
    eta_fraction_bits = if (poisson) 26 else 16,
    loss_fraction_bits = if (poisson) 26 else 16,
    exponential_output_bits = if (poisson) 40 else 0,
    profile_envelope = a, pieces = 64,
    rounding_rule = "nearest_ties_to_even",
    certified_loss_error = error,
    cap_rule = certificate$cap_rule,
    envelope_rule = certificate$envelope_rule,
    evaluation_order = paste0(
      "exact_f100_dot;private_source_and_alignment_mask;round_eta;project;",
      if (poisson) "reduced_exp_k64;private_log_factorial;integer_outcome_product;"
      else "softplus_k64;binary_outcome_mux;",
      "clamp;quantize_g;candidate_sum"))
  spec
}

.dsvert_dp_glm_grid_profile_admit <- function(contract, policy, schema) {
  version <- tryCatch(contract$spec$version, error = function(error) NULL)
  if (identical(version, "nb_grid_cross_v1")) {
    return(.dsvert_dp_nb_grid_cross_contract_validate(contract, policy, schema))
  }
  if (isTRUE(version %in% c("multinomial_grid_cross_v1", "ordinal_grid_cross_v1"))) {
    family <- sub("_grid_cross_v1$", "", version)
    return(.dsvert_dp_categorical_grid_cross_contract_validate(contract, policy, schema, family))
  }
  value <- .dsvert_dp_glm_grid_cross_contract_validate(contract, policy, schema)
  if (!identical(value$spec$numeric_contract$profile_identity,
                 .DSVERT_DP_GLM_GRID_PROFILE_V2)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  value
}
