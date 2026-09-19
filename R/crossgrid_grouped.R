# Additive grouped contracts. A validated contract never authorizes execution;
# the fused source/grouping/noise/evidence adapter must be integrated separately.
.DSVERT_DP_GROUPED_CROSS_FAMILIES <- c(
  "lmm", "binomial_glmm", "poisson_glmm", "binomial_gee", "poisson_gee")
.DSVERT_DP_GROUPED_CROSS_VERSION <- "dsvert-grouped-cross-signed-contract-v1"
.DSVERT_DP_GROUPED_CROSS_DOMAIN <- "dsVert/grouped-cross-contract/v1|"

.dsvert_dp_grouped_cross_fail <- function() .dsvert_dp_glm_grid_cross_fail()

.dsvert_dp_grouped_cross_scalar <- function(value, lower, upper) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < lower || value > upper) {
    .dsvert_dp_grouped_cross_fail()
  }
  as.numeric(value)
}

.dsvert_dp_grouped_cross_parameters <- function(value, family) {
  if (identical(family, "lmm") && "objective" %in% names(value)) {
    return(.dsvert_dp_grouped_cross_ml_parameters(value))
  }
  if (identical(family, "binomial_glmm") && "variance_grid" %in% names(value)) {
    .dsvert_dp_glm_grid_cross_fields(value, c("variance_grid", "quadrature"))
    if (!is.list(value$variance_grid) || !is.null(names(value$variance_grid)) ||
        !length(value$variance_grid) || length(value$variance_grid) > 2L ||
        !identical(value$quadrature, "gh5_fixed_v1")) .dsvert_dp_grouped_cross_fail()
    grid <- lapply(value$variance_grid, function(tau) {
      tau <- .dsvert_dp_grouped_cross_scalar(tau, 0, .25)
      if (!tau %in% c(0, .25)) .dsvert_dp_grouped_cross_fail()
      tau
    })
    if (any(diff(unlist(grid, use.names = FALSE)) <= 0)) .dsvert_dp_grouped_cross_fail()
    return(list(variance_grid = grid, quadrature = "gh5_fixed_v1"))
  }
  fields <- if (family == "lmm") {
    c("residual_variance", "random_intercept_variance")
  } else if (grepl("_glmm$", family)) {
    c("random_intercept_variance", "quadrature")
  } else c("correlation", "rho", "score_clip")
  .dsvert_dp_glm_grid_cross_fields(value, fields)
  if (family == "lmm") {
    sigma <- .dsvert_dp_grouped_cross_scalar(value$residual_variance, .25, 16)
    tau <- .dsvert_dp_grouped_cross_scalar(value$random_intercept_variance, 0, 16)
    if (any(c(sigma, tau) * 2^16 != round(c(sigma, tau) * 2^16))) {
      .dsvert_dp_grouped_cross_fail()
    }
    return(list(residual_variance = sigma, random_intercept_variance = tau))
  }
  if (grepl("_glmm$", family)) {
    tau <- .dsvert_dp_grouped_cross_scalar(value$random_intercept_variance, 0, .25)
    if (!tau %in% c(0, .25) || !identical(value$quadrature, "gh5_fixed_v1")) {
      .dsvert_dp_grouped_cross_fail()
    }
    return(list(random_intercept_variance = tau, quadrature = "gh5_fixed_v1"))
  }
  if (!is.character(value$correlation) || length(value$correlation) != 1L ||
      !value$correlation %in% c("independence", "exchangeable", "ar1")) {
    .dsvert_dp_grouped_cross_fail()
  }
  rho <- .dsvert_dp_grouped_cross_scalar(value$rho, 0, .5)
  if (!rho %in% c(0, .25, .5) ||
      (value$correlation == "independence" && rho != 0)) {
    .dsvert_dp_grouped_cross_fail()
  }
  clip <- .dsvert_dp_grouped_cross_scalar(value$score_clip, .25, 4)
  if (clip * 4 != floor(clip * 4)) .dsvert_dp_grouped_cross_fail()
  list(correlation = value$correlation, rho = rho, score_clip = clip)
}

# These are enforced range caps, independently of the approximation accuracy.
# The DP unit remains a patient. Add/remove changes one cluster; replacement
# (including movement) changes at most two. Each coordinate is clamped inside
# its declared interval before output quantization and exact cluster reduction.
.dsvert_dp_grouped_cross_sensitivity <- function(
    beta_grid, family, max_outcome, grid_bits, grouping, parameters, adjacency,
    numeric_contract) {
  if (identical(family, "lmm") && identical(parameters$objective, "ml")) {
    return(.dsvert_dp_grouped_cross_ml_sensitivity(beta_grid, grid_bits, grouping,
      parameters, adjacency, numeric_contract))
  }
  scale <- 2^grid_bits
  B <- grouping$max_patients_per_cluster
  C <- grouping$cluster_capacity
  multiplier <- if (identical(adjacency, "add_remove_patient")) 1 else {
    if (!identical(adjacency, "replace_one_fixed_cohort")) {
      .dsvert_dp_grouped_cross_fail()
    }
    2
  }
  bounds <- if (identical(family, "binomial_glmm") && !is.null(parameters$variance_grid)) {
    unlist(lapply(parameters$variance_grid, function(tau) {
      .dsvert_dp_grouped_cross_sensitivity(beta_grid, family, max_outcome,
        grid_bits, grouping, list(random_intercept_variance = tau,
          quadrature = parameters$quadrature), adjacency, numeric_contract)$candidate_bounds
    }), recursive = FALSE)
  } else lapply(beta_grid, function(beta) {
    beta <- unlist(beta, use.names = FALSE)
    a <- beta[1L] + sum(pmin(beta[-1L], 0))
    b <- beta[1L] + sum(pmax(beta[-1L], 0))
    A <- max(abs(a), abs(b))
    error <- numeric_contract$per_cluster_error_bound
    if (family == "lmm") {
      H <- B * max(abs(b), abs(1-a))^2 / parameters$residual_variance
      caps <- ceiling(scale * (H + error))
      labels <- "likelihood"
      shifts <- 0
    } else {
      glmm <- grepl("_glmm$", family)
      poisson <- startsWith(family, "poisson")
      T <- A + if (glmm) sqrt(parameters$random_intercept_variance) *
        2.856970013872806 else 0
      loss <- if (poisson) {
        # Safe asymmetric endpoint maximum plus explicit profile error slack.
        max(outer(0:max_outcome, c(-T, T), function(y, eta) {
          exp(eta) - y * eta + if (glmm) 2 else lgamma(y + 1)
        }))
      } else T + log1p(exp(-T))
      caps <- ceiling(scale * (B * loss + error))
      labels <- "likelihood"
      shifts <- 0
      if (!glmm) {
        dimension <- length(beta)
        upper <- which(upper.tri(matrix(0, dimension, dimension), diag = TRUE),
                       arr.ind = TRUE)
        kappa <- if (parameters$correlation == "independence") 1 else {
          if (parameters$correlation == "exchangeable") 1/(1-parameters$rho)
          else (1+parameters$rho)/(1-parameters$rho)
        }
        H <- B * kappa * if (poisson) exp(A) else .25
        bread_shift <- if (parameters$correlation == "independence") 0 else
          ceiling(scale * (H + error))
        bread_cap <- ceiling(scale * (H + error)) + bread_shift
        meat_cap <- ceiling(scale * 2 * parameters$score_clip^2)
        suffix <- paste0(upper[, 1L], ":", upper[, 2L])
        labels <- c(labels, paste0("bread:", suffix), paste0("meat:", suffix))
        caps <- c(caps, rep(bread_cap, nrow(upper)), rep(meat_cap, nrow(upper)))
        shifts <- c(0, rep(bread_shift, nrow(upper)),
                    rep(round(scale * parameters$score_clip^2), nrow(upper)))
      }
    }
    list(eta_lower = a, eta_upper = b, absolute_eta_bound = A,
         coordinate_labels = as.list(labels), per_cluster_caps = as.list(caps),
         coordinate_shifts = as.list(shifts))
  })
  caps <- unlist(lapply(bounds, `[[`, "per_cluster_caps"), use.names = FALSE)
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps)
  if (any(!is.finite(c(caps, C*caps, l1, l2))) ||
      any(c(caps, C*caps, l1, l2) > 2^53-1)) .dsvert_dp_grouped_cross_fail()
  list(dp_unit = "patient", influence_proof = "one_affected_cluster_range_v1",
       candidate_bounds = bounds, per_cluster_caps = as.list(caps),
       maximum_coordinates = as.list(C*caps), adjacency_multiplier = multiplier,
       raw_l1_sensitivity = l1, raw_l2_sensitivity = l2,
       natural_l1_sensitivity = l1/scale, natural_l2_sensitivity = l2/scale)
}

# Propagated v3 GEE bounds; exact-rational derivation is in
# NUMERIC_CERTIFICATE_GEE_WHITENING.md. g>=8, so 1/512 covers final rounding.
.dsvert_dp_grouped_gee_errors <- function(family, B, clip) {
  eta_error <- 1/131072 + 1e-12
  feature_error <- 1/131072 + 2^-51
  if (identical(family, "binomial_gee")) {
    mu_error <- 69/327680 + eta_error/4
    a_error <- 17/65536 + eta_error/4
    b_error <- 257/65536 + 4*eta_error
    loss_error <- 33/65536 + eta_error
    A <- .5; Z <- 8; residual_bound <- 1
  } else {
    mu_error <- .0055 + 55*eta_error
    a_error <- .0055 + 8*(eta_error/2 + 1/131072)
    b_error <- a_error
    loss_error <- .0055 + 59*eta_error + 1/131072
    A <- 8; Z <- 40; residual_bound <- 55
  }
  eu <- a_error + (A+a_error)*feature_error
  ez <- residual_bound*b_error + (8+b_error)*mu_error
  Eu <- 4*eu + 10*B*2^-64*(A+eu) + 2^-65
  Ez <- 4*ez + 10*B*2^-64*(Z+ez) + 2^-65
  score <- B*(4*A*Ez + 4*Z*Eu + Eu*Ez)
  bread <- B*(8*A*Eu + Eu^2)
  meat <- min(2*clip^2, 2*clip*(score+1/131072))
  # Outward slack exceeds rounding accumulated by these positive operations.
  as.list(c(likelihood=B*loss_error+1/512, bread=bread+1/512,
            meat=meat+1/512)*(1+256*.Machine$double.eps))
}

.dsvert_dp_grouped_cross_numeric <- function(family, grouping, parameters) {
  if (identical(family, "lmm") && identical(parameters$objective, "ml")) {
    return(.dsvert_dp_grouped_cross_ml_numeric(grouping, parameters))
  }
  B <- grouping$max_patients_per_cluster
  lmm <- identical(family, "lmm")
  gee <- grepl("_gee$", family)
  errors <- if (gee) .dsvert_dp_grouped_gee_errors(family, B, parameters$score_clip) else NULL
  out <- list(version = "grouped-fixed-profile-numeric-v1",
       profile = if (lmm) "grouped-lmm-stats-f264-q64-v2" else if (gee)
         "grouped-gee-whitening-f96-q64-v3" else if (family == "poisson_glmm")
         "grouped-gh5-poisson-selection-shift2-q16-v3" else "grouped-pwlinear-q16-k64-range-exp-v2",
       profile_sha256 = if (lmm) NULL else "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84",
       source_fraction_bits = 50, predictor_accumulation_fraction_bits = 100,
       predictor_rounding = if (lmm) "exact_f100_dot_no_intermediate_rounding_v1" else
         "complete_dot_once_nearest_ties_even_v1",
       internal_fraction_bits = if (lmm || gee) 64 else 16,
       nonlinear_word_bits = if (lmm) 0 else 32,
       rounding = "nearest_ties_even_v1", per_cluster_error_bound =
         if (lmm) 1e-8 else if (gee) max(unlist(errors)) else 1,
       quadrature_error_included = FALSE,
       integer_cap_enforced = TRUE, arithmetic_certificate_required = TRUE)
  if (family == "poisson_glmm") {
    out$objective <- "gh5_negative_log_kernel_without_factorial_v1"
    out$per_live_row_shift <- 2
    out$full_likelihood_value <- FALSE
  }
  if (gee) {
    out$coordinate_error_bounds <- errors
    out$factorial_q16 <- as.list(c(0, 0, 45426, 117425, 208277))
  }
  if (identical(family, "binomial_glmm") && !is.null(parameters$variance_grid)) {
    certificate <- "76490f13d69f7968b5fa435f1ac7b5da844b8f7476ad582669b4e41a95960377"
    paths <- system.file("certificates", c("grouped_binomial_glmm_gh5_v1.json",
      "grouped_pwlinear_q16_v1.json"), package = "dsVert")
    hashes <- c(certificate, out$profile_sha256)
    if (length(paths) != 2L || any(!nzchar(paths)) ||
        !identical(unname(vapply(paths, function(path) digest::digest(
          file = path, algo = "sha256"), character(1L))), hashes)) {
      .dsvert_dp_grouped_cross_fail()
    }
    # Retained groupedGLMMBounds plus worst final g>=8 quantization. The
    # signed error=1 strictly encloses this finite-GH5 arithmetic bound.
    error <- B*(34/65536 + 1e-12) + 1/131072 +
      4*(.00013 + 1/8000000) + 33/65536 + 1/512
    if (error >= out$per_cluster_error_bound) .dsvert_dp_grouped_cross_fail()
    out$certificate_sha256 <- certificate
    out$version <- "grouped-binomial-glmm-variance-grid-numeric-v1"
    out$objective <- "finite_gh5_binomial_negative_log_likelihood_v1"
    out$candidate_traversal <- "variance_then_beta_v1"
    out$composition_error_bound <- error * (1 + 256*.Machine$double.eps)
  }
  out
}

.dsvert_dp_grouped_cross_spec <- function(raw, policy, schema) {
  .dsvert_dp_glm_grid_cross_fields(raw, c(
    "version", "analysis_id", "dataset", "outcome", "predictor_order",
    "beta_grid", "max_outcome", "alignment", "grouping", "parameters"))
  family <- sub("_grid_cross_v1$", "", raw$version)
  if (length(family) != 1L || !family %in% .DSVERT_DP_GROUPED_CROSS_FAMILIES ||
      !identical(raw$version, paste0(family, "_grid_cross_v1"))) {
    .dsvert_dp_grouped_cross_fail()
  }
  # Reuse frozen canonical schema/owner/beta/alignment validation, then replace
  # family-specific source encoding, profile, statistic and sensitivity.
  base_raw <- raw[setdiff(names(raw), c("grouping", "parameters"))]
  base_raw$version <- if (startsWith(family, "poisson")) {
    "poisson_grid_cross_v1"
  } else "binomial_grid_cross_v1"
  base <- .dsvert_dp_glm_grid_cross_spec(base_raw, policy, schema)
  .dsvert_dp_glm_grid_cross_fields(raw$grouping, c(
    "reference", "cluster_capacity", "max_patients_per_cluster", "patient_rule",
    "ordering"))
  reference <- .dsvert_dp_glm_grid_cross_references(raw$grouping$reference)
  if (length(reference) != 1L || reference %in% unlist(base$input_variable_order) ||
      !identical(raw$grouping$patient_rule, "one_analysis_row_per_patient_v1") ||
      !identical(raw$grouping$ordering, "stable_signed_slots_preserve_gaps_v1")) {
    .dsvert_dp_grouped_cross_fail()
  }
  owner <- sub("\\$.*$", "", reference)
  column_name <- sub("^[^$]+\\$", "", reference)
  columns <- schema$unsigned$datasets[[raw$dataset]]$columns
  match <- vapply(names(columns), function(name) {
    identical(sub("^[^$]+\\$", "", name), column_name) &&
      identical(columns[[name]]$owner_peer, owner)
  }, logical(1L))
  if (sum(match) != 1L || !owner %in% names(policy$peer_pinset) ||
      !identical(columns[[which(match)]]$kind, "categorical")) {
    .dsvert_dp_grouped_cross_fail()
  }
  participants <- sort(unique(c(unlist(base$participating_peers), owner)),
                       method = "radix")
  if (!setequal(participants, names(policy$peer_pinset)) ||
      !all(unlist(base$computation_peers) %in% participants)) {
    .dsvert_dp_grouped_cross_fail()
  }
  C <- .dsvert_dp_glm_grid_cross_integer(raw$grouping$cluster_capacity,
    1, if (family %in% c("lmm", "binomial_glmm")) 500 else 64)
  B <- .dsvert_dp_glm_grid_cross_integer(raw$grouping$max_patients_per_cluster,
                                       1, if (grepl("_gee$", family)) 8 else 16)
  if (base$observation_capacity > B*C ||
      length(columns[[which(match)]]$levels) > C) .dsvert_dp_grouped_cross_fail()
  grouping <- list(reference = reference, owner_peer = owner,
    cluster_capacity = C, max_patients_per_cluster = B, padded_slots = B*C,
    patient_rule = "one_analysis_row_per_patient_v1",
    ordering = "stable_signed_slots_preserve_gaps_v1",
    routing = "primitive_v_benes_private_controls_v1",
    completeness = "private_and_after_routing_v1",
    overflow = "reject_outside_signed_admitted_domain_v1")
  parameters <- .dsvert_dp_grouped_cross_parameters(raw$parameters, family)
  if (C > 64) {
    # A separate signed validation domain; this descriptor is not capacity or
    # promotion evidence. Preserve the existing small-domain contract bytes.
    if (C != 500 || B != 4 || base$observation_capacity != 2000 ||
        length(base$predictors) > 3L ||
        !(identical(family, "lmm") && identical(parameters$objective, "ml") ||
          identical(family, "binomial_glmm") && !is.null(parameters$variance_grid)) ||
        length(parameters$variance_grid) * length(base$beta_grid) > 4L) {
      .dsvert_dp_grouped_cross_fail()
    }
    grouping$capacity_profile <- if (identical(family, "lmm"))
      "lmm-ml-n2000-c500-b4-p3-j4-v1" else "binomial-glmm-gh5-n2000-c500-b4-p3-j4-v1"
  }
  radius <- vapply(base$beta_grid, function(beta) sum(abs(unlist(beta))), numeric(1L))
  if ((grepl("_glmm$", family) && (any(radius > 1) || base$max_outcome > 4)) ||
      (grepl("_gee$", family) && (any(radius > 4) || base$max_outcome > 4 ||
       length(base$predictors) > 3L || length(base$beta_grid) > 32L))) {
    .dsvert_dp_grouped_cross_fail()
  }
  base$version <- raw$version
  base$family <- family
  base$participating_peers <- as.list(participants)
  base$outcome_encoding <- if (family == "lmm") {
    list(kind = "fixed_point", q = 50)
  } else list(kind = "integer")
  base$predictor_encoding <- list(kind = "fixed_point", q = 50)
  base$routing_inputs <- setNames(list(list(reference = reference,
    dataset = raw$dataset, owner_peer = owner, column = column_name,
    kind = "categorical", levels = as.list(unlist(columns[[which(match)]]$levels,
      use.names = FALSE)),
    encoding = "signed_level_index_zero_based_v1")), reference)
  base$grouping <- grouping
  base$parameters <- parameters
  if (identical(family, "lmm") && identical(parameters$objective, "ml")) {
    if (length(parameters$variance_grid) * length(base$beta_grid) > 256L) {
      .dsvert_dp_grouped_cross_fail()
    }
    base$candidate_grid <- unlist(lapply(seq_along(parameters$variance_grid), function(v) {
      lapply(seq_along(base$beta_grid), function(b) {
        list(variance_index = v, beta_index = b)
      })
    }), recursive = FALSE)
    base$candidate_order <- lapply(base$candidate_grid, function(candidate) {
      .dsvert_joint_dp_hash(list(objective = "ml",
        variance = parameters$variance_grid[[candidate$variance_index]],
        beta = base$beta_grid[[candidate$beta_index]]))
    })
  }
  if (identical(family, "binomial_glmm") && !is.null(parameters$variance_grid)) {
    if (length(base$predictors) > 3L ||
        length(parameters$variance_grid) * length(base$beta_grid) > 4L) {
      .dsvert_dp_grouped_cross_fail()
    }
    # Native predictor validation bounds the encoded complete dot. These
    # integer endpoint sums are exact in binary64 at p<=3 and |beta|<=1.
    for (encoded in base$beta_encoded) {
      beta <- as.numeric(unlist(encoded, use.names = FALSE))
      if (beta[1L] + sum(pmin(beta[-1L], 0)) < -2^50 ||
          beta[1L] + sum(pmax(beta[-1L], 0)) > 2^50) {
        .dsvert_dp_grouped_cross_fail()
      }
    }
    base$candidate_grid <- unlist(lapply(seq_along(parameters$variance_grid), function(v) {
      lapply(seq_along(base$beta_grid), function(b) {
        list(variance_index = v, beta_index = b)
      })
    }), recursive = FALSE)
    base$candidate_order <- lapply(base$candidate_grid, function(candidate) {
      .dsvert_joint_dp_hash(list(objective = "finite_gh5_binomial_negative_log_likelihood_v1",
        random_intercept_variance = parameters$variance_grid[[candidate$variance_index]],
        quadrature = parameters$quadrature, beta = base$beta_grid[[candidate$beta_index]]))
    })
  }
  base$numeric_contract <- .dsvert_dp_grouped_cross_numeric(family, grouping, parameters)
  base$preprocessing <- if (family == "lmm") {
    "clip_each_finite_record_then_patient_mean_unit_interval_outcome_v1"
  } else base$preprocessing
  base$complete_case <- "all_owned_validity_private_alignment_and_grouping_v1"
  base$sensitivity <- .dsvert_dp_grouped_cross_sensitivity(
    base$beta_grid, family, base$max_outcome, base$numeric_grid_bits,
    grouping, parameters, base$adjacency, base$numeric_contract)
  base
}

.dsvert_dp_grouped_cross_spec_validate <- function(value, policy, schema) {
  tryCatch({
    raw <- value[c("version", "analysis_id", "dataset", "predictor_order",
                   "beta_grid", "max_outcome", "alignment", "parameters")]
    raw$outcome <- value$outcome$reference
    raw$grouping <- value$grouping[c("reference", "cluster_capacity",
      "max_patients_per_cluster", "patient_rule", "ordering")]
    expected <- .dsvert_dp_grouped_cross_spec(raw, policy, schema)
    .dsvert_dp_glm_grid_cross_equal(value, expected)
    expected
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_grouped_cross_layout <- function(spec) {
  base <- spec
  count <- length(spec$sensitivity$per_cluster_caps)
  # Base layout uses candidate count to allocate its zero release prefix.
  base$beta_grid <- rep(list(NULL), count)
  base$observation_capacity <- spec$grouping$padded_slots
  layout <- .dsvert_dp_glm_grid_cross_layout(base)
  layout$version <- "dsvert-grouped-cross-private-source-layout-v1"
  if (spec$family == "lmm") {
    index <- length(layout$blocks)
    layout$blocks[[index]]$value_fraction_bits <- 50
    layout$blocks[[index]]$value_maximum <- 2^50
    layout$blocks[[index]]$value_encoding <- "normalized_unsigned_fixed_point_v1"
  }
  routing <- spec$routing_inputs[[spec$grouping$reference]]
  cursor <- layout$transport_coordinate_count + 1
  layout$blocks[[length(layout$blocks) + 1L]] <- list(
    reference = routing$reference, owner_peer = routing$owner_peer,
    value_start = cursor, validity_start = cursor + layout$padded_units,
    length = layout$padded_units, value_fraction_bits = 0,
    value_encoding = routing$encoding,
    value_maximum = length(routing$levels) - 1,
    validity_fraction_bits = 0, validity_maximum = 1,
    private_routing_input = TRUE)
  layout$transport_coordinate_count <- cursor + 2 * layout$padded_units - 1
  if (layout$transport_coordinate_count > 64 * 1024^2) {
    .dsvert_dp_grouped_cross_fail()
  }
  layout$block_order <- "predictors_then_outcome_then_private_routing_each_values_then_validity_v1"
  layout$grouping_controls <- list(
    source_peer = spec$grouping$owner_peer, private_control_bits = TRUE,
    source_reference = routing$reference,
    source_encoding_sha256 = .dsvert_joint_dp_hash(routing),
    padded_slots = spec$grouping$padded_slots,
    next_power_two_padding = TRUE, primitive = spec$grouping$routing,
    authenticated_private_sidecar_required = TRUE)
  layout
}

.dsvert_dp_grouped_cross_artifact <- function(spec) {
  list(version = paste0("bounded-", gsub("_", "-", spec$family), "-cross-grid-v1"),
       spec_version = spec$version, spec_sha256 = .dsvert_joint_dp_hash(spec),
       analysis_id = spec$analysis_id, owner_peer = spec$owner_peer,
       participating_peers = spec$participating_peers,
       computation_peers = spec$computation_peers, candidate_order = spec$candidate_order,
       coordinate_count = length(spec$sensitivity$per_cluster_caps),
       coordinate_order = "candidate_then_likelihood_bread_upper_meat_upper_v1",
       numeric_grid_bits = spec$numeric_grid_bits, sensitivity = spec$sensitivity,
       numeric_contract_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
       private_layout_sha256 = .dsvert_joint_dp_hash(.dsvert_dp_grouped_cross_layout(spec)),
       transcript = list(version = "grouped-fixed-chunk-schedule-v1",
         cluster_slots = spec$grouping$cluster_capacity,
         rows_per_cluster = spec$grouping$max_patients_per_cluster,
         cluster_batch_size = 1, candidate_batch_size = 1,
         traversal = "routing_stage_then_cluster_then_candidate_v1",
         source_cap_bytes = 2097152, input_cap_bits = 524288, gate_cap = 32000000,
         output = "two_authority_additive_coordinate_sum_shares_only_v1"),
       result_evidence_required = TRUE,
       implementation_state = "cross_owner_exact_gc_materialized",
       cross_owner_state = "exact_gc_to_joint_dp_vector_v1")
}

.dsvert_dp_grouped_cross_source_contract <- function(spec, artifact) {
  list(version = "dsvert-grouped-cross-private-source-contract-v1",
       purpose = "grouped_cross_inputs_grouping_controls_and_release_shares_only",
       spec_sha256 = .dsvert_joint_dp_hash(spec),
       artifact_sha256 = .dsvert_joint_dp_hash(artifact),
       schema_sha256 = spec$schema_sha256, logical_snapshot = spec$logical_snapshot,
       peer_pinset_sha256 = spec$peer_pinset_sha256,
       source_peers = spec$participating_peers, recipients = spec$computation_peers,
       alignment = spec$alignment,
       alignment_sharing = "recipient_specific_xor_share_exact_gc_gate_v1",
       private_layout = .dsvert_dp_grouped_cross_layout(spec))
}

.dsvert_dp_grouped_cross_message <- function(unsigned) {
  charToRaw(paste0(.DSVERT_DP_GROUPED_CROSS_DOMAIN,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_grouped_cross_contract_validate <- function(
    value, policy, schema_manifest, .verifier = .dsvert_relay_verify_message) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(value, c(
      "version", "spec", "artifact", "source_contract", "signatures"))
    if (!identical(value$version, .DSVERT_DP_GROUPED_CROSS_VERSION)) {
      .dsvert_dp_grouped_cross_fail()
    }
    schema <- .dsvert_dp_capsule_schema(
      policy, schema_manifest$logical_snapshot, schema_manifest, .verifier)
    spec <- .dsvert_dp_grouped_cross_spec_validate(value$spec, policy, schema)
    artifact <- .dsvert_dp_grouped_cross_artifact(spec)
    .dsvert_dp_glm_grid_cross_equal(value$artifact, artifact)
    .dsvert_dp_glm_grid_cross_equal(value$source_contract,
      .dsvert_dp_grouped_cross_source_contract(spec, artifact))
    pins <- policy$peer_pinset
    .dsvert_dp_glm_grid_cross_fields(value$signatures, names(pins))
    unsigned <- value[setdiff(names(value), "signatures")]
    message <- .dsvert_dp_grouped_cross_message(unsigned)
    verified <- vapply(names(pins), function(peer) {
      signature <- value$signatures[[peer]]
      is.character(signature) && length(signature) == 1L && !is.na(signature) &&
        grepl("^[A-Za-z0-9_-]{86}$", signature) &&
        isTRUE(.verifier(message, unname(pins[[peer]]), signature))
    }, logical(1L))
    if (!all(verified)) .dsvert_dp_grouped_cross_fail()
    .dsvert_dp_canonical_query_value(value)
  }, error = .dsvert_dp_transcript_stop)
}

# One integration entry point. No unverified callback can convert this contract
# into a production materializer; execution stays closed until reviewed wiring.
.dsvert_register_grouped_cross <- function() {
  list(versions = paste0(.DSVERT_DP_GROUPED_CROSS_FAMILIES, "_grid_cross_v1"),
       build_spec = .dsvert_dp_grouped_cross_spec,
       validate_contract = .dsvert_dp_grouped_cross_contract_validate,
       build_artifact = .dsvert_dp_grouped_cross_artifact,
       build_source_contract = .dsvert_dp_grouped_cross_source_contract,
       materialize = function(...) .dsvert_dp_grouped_cross_fail(),
       production_enabled = FALSE)
}
