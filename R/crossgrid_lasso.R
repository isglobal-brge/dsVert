# Public finite L1 extension. These helpers neither resolve protected sources nor
# produce a DP release. The base route retains all authentication and noise gates.

# Exact public binary64 rational arithmetic in base-2^15 limbs. Products of
# limbs and carries are below 2^53; tiny positive penalties never round to zero.
.dsvert_dp_lasso_cross_penalty <- function(beta, lambda, capacity, bits) {
  radix <- 2^15
  limbs <- function(value) {
    out <- numeric()
    while (value > 0) {
      out <- c(out, value %% radix)
      value <- floor(value / radix)
    }
    if (length(out)) out else 0
  }
  normalize <- function(value) {
    index <- 1L
    while (index <= length(value)) {
      carry <- floor(value[index] / radix)
      value[index] <- value[index] %% radix
      if (carry > 0) {
        if (index == length(value)) value <- c(value, 0)
        value[index + 1L] <- value[index + 1L] + carry
      }
      index <- index + 1L
    }
    while (length(value) > 1L && tail(value, 1L) == 0) value <- head(value, -1L)
    value
  }
  multiply <- function(a, b) {
    out <- numeric(length(a) + length(b))
    for (i in seq_along(a)) for (j in seq_along(b)) {
      out[i + j - 1L] <- out[i + j - 1L] + a[i] * b[j]
    }
    normalize(out)
  }
  decode <- function(x) {
    bytes <- as.numeric(writeBin(as.double(x), raw(), size = 8L,
                                 endian = "little"))
    exponent <- (bytes[8L] %% 128) * 16 + floor(bytes[7L] / 16)
    mantissa <- sum(bytes[1:6] * 256^(0:5)) + (bytes[7L] %% 16) * 2^48
    if (exponent != 0) mantissa <- mantissa + 2^52
    list(value = limbs(mantissa), shift = if (exponent == 0) -1074 else exponent - 1075)
  }
  if (lambda == 0 || all(beta[-1L] == 0)) return(0)
  decoded_lambda <- decode(lambda)
  terms <- lapply(abs(beta[-1L]), function(slope) {
    decoded <- decode(slope)
    list(value = multiply(multiply(decoded$value, decoded_lambda$value),
                          limbs(capacity)),
         shift = decoded$shift + decoded_lambda$shift + bits)
  })
  shift <- min(vapply(terms, `[[`, numeric(1L), "shift"), 0)
  numerator <- 0
  for (term in terms) {
    delta <- term$shift - shift
    value <- c(rep(0, floor(delta / 15)),
               normalize(term$value * 2^(delta %% 15)))
    length(numerator) <- max(length(numerator), length(value))
    numerator[is.na(numerator)] <- 0
    numerator[seq_along(value)] <- numerator[seq_along(value)] + value
    numerator <- normalize(numerator)
  }
  drop <- floor(-shift / 15)
  low_bits <- (-shift) %% 15
  remainder <- if (drop) any(numerator[seq_len(min(drop, length(numerator)))] != 0) else FALSE
  if (drop >= length(numerator)) return(as.numeric(any(numerator != 0)))
  quotient <- numerator[seq.int(drop + 1L, length(numerator))]
  remainder <- remainder || quotient[1L] %% 2^low_bits != 0
  carry <- 0
  for (index in rev(seq_along(quotient))) {
    dividend <- carry * radix + quotient[index]
    quotient[index] <- floor(dividend / 2^low_bits)
    carry <- dividend %% 2^low_bits
  }
  value <- 0
  for (limb in rev(quotient)) value <- value * radix + limb
  value <- value + as.numeric(remainder)
  .dsvert_dp_glm_grid_cross_integer(value, 0, 2^53 - 1)
}

# Public adapter descriptor for an ALREADY authenticated base. Contract validation
# below independently obtains this descriptor from the base validator.
.dsvert_dp_lasso_cross_base <- function(base, policy, family = NULL) {
  if (is.null(family)) family <- base$spec$family
  if (!is.character(family) || length(family) != 1L ||
      !family %in% c("binomial", "poisson", "gaussian")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  gaussian <- identical(family, "gaussian")
  artifact <- if (gaussian) base else base$artifact
  spec <- if (gaussian) base else base$spec
  if (!identical(artifact$implementation_state,
                 "cross_owner_exact_gc_materialized") ||
      !identical(artifact$cross_owner_state, "exact_gc_to_joint_dp_vector_v1") ||
      !isTRUE(spec$intercept) ||
      length(unique(unlist(spec$participating_peers))) < 2L ||
      !setequal(unlist(spec$participating_peers), names(policy$peer_pinset)) ||
      length(unique(unlist(spec$computation_peers))) != 2L ||
      !all(unlist(spec$computation_peers) %in% unlist(spec$participating_peers)) ||
      !setequal(unlist(spec$computation_peers),
                unname(policy$designated_noise_peers)) ||
      length(policy$peer_pinset) < 2L) .dsvert_dp_glm_grid_cross_fail()
  bits <- .dsvert_dp_glm_grid_cross_integer(spec$numeric_grid_bits, 8, 18)
  if (bits != .dsvert_dp_glm_grid_cross_integer(policy$numeric_grid_bits, 8, 18) ||
      !setequal(unlist(spec$participating_peers), names(policy$peer_pinset))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  capacity <- .dsvert_dp_glm_grid_cross_integer(policy$unit_capacity, 1, 2^31 - 1)
  if (!gaussian && (!identical(family, spec$family) ||
      spec$observation_capacity != capacity)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  if (gaussian && !identical(spec$version,
      "bounded-normalized-gaussian-cross-sufficient-statistics-v1")) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  terms <- unlist(spec$design_terms, use.names = FALSE)
  if (!identical(terms[1L], "(Intercept)") || length(terms) < 2L ||
      length(terms) > 17L) .dsvert_dp_glm_grid_cross_fail()
  if (gaussian && (!identical(spec$coordinate_order,
      "n_then_xtx_upper_column_major_then_xty_design_order_then_yty_v2") ||
      !identical(spec$source_coordinate_scaling,
        "all_coordinates_already_on_common_numeric_lattice_v1") ||
      spec$coordinate_count != length(terms) * (length(terms) + 1) / 2 +
        length(terms) + 2 ||
      length(spec$statistic_maximum) != spec$coordinate_count ||
      any(unlist(spec$statistic_maximum) != capacity * 2^bits))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  predictors <- if (gaussian) vapply(spec$predictors, function(value) {
    paste0(value$owner_peer, "$", sub("^[^$]+\\$", "", value$column))
  }, character(1L)) else unlist(spec$predictor_order, use.names = FALSE)
  outcome <- if (gaussian) paste0(spec$outcome$owner_peer, "$",
    sub("^[^$]+\\$", "", spec$outcome$column)) else spec$outcome$reference
  list(family = family, base_contract_sha256 = .dsvert_joint_dp_hash(base),
    analysis_id = spec$analysis_id, dataset = spec$dataset,
    outcome = outcome, predictor_order = as.list(unname(predictors)),
    design_terms = as.list(c("(Intercept)", unname(predictors))),
    beta_grid = if (gaussian) NULL else spec$beta_grid,
    numeric_grid_bits = bits, observation_capacity = capacity,
    release_kind = if (gaussian) "gaussian_cross_sufficient_statistics_v1" else
      "exact_gc_candidate_loss_vector_v1",
    coordinate_count = artifact$coordinate_count,
    maximum_coordinates = if (gaussian) as.list(spec$statistic_maximum) else
      spec$sensitivity$maximum_coordinates,
    sensitivity = if (gaussian) list(
      raw_l1_sensitivity = spec$source_raw_l1_sensitivity,
      raw_l2_sensitivity = spec$source_raw_l2_sensitivity,
      natural_l1_sensitivity = spec$natural_l1_sensitivity,
      natural_l2_sensitivity = spec$natural_l2_sensitivity) else spec$sensitivity)
}

.dsvert_dp_lasso_cross_spec <- function(raw, base) {
  .dsvert_dp_glm_grid_cross_fields(raw,
    c("version", "analysis_id", "candidate_grid"))
  if (!identical(raw$version, "lasso_grid_cross_v1") ||
      !is.character(raw$analysis_id) || length(raw$analysis_id) != 1L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  .dsvert_dp_glm_grid_cross_strings(raw$analysis_id)
  candidates <- raw$candidate_grid
  if (!is.list(candidates) || !is.null(names(candidates)) ||
      !length(candidates) || length(candidates) > 256L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  candidates <- lapply(candidates, function(candidate) {
    .dsvert_dp_glm_grid_cross_fields(candidate, c("lambda", "beta"))
    lambda <- candidate$lambda
    beta <- candidate$beta
    if (is.list(beta) && is.null(names(beta)) && all(vapply(beta,
        function(x) is.numeric(x) && length(x) == 1L, logical(1L)))) {
      beta <- unlist(beta, use.names = FALSE)
    }
    if (!is.numeric(lambda) || length(lambda) != 1L || is.na(lambda) ||
        !is.finite(lambda) || lambda < 0 || lambda > 8 ||
        !is.numeric(beta) || !is.null(names(beta)) || anyNA(beta) ||
        any(!is.finite(beta)) || length(beta) != length(base$design_terms) ||
        any(abs(beta) > 8) || !.dsvert_dp_glm_grid_cross_beta_l1_valid(beta)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    list(lambda = as.numeric(lambda), beta = as.list(as.numeric(beta)))
  })
  beta_keys <- vapply(candidates, function(x) .dsvert_dp_canonical_json(x$beta), character(1L))
  lambda <- vapply(candidates, `[[`, numeric(1L), "lambda")
  keys <- vapply(candidates, .dsvert_dp_canonical_json, character(1L))
  if (anyDuplicated(keys) || !identical(seq_along(candidates),
      order(-lambda, beta_keys, method = "radix"))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  mapping <- if (identical(base$family, "gaussian")) NULL else
    as.list(match(beta_keys, vapply(base$beta_grid, .dsvert_dp_canonical_json, character(1L))))
  if (anyNA(unlist(mapping))) .dsvert_dp_glm_grid_cross_fail()
  penalties <- lapply(candidates, function(candidate) {
    .dsvert_dp_lasso_cross_penalty(unlist(candidate$beta), candidate$lambda,
      base$observation_capacity, base$numeric_grid_bits)
  })
  list(version = "lasso_grid_cross_v1", analysis_id = raw$analysis_id,
    family = base$family, base = base, candidate_grid = candidates,
    candidate_order = as.list(vapply(candidates, .dsvert_joint_dp_hash, character(1L))),
    base_coordinate_index = mapping, public_penalty_raw = penalties,
    penalty_normalizer = "public_observation_capacity_v1",
    penalty_rule = "exact_binary64_slope_l1_ceiling_on_release_lattice_v1",
    objective = if (identical(base$family, "gaussian"))
      "half_normalized_rss_over_capacity_plus_lambda_l1_v1" else
      "negative_log_likelihood_over_capacity_plus_lambda_l1_v1",
    penalty_requires_mpc = FALSE, additional_raw_l1_sensitivity = 0,
    additional_raw_l2_sensitivity = 0,
    implementation_state = "cross_owner_exact_gc_materialized",
    cross_owner_state = "exact_gc_to_joint_dp_vector_v1",
    result_evidence_required = TRUE)
}

.dsvert_dp_lasso_cross_message <- function(unsigned) {
  charToRaw(paste0("dsVert/cross-owner-lasso-contract/v1|",
                   .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_lasso_cross_contract_validate <- function(
    value, policy, schema_manifest, base_contract,
    .base_validator = .dsvert_dp_lasso_cross_validate_base,
    .verifier = .dsvert_relay_verify_message) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_fields(value, c("version", "spec", "signatures"))
    if (!identical(value$version, "dsvert-cross-owner-lasso-signed-contract-v1")) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    base <- .base_validator(base_contract, policy, schema_manifest)
    expected <- .dsvert_dp_lasso_cross_spec(
      value$spec[c("version", "analysis_id", "candidate_grid")], base)
    .dsvert_dp_glm_grid_cross_equal(value$spec, expected)
    .dsvert_dp_glm_grid_cross_fields(value$signatures, names(policy$peer_pinset))
    message <- .dsvert_dp_lasso_cross_message(value[c("version", "spec")])
    verified <- vapply(names(policy$peer_pinset), function(peer) {
      signature <- value$signatures[[peer]]
      is.character(signature) && length(signature) == 1L && !is.na(signature) &&
        grepl("^[A-Za-z0-9_-]{86}$", signature) &&
        isTRUE(.verifier(message, unname(policy$peer_pinset[[peer]]), signature))
    }, logical(1L))
    if (!all(verified)) .dsvert_dp_glm_grid_cross_fail()
    .dsvert_dp_canonical_query_value(value)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_lasso_cross_validate_base <- function(value, policy, schema_manifest) {
  # This default validates the frozen staging contract, not execution evidence.
  # Step 2 must supply its authoritative certified-profile base validator before
  # enabling a nonlinear release; the legacy numeric profile is not promoted.
  # The frozen GLM validator deliberately rejects Gaussian artifacts. Gaussian
  # integration must first run its existing manifest/certificate validator and
  # then call .dsvert_dp_lasso_cross_base(artifact, policy, "gaussian").
  validated <- .dsvert_dp_glm_grid_cross_contract_validate(
    value, policy, schema_manifest)
  .dsvert_dp_lasso_cross_base(validated, policy)
}

# Internal postprocessing boundary: coordinates must already be authenticated
# joint-DP output. Public callers cannot provide unverified vectors as releases.
.dsvert_dp_lasso_cross_postprocess <- function(coordinates, spec) {
  tryCatch({
    .dsvert_dp_glm_grid_cross_equal(spec, .dsvert_dp_lasso_cross_spec(
      spec[c("version", "analysis_id", "candidate_grid")], spec$base))
    base <- spec$base
    if (!is.numeric(coordinates) || anyNA(coordinates) ||
        any(!is.finite(coordinates)) || any(coordinates != floor(coordinates)) ||
        any(abs(coordinates) > 2^53 - 1) ||
        length(coordinates) != base$coordinate_count) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    if (identical(base$family, "gaussian")) {
      dimension <- length(base$design_terms)
      gram_count <- dimension * (dimension + 1) / 2
      if (length(coordinates) != gram_count + dimension + 2) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      gram <- matrix(0, dimension, dimension)
      gram[upper.tri(gram, diag = TRUE)] <- coordinates[1L + seq_len(gram_count)]
      gram <- gram + t(gram) - diag(diag(gram), dimension)
      xy <- coordinates[1L + gram_count + seq_len(dimension)]
      yy <- tail(coordinates, 1L)
      loss <- vapply(spec$candidate_grid, function(candidate) {
        beta <- unlist(candidate$beta)
        0.5 * (sum(beta * as.vector(gram %*% beta)) - 2 * sum(beta * xy) + yy)
      }, numeric(1L))
    } else loss <- coordinates[unlist(spec$base_coordinate_index)]
    penalties <- unlist(spec$public_penalty_raw, use.names = FALSE)
    scores <- (loss + penalties) /
      (base$observation_capacity * 2^base$numeric_grid_bits)
    if (any(!is.finite(scores))) .dsvert_dp_glm_grid_cross_fail()
    lambda <- vapply(spec$candidate_grid, `[[`, numeric(1L), "lambda")
    selected <- vapply(unique(lambda), function(value) {
      indices <- which(lambda == value)
      indices[which.min(scores[indices])]
    }, integer(1L))
    list(family = base$family, lambda = unique(lambda),
      selected_candidates = selected, selected_objectives = scores[selected],
      normalized_paths = lapply(selected, function(index) {
        stats::setNames(unlist(spec$candidate_grid[[index]]$beta),
                        unlist(base$design_terms))
      }), covariance = NULL, standard_errors = NULL,
      additional_privacy_cost = c(epsilon = 0, delta = 0),
      selection = "minimum_signed_public_capacity_normalized_l1_objective_v1")
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_lasso_cross_register <- function() {
  list(version = "lasso_grid_cross_v1", families = c("binomial", "poisson", "gaussian"),
    spec = .dsvert_dp_lasso_cross_spec,
    validate_contract = .dsvert_dp_lasso_cross_contract_validate,
    base_descriptor = .dsvert_dp_lasso_cross_base,
    postprocess = .dsvert_dp_lasso_cross_postprocess,
    implementation_state = "cross_owner_exact_gc_materialized",
    cross_owner_state = "exact_gc_to_joint_dp_vector_v1",
    nonlinear_arithmetic_required = "certified_piecewise_polynomial_profile_v1",
    production_release_enabled = FALSE, result_evidence_required = TRUE)
}
