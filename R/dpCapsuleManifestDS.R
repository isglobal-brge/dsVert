# Server-authoritative bootstrap for one immutable biomedical DP capsule.
#
# The relay never supplies bounds, domains, dataset versions, a logical
# snapshot, or workload specifications.  It only combines signed public
# policy drafts, relays the resulting schema for unanimous signatures, and
# asks every peer to build the same manifest.  A later producer accepts that
# manifest only if it is present in this server's authenticated durable cache.

.DSVERT_DP_CAPSULE_MANIFEST_DRAFT_VERSION <-
  "dsvert-biomedical-capsule-manifest-draft-v1"
.DSVERT_DP_CAPSULE_MANIFEST_SIGN_VERSION <-
  "dsvert-biomedical-capsule-manifest-schema-signature-v1"
.DSVERT_DP_CAPSULE_MANIFEST_BUILD_VERSION <-
  "dsvert-biomedical-capsule-manifest-build-v2"
.DSVERT_DP_CAPSULE_ARTIFACT_INDEX_VERSION <-
  "dsvert-biomedical-capsule-artifact-commitment-index-v3"
.DSVERT_DP_CAPSULE_ARTIFACT_ENTRY_VERSION <-
  "dsvert-biomedical-capsule-artifact-commitment-v1"
.DSVERT_DP_CAPSULE_ARTIFACT_INDEX_MAX_BYTES <- 8L * 1024L^2
.DSVERT_DP_CAPSULE_MANIFEST_REJECTION_VERSION <-
  "dsvert-biomedical-capsule-manifest-rejection-v1"
.DSVERT_DP_CAPSULE_MANIFEST_CACHE_VERSION <-
  "dsvert-biomedical-capsule-manifest-cache-v5"
.DSVERT_DP_CAPSULE_MANIFEST_REPLAY_CACHE_VERSIONS <- c(
  .DSVERT_DP_CAPSULE_MANIFEST_CACHE_VERSION,
  "dsvert-biomedical-capsule-manifest-cache-v4")
.DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION <-
  "dsvert-biomedical-capsule-workload-contract-v2"
.DSVERT_DP_CAPSULE_MANIFEST_SIGNATURE_DOMAIN <-
  "dsVert/dp/biomedical-capsule-manifest/v1/"
.DSVERT_DP_CAPSULE_MANIFEST_SCHEMA_VERSION <- "custodian-policy-v1"
.DSVERT_DP_CAPSULE_MANIFEST_MAX_SCHEMA_BYTES <- 8L * 1024L^2
.DSVERT_DP_CAPSULE_MANIFEST_MAX_WORKLOAD_BYTES <- 8L * 1024L^2
.DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES <- 32L * 1024L^2

.dsvert_dp_capsule_manifest_abort <- function(reason_code, message) {
  if (!is.character(reason_code) || length(reason_code) != 1L ||
      is.na(reason_code) ||
      !grepl("^[a-z][a-z0-9_]{0,63}$", reason_code)) {
    reason_code <- "boundary_validation_failed"
  }
  condition <- structure(
    list(message = as.character(message), call = NULL,
         reason_code = reason_code),
    class = c("dsvert_capsule_manifest_rejected", "error", "condition"))
  stop(condition)
}

.dsvert_dp_capsule_manifest_rejection <- function(phase, reason_code) {
  list(
    version = .DSVERT_DP_CAPSULE_MANIFEST_REJECTION_VERSION,
    rejected = TRUE,
    phase = phase,
    reason_code = reason_code,
    retryable = FALSE,
    operation_limit = FALSE,
    request_limit = FALSE,
    history_can_deny_operation = FALSE)
}

.dsvert_dp_capsule_manifest_public <- function(phase, code) {
  tryCatch(force(code), error = function(error) {
    reason <- if (inherits(error, "dsvert_capsule_manifest_rejected")) {
      error$reason_code
    } else {
      "boundary_validation_failed"
    }
    .dsvert_dp_capsule_manifest_rejection(phase, reason)
  })
}

.dsvert_dp_capsule_manifest_decode <- function(
    value, what, maximum_bytes, simplify = TRUE) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_canonical_message", paste("Invalid", what))
  }
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = simplify, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE), error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded)), error = function(error) NULL)
  if (!is.list(decoded) || is.null(canonical) ||
      !identical(canonical, value)) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_canonical_message", paste("Invalid canonical", what))
  }
  decoded
}

.dsvert_dp_capsule_manifest_message <- function(domain, unsigned) {
  signed <- unsigned
  if (identical(domain, "build") && is.list(signed)) {
    signed$manifest_json <- NULL
    signed$artifact_commitments <- NULL
  }
  charToRaw(paste0(
    .DSVERT_DP_CAPSULE_MANIFEST_SIGNATURE_DOMAIN, domain, "|",
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(signed))))
}

.dsvert_dp_capsule_artifact_merkle_parent <- function(left, right) {
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-artifact-merkle-parent-v1",
    left = left, right = right))
}

.dsvert_dp_capsule_artifact_merkle_root <- function(hashes, context) {
  hashes <- unname(as.character(hashes))
  if (!length(hashes)) {
    return(.dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-artifact-merkle-empty-v1",
      context = context)))
  }
  if (anyNA(hashes) || any(!grepl("^[0-9a-f]{64}$", hashes))) {
    stop("Invalid biomedical artifact commitment leaf.", call. = FALSE)
  }
  nodes <- hashes
  while (length(nodes) > 1L) {
    if (length(nodes) %% 2L) nodes <- c(nodes, tail(nodes, 1L))
    nodes <- vapply(seq.int(1L, length(nodes), by = 2L), function(index) {
      .dsvert_dp_capsule_artifact_merkle_parent(
        nodes[[index]], nodes[[index + 1L]])
    }, character(1L))
  }
  nodes[[1L]]
}

.dsvert_dp_capsule_artifact_commitment_index <- function(
    manifest, policy, manifest_sha256) {
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  identity <- manifest$capsule_identity
  contract <- identity$contract
  context <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_ARTIFACT_INDEX_VERSION,
    manifest_sha256 = manifest_sha256,
    capsule_id = identity$capsule_id,
    domain = policy$domain,
    cohort_id = policy$cohort_id,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    designated_noise_peers = as.list(
      sort(policy$designated_noise_peers, method = "radix")),
    privacy_epoch_scope = if (.dsvert_dp_synopsis_policy_is_v1(policy)) {
      "per_canonical_artifact_sticky_v1"
    } else {
      "per_peer_signed_receipts_v1"
    },
    epsilon = as.numeric(policy$global_total_epsilon),
    delta = as.numeric(policy$global_total_delta),
    adjacency = policy$adjacency,
    unit_capacity = as.numeric(policy$unit_capacity),
    max_records_per_unit = as.numeric(policy$max_records_per_unit),
    overflow_policy = policy$overflow_policy,
    consortium_id = contract$consortium_id,
    policy_contract_hash = contract$policy_contract_hash,
    logical_snapshot = manifest$logical_snapshot,
    capsule_schema = manifest$capsule_schema,
    admission_sha256 = .dsvert_joint_dp_hash(manifest$admission),
    bounds_sha256 = .dsvert_joint_dp_hash(manifest$bounds),
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    release_lattice = manifest$workload$release_lattice,
    capsule_mechanism = manifest$workload$capsule_mechanism,
    mechanism_selection = manifest$workload$mechanism_selection,
    coordinate_layout_version = layout$version,
    coordinate_count = as.numeric(layout$coordinate_count),
    coordinate_order_sha256 = layout$sha256))
  gaussian <- layout$blocks[vapply(layout$blocks, function(block) {
    identical(block$family, "gaussian_models")
  }, logical(1L))]
  if (length(gaussian)) {
    gaussian <- gaussian[order(vapply(
      gaussian, `[[`, character(1L), "key"), method = "radix")]
  }
  entries <- lapply(gaussian, function(block) {
    entry <- .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_DP_CAPSULE_ARTIFACT_ENTRY_VERSION,
      family = block$family, analysis_id = block$key,
      dataset = block$dataset, owner_peer = block$owner_peer,
      start = as.numeric(block$start), end = as.numeric(block$end),
      length = as.numeric(block$length),
      descriptor_sha256 = .dsvert_joint_dp_hash(block$descriptor)))
    c(entry, list(node_sha256 = .dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-artifact-merkle-leaf-v1",
      context = context, entry = entry))))
  })
  names(entries) <- vapply(gaussian, `[[`, character(1L), "key")
  value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_ARTIFACT_INDEX_VERSION,
    context = context, gaussian_models = entries))
  if (nchar(.dsvert_dp_canonical_json(value), type = "bytes") >
      .DSVERT_DP_CAPSULE_ARTIFACT_INDEX_MAX_BYTES) {
    .dsvert_dp_capsule_manifest_abort(
      "artifact_index_too_large",
      "The public biomedical artifact commitment index is too large")
  }
  hashes <- vapply(entries, `[[`, character(1L), "node_sha256")
  list(
    value = value, count = as.numeric(length(entries)),
    root = .dsvert_dp_capsule_artifact_merkle_root(hashes, context))
}

.dsvert_dp_capsule_manifest_identity_signature <- function(
    message, policy, signer = NULL) {
  pin <- unname(policy$peer_pinset[[policy$peer_name]])
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    if (!identical(
          .dsvert_relay_normalize_identity_pk(identity$identity_pk),
          .dsvert_relay_normalize_identity_pk(pin))) {
      .dsvert_dp_capsule_manifest_abort(
        "runtime_identity_mismatch",
        "The runtime identity does not match its pinned policy identity")
    }
    signature <- .dsvert_relay_sign_message(message, identity$identity_sk)
  } else {
    if (!is.function(signer)) {
      .dsvert_dp_capsule_manifest_abort(
        "runtime_identity_mismatch", "Invalid manifest signer")
    }
    signature <- signer(message, policy$peer_name, pin)
  }
  if (!is.character(signature) || length(signature) != 1L ||
      is.na(signature) || !grepl("^[A-Za-z0-9_-]{86}$", signature)) {
    .dsvert_dp_capsule_manifest_abort(
      "runtime_identity_mismatch", "Invalid manifest signature")
  }
  signature
}

.dsvert_dp_capsule_manifest_sign_object <- function(
    unsigned, policy, domain, signer = NULL) {
  signature <- .dsvert_dp_capsule_manifest_identity_signature(
    .dsvert_dp_capsule_manifest_message(domain, unsigned),
    policy, signer)
  .dsvert_dp_canonical_query_value(c(
    unsigned, list(signature = signature)))
}

.dsvert_dp_capsule_manifest_local_mapping <- function(policy) {
  sorted_names <- function(value) {
    result <- names(value)
    if (is.null(result)) result <- character()
    sort(result, method = "radix")
  }
  datasets <- sorted_names(policy$datasets)
  numeric <- sorted_names(policy$numeric_bounds)
  categorical <- sorted_names(policy$categorical_levels)
  columns <- sort(c(numeric, categorical), method = "radix")
  if (!length(datasets) || !length(columns) ||
      anyDuplicated(columns) || policy$patient_column %in% columns) {
    .dsvert_dp_capsule_manifest_abort(
      "unsupported_local_schema",
      "The local policy has no unambiguous bounded analysis schema")
  }
  configured <- policy$capsule_dataset_mapping
  if (is.null(configured)) {
    if (length(datasets) != 1L) {
      .dsvert_dp_capsule_manifest_abort(
        "ambiguous_local_dataset_mapping",
        paste("Several local datasets require the custodian-owned",
              "dsvert.dp.capsule_dataset_mapping"))
    }
    configured <- stats::setNames(list(columns), datasets)
    mode <- "automatic_single_local_dataset"
  } else {
    mode <- "custodian_explicit_dataset_mapping_v1"
  }
  valid <- is.list(configured) && !is.null(names(configured)) &&
    !anyNA(names(configured)) && !anyDuplicated(names(configured)) &&
    setequal(names(configured), datasets) &&
    all(vapply(configured, function(value) {
      is.character(value) && length(value) > 0L && !anyNA(value) &&
        all(nzchar(value)) && !anyDuplicated(value)
    }, logical(1L)))
  if (!isTRUE(valid)) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_local_dataset_mapping",
      "The custodian-owned capsule dataset mapping is invalid")
  }
  configured <- configured[datasets]
  configured <- lapply(configured, function(value) {
    sort(enc2utf8(unname(value)), method = "radix")
  })
  flattened <- unname(unlist(configured, use.names = FALSE))
  if (anyDuplicated(flattened) || !setequal(flattened, columns)) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_local_dataset_mapping",
      "The capsule dataset mapping must partition every bounded column once")
  }
  list(mode = mode, datasets = configured)
}

.dsvert_dp_capsule_manifest_spec_list <- function(value, what) {
  if (is.null(value)) value <- list()
  if (!is.list(value) || (!length(value) && !is.null(names(value))) ||
      (length(value) && (is.null(names(value)) || anyNA(names(value)) ||
        any(!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                   names(value))) || anyDuplicated(names(value))))) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_custodian_workload_specs",
      paste("Invalid custodian-owned", what, "specifications"))
  }
  if (!length(value)) return(list())
  value[order(names(value), method = "radix")]
}

.dsvert_dp_capsule_manifest_local_specs <- function(policy, mapping = NULL) {
  if (is.null(mapping)) {
    mapping <- .dsvert_dp_capsule_manifest_local_mapping(policy)
  }
  configured <- policy$capsule_workload_specs
  if (is.null(configured)) {
    configured <- list(
      describe = .dsvert_dp_option("describe_specs", list()),
      survival = .dsvert_dp_option("survival_specs", list()),
      gaussian = .dsvert_dp_option("gaussian_specs", list()),
      vertical_cross = .dsvert_dp_option("vertical_cross_specs", list()))
  }
  if (!is.list(configured) || is.null(names(configured)) ||
      anyNA(names(configured)) || anyDuplicated(names(configured)) ||
      !setequal(names(configured),
                c("describe", "survival", "gaussian", "vertical_cross"))) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_custodian_workload_specs",
      "The custodian-owned capsule workload specifications are invalid")
  }
  local_columns <- unname(unlist(mapping$datasets, use.names = FALSE))

  describe <- .dsvert_dp_capsule_manifest_spec_list(
    configured$describe, "describe")
  normalized_describe <- vector("list", length(describe))
  names(normalized_describe) <- names(describe)
  for (analysis_id in names(describe)) {
    raw <- describe[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- tryCatch(.dsvert_dp_describe_spec(
      policy, data_name, analysis_id, specs = describe),
      error = function(error) NULL)
    if (is.null(spec) || !data_name %in% names(mapping$datasets) ||
        !all(spec$variables %in% mapping$datasets[[data_name]])) {
      .dsvert_dp_capsule_manifest_abort(
        "invalid_custodian_workload_specs",
        "A custodian describe specification is not locally owned")
    }
    variables <- sort(unname(spec$variables), method = "radix")
    grid_index <- match(variables, spec$variables)
    grids <- stats::setNames(
      lapply(spec$histogram_grids[grid_index], unname), variables)
    allocation <- stats::setNames(
      as.list(unname(spec$allocation_weights)), spec$allocation_names)
    normalized_describe[[analysis_id]] <- list(
      version = spec$version, dataset = spec$dataset,
      variables = variables, histogram_grids = grids,
      allocation = allocation)
  }

  survival <- .dsvert_dp_capsule_manifest_spec_list(
    configured$survival, "survival")
  normalized_survival <- vector("list", length(survival))
  names(normalized_survival) <- names(survival)
  for (analysis_id in names(survival)) {
    raw <- survival[[analysis_id]]
    data_name <- if (is.list(raw)) raw$dataset else NULL
    spec <- tryCatch(if (is.list(raw) && identical(
        raw$version, "cox_partial_likelihood_grid_v1")) {
      .dsvert_dp_capsule_cox_partial_grid_spec(
        policy, data_name, analysis_id, survival)
    } else {
      .dsvert_dp_survival_spec(
        policy, data_name, analysis_id, specs = survival)
    }, error = function(error) NULL)
    variables <- if (is.null(spec)) {
      character()
    } else if (identical(spec$kind, "cox_partial_likelihood_grid")) {
      c(spec$time, spec$event, spec$predictors)
    } else {
      c(spec$time, spec$event, spec$entry)
    }
    variables <- variables[!vapply(variables, is.null, logical(1L))]
    if (is.null(spec) || !data_name %in% names(mapping$datasets) ||
        !all(variables %in% mapping$datasets[[data_name]])) {
      .dsvert_dp_capsule_manifest_abort(
        "invalid_custodian_workload_specs",
        "A custodian survival specification is not locally owned")
    }
    normalized_survival[[analysis_id]] <- if (identical(
        spec$kind, "cox_partial_likelihood_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        time = spec$time, event = spec$event, censor = spec$censor,
        event_level = spec$event_level, time_grid = unname(spec$time_grid),
        predictors = unname(spec$predictors), intercept = FALSE,
        candidate_grid = lapply(spec$candidate_grid, unname))
    } else {
      list(
        version = spec$version, dataset = spec$dataset,
        time = spec$time, event = spec$event, censor = spec$censor,
        time_grid = unname(spec$time_grid), entry = spec$entry)
    }
  }

  gaussian <- .dsvert_dp_capsule_manifest_spec_list(
    configured$gaussian, "Gaussian")
  normalized_gaussian <- vector("list", length(gaussian))
  names(normalized_gaussian) <- names(gaussian)
  for (analysis_id in names(gaussian)) {
    spec <- tryCatch(.dsvert_dp_capsule_gaussian_spec(
      policy, analysis_id, gaussian, require_public_bounds = FALSE),
      error = function(error) NULL)
    references <- if (is.null(spec)) list() else lapply(
      c(spec$outcome, if (identical(spec$kind, "random_intercept")) {
        spec$cluster
      } else if (spec$kind %in% c("gaussian_ar1_working_gls_grid",
                                   "gaussian_ar1_robust_working_gls_grid")) {
        c(spec$cluster, spec$order, spec$predictors)
      } else if (spec$kind %in% c("random_intercept_fixed",
                                   "binary_random_intercept_grid",
                                   "poisson_random_intercept_grid",
                                   "binary_random_slope_grid",
                                   "gaussian_random_slope_grid")) {
        c(spec$cluster, spec$predictors)
      } else {
        spec$predictors
      }),
      .dsvert_dp_capsule_column_reference, what = "Gaussian variable")
    variables <- vapply(
      references, `[[`, character(1L), "column")
    owners <- vapply(references, function(reference) {
      reference$owner_peer %||% policy$peer_name
    }, character(1L))
    outcome_owned <- !is.null(spec) &&
      spec$dataset %in% names(mapping$datasets) &&
      identical(owners[[1L]], policy$peer_name) &&
      variables[[1L]] %in% mapping$datasets[[spec$dataset]]
    valid_ownership <- if (is.null(spec)) {
      FALSE
    } else if (identical(spec$kind, "random_intercept")) {
      isTRUE(outcome_owned) && length(variables) == 2L &&
        all(owners == policy$peer_name) &&
        all(variables %in% mapping$datasets[[spec$dataset]])
    } else if (spec$kind %in% c("random_intercept_fixed",
                                 "binary_random_intercept_grid",
                                 "poisson_random_intercept_grid",
                                 "binary_random_slope_grid",
                                 "gaussian_random_slope_grid")) {
      isTRUE(outcome_owned) && length(variables) == 2L +
        length(spec$predictors) && all(owners == policy$peer_name) &&
        all(variables %in% mapping$datasets[[spec$dataset]])
    } else if (spec$kind %in% c("gaussian_ar1_working_gls_grid",
                                 "gaussian_ar1_robust_working_gls_grid")) {
      isTRUE(outcome_owned) && length(variables) == 3L +
        length(spec$predictors) && all(owners == policy$peer_name) &&
        all(variables %in% mapping$datasets[[spec$dataset]])
    } else if (spec$kind %in% c("binomial_grid", "poisson_grid",
                                 "negative_binomial_grid",
                                 "multinomial_grid", "ordinal_grid")) {
      isTRUE(outcome_owned) && length(variables) == 1L +
        length(spec$predictors) && all(owners == policy$peer_name) &&
        all(variables %in% mapping$datasets[[spec$dataset]])
    } else if (identical(spec$version, "v1")) {
      isTRUE(outcome_owned) &&
        all(variables %in% mapping$datasets[[spec$dataset]])
    } else if (identical(spec$version, "v2")) {
      # The outcome custodian owns the one global cross-model fragment.  Its
      # remote predictor references are resolved only against the unanimously
      # signed owner/dataset/column schema.
      isTRUE(outcome_owned) && length(spec$predictors) > 0L
    } else {
      FALSE
    }
    if (!isTRUE(valid_ownership)) {
      .dsvert_dp_capsule_manifest_abort(
        "invalid_custodian_workload_specs",
        "A custodian Gaussian specification is not locally owned")
    }
    normalized_gaussian[[analysis_id]] <- if (identical(
          spec$kind, "random_intercept")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        max_patients_per_cluster = spec$max_patients_per_cluster)
    } else if (identical(spec$kind, "random_intercept_fixed")) {
      fixed <- list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        predictors = unname(spec$predictors), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        variance_ratio_grid = unname(spec$variance_ratio_grid))
      if (identical(spec$version, "random_intercept_fixed_v3")) {
        fixed$estimation_profile <- spec$estimation_profile
      }
      fixed
    } else if (identical(spec$kind, "gaussian_random_slope_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        predictors = unname(spec$predictors),
        random_slopes = unname(spec$random_slopes), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        candidate_grid = lapply(spec$candidate_grid, function(candidate) list(
          beta = unname(candidate$beta), sigma2 = candidate$sigma2,
          covariance = unname(candidate$covariance))))
    } else if (spec$kind %in% c("gaussian_ar1_working_gls_grid",
                                 "gaussian_ar1_robust_working_gls_grid")) {
      ar1 <- list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster, order = spec$order,
        predictors = unname(spec$predictors), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        candidate_grid = lapply(spec$candidate_grid, function(candidate) list(
          beta = unname(candidate$beta), rho = candidate$rho)))
      if (identical(spec$kind, "gaussian_ar1_robust_working_gls_grid")) {
        ar1$score_clip <- spec$score_clip
      }
      ar1
    } else if (identical(spec$kind, "binary_random_slope_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        predictors = unname(spec$predictors),
        random_slopes = unname(spec$random_slopes), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        candidate_grid = lapply(spec$candidate_grid, function(candidate) list(
          beta = unname(candidate$beta), covariance = unname(candidate$covariance))))
    } else if (identical(spec$kind, "binary_random_intercept_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        predictors = unname(spec$predictors), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        beta_grid = lapply(spec$beta_grid, unname),
        variance_grid = unname(spec$variance_grid))
    } else if (identical(spec$kind, "poisson_random_intercept_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, cluster = spec$cluster,
        predictors = unname(spec$predictors), intercept = spec$intercept,
        max_patients_per_cluster = spec$max_patients_per_cluster,
        max_outcome = spec$max_outcome,
        beta_grid = lapply(spec$beta_grid, unname),
        variance_grid = unname(spec$variance_grid))
    } else if (spec$kind %in% c("binomial_grid", "poisson_grid")) {
      value <- list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, predictors = unname(spec$predictors),
        intercept = spec$intercept, beta_grid = lapply(spec$beta_grid, unname))
      if (identical(spec$kind, "poisson_grid")) {
        value$max_outcome <- spec$max_outcome
      }
      value
    } else if (identical(spec$kind, "negative_binomial_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, predictors = unname(spec$predictors),
        intercept = spec$intercept, max_outcome = spec$max_outcome,
        beta_grid = lapply(spec$beta_grid, unname),
        theta_grid = unname(spec$theta_grid))
    } else if (identical(spec$kind, "multinomial_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, predictors = unname(spec$predictors),
        intercept = spec$intercept, levels = unname(spec$levels),
        reference = spec$reference, beta_grid = lapply(spec$beta_grid, unname))
    } else if (identical(spec$kind, "ordinal_grid")) {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, predictors = unname(spec$predictors),
        intercept = spec$intercept,
        ordered_levels = unname(spec$ordered_levels),
        candidate_grid = lapply(spec$candidate_grid, function(candidate) {
          list(thresholds = unname(candidate$thresholds),
               beta = unname(candidate$beta))
        }))
    } else {
      list(
        version = spec$version, dataset = spec$dataset,
        outcome = spec$outcome, predictors = unname(spec$predictors),
        intercept = spec$intercept)
    }
  }

  vertical <- .dsvert_dp_capsule_manifest_spec_list(
    configured$vertical_cross, "vertical-cross")
  normalized_vertical <- vector("list", length(vertical))
  names(normalized_vertical) <- names(vertical)
  expected <- c(
    "version", "left_dataset", "right_dataset", "left", "right",
    "family")
  for (analysis_id in names(vertical)) {
    raw <- vertical[[analysis_id]]
    valid <- is.list(raw) && !is.null(names(raw)) && !anyNA(names(raw)) &&
      !anyDuplicated(names(raw)) && setequal(names(raw), expected) &&
      all(vapply(raw, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value)
      }, logical(1L))) && raw$family %in% c(
        "categorical_pair", "numeric_cross_moment",
        "numeric_by_category") && !identical(raw$left, raw$right)
    parsed <- list()
    if (isTRUE(valid)) {
      tryCatch({
        .dsvert_dp_capsule_id(analysis_id, "vertical-cross id")
        .dsvert_dp_capsule_id(raw$version, "vertical-cross version")
        .dsvert_dp_capsule_id(raw$left_dataset, "left dataset")
        .dsvert_dp_capsule_id(raw$right_dataset, "right dataset")
        parsed$left <- .dsvert_dp_capsule_column_reference(
          raw$left, "left column")
        parsed$right <- .dsvert_dp_capsule_column_reference(
          raw$right, "right column")
      }, error = function(error) valid <<- FALSE)
    }
    references <- if (isTRUE(valid)) list(
      list(dataset = raw$left_dataset, value = parsed$left),
      list(dataset = raw$right_dataset, value = parsed$right)) else list()
    locally_owned <- vapply(references, function(reference) {
      reference$dataset %in% names(mapping$datasets) &&
        (is.null(reference$value$owner_peer) ||
           identical(reference$value$owner_peer, policy$peer_name)) &&
        reference$value$column %in% mapping$datasets[[reference$dataset]]
    }, logical(1L))
    locally_named <- vapply(references, function(reference) {
      reference$dataset %in% names(mapping$datasets) ||
        identical(reference$value$owner_peer, policy$peer_name) ||
        (is.null(reference$value$owner_peer) &&
           reference$value$column %in% local_columns)
    }, logical(1L))
    if (!isTRUE(valid) || !any(locally_owned) ||
        any(locally_named != locally_owned)) {
      .dsvert_dp_capsule_manifest_abort(
        "invalid_custodian_workload_specs",
        "A custodian vertical-cross specification is not locally owned")
    }
    raw$left <- parsed$left$reference
    raw$right <- parsed$right$reference
    normalized_vertical[[analysis_id]] <- raw[expected]
  }
  tryCatch(.dsvert_dp_canonical_query_value(list(
    describe = normalized_describe,
    survival = normalized_survival,
    gaussian = normalized_gaussian,
    vertical_cross = normalized_vertical)), error = function(error) {
      .dsvert_dp_capsule_manifest_abort(
        "invalid_custodian_workload_specs",
        "The custodian-owned capsule workload specifications are invalid")
    })
}

.dsvert_dp_capsule_manifest_draft_unsigned <- function(policy) {
  mapping <- .dsvert_dp_capsule_manifest_local_mapping(policy)
  peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  patient <- .dsvert_dp_capsule_id(
    policy$patient_column, "patient-key column")
  if (!is.character(policy$peer_pinset) ||
      !peer %in% names(policy$peer_pinset) ||
      !identical(unname(policy$peer_pinset[[peer]]),
                 policy$own_identity_pk)) {
    .dsvert_dp_capsule_manifest_abort(
      "invalid_pinned_policy", "The local pinned policy is invalid")
  }
  local_datasets <- vector("list", length(mapping$datasets))
  names(local_datasets) <- names(mapping$datasets)
  for (data_name in names(mapping$datasets)) {
    .dsvert_dp_capsule_id(data_name, "dataset name")
    descriptor <- policy$datasets[[data_name]]
    alignment_version <- descriptor$alignment_manifest_version
    if (!is.numeric(alignment_version) || length(alignment_version) != 1L ||
        is.na(alignment_version) || !is.finite(alignment_version) ||
        alignment_version < 1 ||
        alignment_version != floor(alignment_version)) {
      .dsvert_dp_capsule_manifest_abort(
        "missing_alignment_protocol_version",
        "The local dataset lacks a public alignment protocol version")
    }
    local_columns <- vector("list", length(mapping$datasets[[data_name]]))
    names(local_columns) <- mapping$datasets[[data_name]]
    for (column_name in names(local_columns)) {
      .dsvert_dp_capsule_id(column_name, "column name")
      if (column_name %in% names(policy$numeric_bounds)) {
        bounds <- unname(as.numeric(policy$numeric_bounds[[column_name]]))
        local_columns[[column_name]] <- list(
          kind = "numeric", owner_peer = peer,
          lower = bounds[[1L]], upper = bounds[[2L]])
      } else {
        levels <- sort(unname(policy$categorical_levels[[column_name]]),
                       method = "radix")
        local_columns[[column_name]] <- list(
          kind = "categorical", owner_peer = peer, levels = levels)
      }
      local_columns[[column_name]] <- .dsvert_dp_capsule_column(
        local_columns[[column_name]], names(policy$peer_pinset))
    }
    local_datasets[[data_name]] <- list(
      dataset_id = .dsvert_dp_capsule_id(descriptor$id, "dataset id"),
      dataset_version = .dsvert_dp_capsule_id(
        descriptor$version, "dataset version"),
      schema_version = .DSVERT_DP_CAPSULE_MANIFEST_SCHEMA_VERSION,
      alignment_group = .dsvert_dp_capsule_id(
        policy$cohort_id, "alignment group"),
      alignment_protocol_version = as.integer(alignment_version),
      patient_column = patient,
      columns = local_columns)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_MANIFEST_DRAFT_VERSION,
    phase = "custodian_policy_draft",
    peer_name = peer,
    peer_identity_pk = unname(policy$peer_pinset[[peer]]),
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    domain = policy$domain,
    cohort_id = policy$cohort_id,
    dataset_mapping_mode = mapping$mode,
    datasets = local_datasets,
    workload_fragments = .dsvert_dp_capsule_manifest_local_specs(
      policy, mapping),
    data_access = FALSE,
    patient_derived_metadata = FALSE,
    operation_limit = FALSE,
    request_limit = FALSE,
    history_can_deny_operation = FALSE))
}

.dsvert_dp_capsule_manifest_draft_impl <- function(
    .policy = NULL, .signer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  signed <- .dsvert_dp_capsule_manifest_sign_object(
    .dsvert_dp_capsule_manifest_draft_unsigned(.policy),
    .policy, "draft", .signer)
  .dsvert_dp_canonical_json(signed)
}

.dsvert_dp_capsule_manifest_workload_contract <- function(
    workload_contract_json, policy, .local_exact = TRUE) {
  value <- .dsvert_dp_capsule_manifest_decode(
    workload_contract_json, "biomedical capsule workload contract",
    .DSVERT_DP_CAPSULE_MANIFEST_MAX_WORKLOAD_BYTES)
  families <- c("describe", "survival", "gaussian", "vertical_cross")
  if (is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) ||
      !setequal(names(value), c("version", families)) ||
      !identical(value$version,
                 .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION)) {
    .dsvert_dp_capsule_manifest_abort(
      "workload_contract_conflict", "Invalid workload contract")
  }
  normalized <- stats::setNames(vector("list", length(families)), families)
  specs <- stats::setNames(vector("list", length(families)), families)
  for (family in families) {
    entries <- value[[family]]
    if (is.null(entries)) entries <- list()
    if (!is.list(entries) || (length(entries) &&
        (is.null(names(entries)) || anyNA(names(entries)) ||
         any(!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                    names(entries))) || anyDuplicated(names(entries))))) {
      .dsvert_dp_capsule_manifest_abort(
        "workload_contract_conflict", "Invalid workload contract entries")
    }
    if (length(entries)) {
      entries <- entries[order(names(entries), method = "radix")]
    }
    normalized[[family]] <- vector("list", length(entries))
    names(normalized[[family]]) <- names(entries)
    specs[[family]] <- vector("list", length(entries))
    names(specs[[family]]) <- names(entries)
    for (analysis_id in names(entries)) {
      entry <- entries[[analysis_id]]
      if (!is.list(entry) || is.null(names(entry)) ||
          anyNA(names(entry)) || anyDuplicated(names(entry)) ||
          !setequal(names(entry), c("owner_peer", "spec")) ||
          !is.character(entry$owner_peer) ||
          length(entry$owner_peer) != 1L || is.na(entry$owner_peer) ||
          !entry$owner_peer %in% names(policy$peer_pinset) ||
          !is.list(entry$spec)) {
        .dsvert_dp_capsule_manifest_abort(
          "workload_contract_conflict", "Invalid workload contract owner")
      }
      normalized[[family]][[analysis_id]] <- list(
        owner_peer = entry$owner_peer, spec = entry$spec)
      specs[[family]][[analysis_id]] <- entry$spec
    }
  }
  normalized <- .dsvert_dp_canonical_query_value(c(
    list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
    normalized))

  if (isTRUE(.local_exact)) {
    local <- .dsvert_dp_capsule_manifest_local_specs(policy)
    peer <- policy$peer_name
    for (family in families) {
      owned <- normalized[[family]][vapply(
        normalized[[family]], function(entry) {
          identical(entry$owner_peer, peer)
        }, logical(1L))]
      owned_specs <- lapply(owned, `[[`, "spec")
      same_names <- length(owned_specs) == length(local[[family]]) &&
        setequal(names(owned_specs), names(local[[family]]))
      same_specs <- isTRUE(same_names) && all(vapply(
        names(local[[family]]), function(analysis_id) {
          identical(
            .dsvert_dp_canonical_json(owned_specs[[analysis_id]]),
            .dsvert_dp_canonical_json(local[[family]][[analysis_id]]))
        }, logical(1L)))
      if (!isTRUE(same_specs)) {
        .dsvert_dp_capsule_manifest_abort(
          "local_workload_contract_conflict",
          "The global workload contract changed a custodian-owned fragment")
      }
    }
  }

  for (analysis_id in names(specs$describe)) {
    raw <- specs$describe[[analysis_id]]
    raw$variables <- unname(as.character(unlist(
      raw$variables, use.names = FALSE)))
    raw$histogram_grids <- lapply(
      raw$histogram_grids, function(grid) unname(as.numeric(unlist(
        grid, use.names = FALSE))))
    raw$allocation <- unlist(raw$allocation, use.names = TRUE)
    specs$describe[[analysis_id]] <- raw
  }
  for (analysis_id in names(specs$survival)) {
    raw <- specs$survival[[analysis_id]]
    raw$time_grid <- unname(as.numeric(unlist(
      raw$time_grid, use.names = FALSE)))
    if (identical(raw$version, "cox_partial_likelihood_grid_v1")) {
      raw$predictors <- unname(as.character(unlist(
        raw$predictors, use.names = FALSE)))
      raw$candidate_grid <- lapply(raw$candidate_grid, function(beta) {
        unname(as.numeric(unlist(beta, use.names = FALSE)))
      })
    }
    specs$survival[[analysis_id]] <- raw
  }
  for (analysis_id in names(specs$gaussian)) {
    raw <- specs$gaussian[[analysis_id]]
    if (!identical(raw$version, "random_intercept_v1")) {
      raw$predictors <- unname(as.character(unlist(
        raw$predictors, use.names = FALSE)))
    }
    if (identical(raw$version, "gaussian_random_slope_grid_v1")) {
      raw$random_slopes <- unname(as.character(unlist(
        raw$random_slopes, use.names = FALSE)))
      raw$candidate_grid <- lapply(raw$candidate_grid, function(candidate) list(
        beta = unname(as.numeric(unlist(candidate$beta, use.names = FALSE))),
        sigma2 = as.numeric(candidate$sigma2),
        covariance = unname(as.numeric(unlist(candidate$covariance,
                                               use.names = FALSE)))))
    }
    if (raw$version %in% c("gaussian_ar1_working_gls_grid_v1",
                           "gaussian_ar1_robust_working_gls_grid_v1")) {
      raw$candidate_grid <- lapply(raw$candidate_grid, function(candidate) list(
        beta = unname(as.numeric(unlist(candidate$beta, use.names = FALSE))),
        rho = as.numeric(candidate$rho)))
      if (identical(raw$version, "gaussian_ar1_robust_working_gls_grid_v1")) {
        raw$score_clip <- as.numeric(raw$score_clip)
      }
    }
    if (identical(raw$version, "binary_random_slope_grid_v1")) {
      raw$random_slopes <- unname(as.character(unlist(
        raw$random_slopes, use.names = FALSE)))
      raw$candidate_grid <- lapply(raw$candidate_grid, function(candidate) list(
        beta = unname(as.numeric(unlist(candidate$beta, use.names = FALSE))),
        covariance = unname(as.numeric(unlist(candidate$covariance,
                                               use.names = FALSE)))))
    }
    if (raw$version %in% c("random_intercept_fixed_v2",
                            "random_intercept_fixed_v3")) {
      raw$variance_ratio_grid <- unname(as.numeric(unlist(
        raw$variance_ratio_grid, use.names = FALSE)))
    }
    if (identical(raw$version, "negative_binomial_grid_v1")) {
      raw$theta_grid <- unname(as.numeric(unlist(
        raw$theta_grid, use.names = FALSE)))
    }
    specs$gaussian[[analysis_id]] <- raw
  }
  list(
    value = normalized,
    json = .dsvert_dp_canonical_json(normalized),
    sha256 = digest::digest(
      .dsvert_dp_canonical_json(normalized), algo = "sha256",
      serialize = FALSE),
    specs = specs)
}

.dsvert_dp_capsule_manifest_expected_snapshot <- function(
    policy, datasets, alignment_protocol_version, workload_contract) {
  if (!is.numeric(alignment_protocol_version) ||
      length(alignment_protocol_version) != 1L ||
      is.na(alignment_protocol_version) ||
      !is.finite(alignment_protocol_version) ||
      alignment_protocol_version < 1 ||
      alignment_protocol_version != floor(alignment_protocol_version)) {
    .dsvert_dp_capsule_manifest_abort(
      "logical_snapshot_conflict", "Invalid alignment protocol version")
  }
  local_versions <- vapply(policy$datasets, function(descriptor) {
    as.numeric(descriptor$alignment_manifest_version)
  }, numeric(1L))
  if (!length(local_versions) || anyNA(local_versions) ||
      any(!is.finite(local_versions)) ||
      any(local_versions != alignment_protocol_version)) {
    .dsvert_dp_capsule_manifest_abort(
      "logical_snapshot_conflict",
      "The logical snapshot conflicts with local alignment policy")
  }
  fingerprint <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-logical-snapshot-v1",
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    alignment_protocol_version = as.integer(alignment_protocol_version),
    datasets = datasets,
    workload_contract = workload_contract))
  .dsvert_dp_canonical_query_value(list(
    logical_snapshot_id = policy$cohort_id,
    version = paste0("schema-v1-", fingerprint),
    alignment_protocol_version = as.integer(alignment_protocol_version)))
}

.dsvert_dp_capsule_manifest_unsigned_schema <- function(
    schema_json, workload_contract_json, policy) {
  workload <- .dsvert_dp_capsule_manifest_workload_contract(
    workload_contract_json, policy)
  schema <- .dsvert_dp_capsule_manifest_decode(
    schema_json, "unsigned biomedical capsule schema",
    .DSVERT_DP_CAPSULE_MANIFEST_MAX_SCHEMA_BYTES)
  required <- c(
    "version", "logical_snapshot", "peer_pinset_sha256", "datasets")
  if (is.null(names(schema)) || anyNA(names(schema)) ||
      anyDuplicated(names(schema)) || !setequal(names(schema), required)) {
    .dsvert_dp_capsule_manifest_abort(
      "schema_conflict", "The unsigned capsule schema is invalid")
  }
  placeholder <- stats::setNames(
    as.list(rep(strrep("A", 86L), length(policy$peer_pinset))),
    names(policy$peer_pinset))
  candidate <- c(schema, list(signatures = placeholder))
  validated <- tryCatch(
    .dsvert_dp_capsule_schema(
      policy, schema$logical_snapshot, candidate, function(...) TRUE),
    error = function(error) NULL)
  if (is.null(validated) ||
      !identical(validated$unsigned,
                 .dsvert_dp_canonical_query_value(schema))) {
    .dsvert_dp_capsule_manifest_abort(
      "schema_conflict", "The unsigned capsule schema is invalid")
  }
  expected_snapshot <- .dsvert_dp_capsule_manifest_expected_snapshot(
    policy, validated$unsigned$datasets,
    validated$unsigned$logical_snapshot$alignment_protocol_version,
    workload$value)
  if (!identical(validated$unsigned$logical_snapshot, expected_snapshot)) {
    .dsvert_dp_capsule_manifest_abort(
      "logical_snapshot_conflict",
      "The relay supplied a non-authoritative logical snapshot")
  }
  tryCatch(
    .dsvert_dp_capsule_validate_local_schema(policy, validated$unsigned),
    error = function(error) .dsvert_dp_capsule_manifest_abort(
      "local_policy_conflict",
      "The global schema conflicts with the local custodian policy"))
  candidate <- c(validated$unsigned, list(signatures = placeholder))
  tryCatch(.dsvert_dp_capsule_workload_manifest(
    policy, validated$unsigned$logical_snapshot, candidate,
    describe_specs = workload$specs$describe,
    survival_specs = workload$specs$survival,
    gaussian_specs = workload$specs$gaussian,
    vertical_cross_specs = workload$specs$vertical_cross,
    .signature_verifier = function(...) TRUE), error = function(error) {
      .dsvert_dp_capsule_manifest_abort(
        "workload_contract_conflict",
        "The global workload contract is invalid for the signed schema")
    })
  list(validated = validated, workload = workload)
}

.dsvert_dp_capsule_manifest_sign_impl <- function(
    schema_json, workload_contract_json,
    .policy = NULL, .signer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  checked <- .dsvert_dp_capsule_manifest_unsigned_schema(
    schema_json, workload_contract_json, .policy)
  validated <- checked$validated
  schema_signature <- .dsvert_dp_capsule_manifest_identity_signature(
    .dsvert_dp_capsule_schema_message(validated$unsigned),
    .policy, .signer)
  response <- list(
    version = .DSVERT_DP_CAPSULE_MANIFEST_SIGN_VERSION,
    phase = "global_schema_policy_verified",
    peer_name = .policy$peer_name,
    peer_identity_pk = unname(
      .policy$peer_pinset[[.policy$peer_name]]),
    peer_pinset_sha256 = .policy$peer_pinset_sha256,
    schema_sha256 = validated$sha256,
    workload_contract_sha256 = checked$workload$sha256,
    logical_snapshot = validated$unsigned$logical_snapshot,
    schema_signature = schema_signature,
    data_access = FALSE,
    operation_limit = FALSE,
    request_limit = FALSE,
    history_can_deny_operation = FALSE)
  .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(response))
}

.dsvert_dp_capsule_manifest_signed_schema <- function(
    schema_json, workload_contract_json, policy, verifier = NULL,
    .primitive_scope = NULL) {
  workload <- .dsvert_dp_capsule_manifest_workload_contract(
    workload_contract_json, policy,
    .local_exact = is.null(.primitive_scope))
  schema <- .dsvert_dp_capsule_manifest_decode(
    schema_json, "signed biomedical capsule schema",
    .DSVERT_DP_CAPSULE_MANIFEST_MAX_SCHEMA_BYTES)
  if (is.null(verifier)) verifier <- .dsvert_relay_verify_message
  validated <- tryCatch(
    .dsvert_dp_capsule_schema(
      policy, schema$logical_snapshot, schema, verifier),
    error = function(error) NULL)
  if (is.null(validated)) {
    .dsvert_dp_capsule_manifest_abort(
      "schema_signature_conflict", "The global schema is not fully signed")
  }
  expected_snapshot <- .dsvert_dp_capsule_manifest_expected_snapshot(
    policy, validated$unsigned$datasets,
    validated$unsigned$logical_snapshot$alignment_protocol_version,
    workload$value)
  if (!identical(validated$unsigned$logical_snapshot, expected_snapshot)) {
    .dsvert_dp_capsule_manifest_abort(
      "logical_snapshot_conflict",
      "The signed schema has a non-authoritative logical snapshot")
  }
  tryCatch({
    if (is.null(.primitive_scope)) {
      .dsvert_dp_capsule_validate_local_schema(policy, validated$unsigned)
    } else {
      .dsvert_dp_capsule_validate_local_projection_schema(
        policy, validated$unsigned, .primitive_scope)
    }
  }, error = function(error) .dsvert_dp_capsule_manifest_abort(
    "local_policy_conflict",
    "The signed schema conflicts with the local custodian policy"))
  list(value = schema, validated = validated, workload = workload)
}

.dsvert_dp_capsule_manifest_cache_with <- function(
    policy, secret, code) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS capsule_manifest_cache (",
      "cache_key TEXT PRIMARY KEY, public_capsule_key TEXT,",
      "manifest_sha256 TEXT NOT NULL,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
    fields <- DBI::dbListFields(connection, "capsule_manifest_cache")
    if (!"public_capsule_key" %in% fields) {
      DBI::dbExecute(connection, paste(
        "ALTER TABLE capsule_manifest_cache",
        "ADD COLUMN public_capsule_key TEXT"))
    }
    DBI::dbExecute(connection, paste(
      "CREATE INDEX IF NOT EXISTS capsule_manifest_cache_hash",
      "ON capsule_manifest_cache(manifest_sha256)"))
    DBI::dbExecute(connection, paste(
      "CREATE INDEX IF NOT EXISTS capsule_manifest_cache_public",
      "ON capsule_manifest_cache(public_capsule_key)"))
    code(connection, config, secret)
  })
}

.dsvert_dp_capsule_manifest_local_authority <- function(policy, secret) {
  primitive_scope <- .dsvert_dp_capsule_scope_policy_binding(
    policy$capsule_workload_scope)
  value <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
    protocol = "dsvert-biomedical-capsule-local-authority-v2",
    private_policy_sha256 = .dsvert_dp_policy_hash(policy),
    public_draft = .dsvert_dp_capsule_manifest_draft_unsigned(policy),
    primitive_scope = primitive_scope)))
  .dsvert_capsule_registry_hmac(
    secret, "manifest-local-authority", value)
}

.dsvert_dp_capsule_manifest_cache_record <- function(
    cache_key, public_capsule_key, local_authority_sha256, schema_sha256,
    workload_contract_sha256, manifest_json) {
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_MANIFEST_CACHE_VERSION,
    cache_key = cache_key,
    public_capsule_key = public_capsule_key,
    local_authority_sha256 = local_authority_sha256,
    schema_sha256 = schema_sha256,
    workload_contract_sha256 = workload_contract_sha256,
    manifest_sha256 = digest::digest(
      manifest_json, algo = "sha256", serialize = FALSE),
    manifest_json = manifest_json))
}

.dsvert_dp_capsule_manifest_cache_decode <- function(
    row, secret, expected_key = NULL, expected_manifest_hash = NULL) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !setequal(names(row), c(
        "cache_key", "public_capsule_key", "manifest_sha256",
        "record_json", "row_mac"))) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_corrupt", "The manifest cache row is invalid")
  }
  record <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record)), error = function(error) NULL)
  expected_mac <- if (!is.null(canonical)) {
    .dsvert_capsule_registry_hmac(
      secret, "manifest-authority-cache", canonical)
  } else {
    NULL
  }
  valid <- is.list(record) && !is.null(names(record)) &&
    setequal(names(record), c(
      "version", "cache_key", "public_capsule_key",
      "local_authority_sha256", "schema_sha256",
      "workload_contract_sha256", "manifest_sha256", "manifest_json")) &&
    record$version %in%
      .DSVERT_DP_CAPSULE_MANIFEST_REPLAY_CACHE_VERSIONS &&
    identical(canonical, row$record_json[[1L]]) &&
    identical(record$cache_key, row$cache_key[[1L]]) &&
    identical(record$public_capsule_key,
              row$public_capsule_key[[1L]]) &&
    identical(record$manifest_sha256, row$manifest_sha256[[1L]]) &&
    identical(record$manifest_sha256, digest::digest(
      record$manifest_json, algo = "sha256", serialize = FALSE)) &&
    identical(expected_mac, row$row_mac[[1L]]) &&
    (is.null(expected_key) || identical(record$cache_key, expected_key)) &&
    (is.null(expected_manifest_hash) ||
       identical(record$manifest_sha256, expected_manifest_hash))
  if (!isTRUE(valid)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_corrupt",
      "The manifest cache failed authenticated validation")
  }
  record
}

.dsvert_dp_capsule_manifest_cache_get <- function(
    policy, secret, cache_key = NULL, manifest_sha256 = NULL) {
  if (xor(is.null(cache_key), is.null(manifest_sha256)) == FALSE) {
    stop("Exactly one manifest-cache lookup key is required", call. = FALSE)
  }
  .dsvert_dp_capsule_manifest_cache_with(
    policy, secret, function(connection, config, secret) {
      if (!is.null(cache_key)) {
        row <- DBI::dbGetQuery(connection, paste(
          "SELECT cache_key, public_capsule_key, manifest_sha256,",
          "record_json, row_mac",
          "FROM capsule_manifest_cache WHERE cache_key = ?"),
          params = list(cache_key))
      } else {
        rows <- DBI::dbGetQuery(connection, paste(
          "SELECT cache_key, public_capsule_key, manifest_sha256,",
          "record_json, row_mac",
          "FROM capsule_manifest_cache WHERE manifest_sha256 = ?",
          "ORDER BY cache_key"), params = list(manifest_sha256))
        if (nrow(rows) > 1L) {
          decoded <- lapply(seq_len(nrow(rows)), function(index) {
            .dsvert_dp_capsule_manifest_cache_decode(
              rows[index, , drop = FALSE], secret,
              expected_manifest_hash = manifest_sha256)
          })
          authority <- .dsvert_dp_capsule_manifest_local_authority(
            policy, secret)
          decoded <- decoded[vapply(decoded, function(value) {
            identical(value$local_authority_sha256, authority)
          }, logical(1L))]
          if (!length(decoded)) return(NULL)
          common <- c(
            "public_capsule_key", "local_authority_sha256", "schema_sha256",
            "workload_contract_sha256", "manifest_sha256",
            "manifest_json")
          if (!all(vapply(decoded[-1L], function(value) {
                identical(value[common], decoded[[1L]][common])
              }, logical(1L)))) {
            .dsvert_dp_capsule_manifest_abort(
              "manifest_cache_corrupt",
              "The manifest cache contains conflicting authorizations")
          }
          return(decoded[[1L]])
        }
        row <- rows
      }
      if (!nrow(row)) return(NULL)
      decoded <- .dsvert_dp_capsule_manifest_cache_decode(
        row, secret, expected_key = cache_key,
        expected_manifest_hash = manifest_sha256)
      if (!is.null(manifest_sha256) && !identical(
            decoded$local_authority_sha256,
            .dsvert_dp_capsule_manifest_local_authority(policy, secret))) {
        return(NULL)
      }
      decoded
    })
}

.dsvert_dp_capsule_manifest_cache_put <- function(
    policy, secret, record) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record))
  mac <- .dsvert_capsule_registry_hmac(
    secret, "manifest-authority-cache", json)
  .dsvert_dp_capsule_manifest_cache_with(
    policy, secret, function(connection, config, secret) {
      DBI::dbExecute(connection, "BEGIN IMMEDIATE")
      committed <- FALSE
      on.exit(if (!committed) try(
        DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
      prior_rows <- DBI::dbGetQuery(connection, paste(
        "SELECT cache_key, public_capsule_key, manifest_sha256,",
        "record_json, row_mac FROM capsule_manifest_cache",
        "WHERE public_capsule_key = ? ORDER BY cache_key"),
        params = list(record$public_capsule_key))
      if (nrow(prior_rows)) {
        prior <- lapply(seq_len(nrow(prior_rows)), function(index) {
          .dsvert_dp_capsule_manifest_cache_decode(
            prior_rows[index, , drop = FALSE], secret)
        })
        immutable <- c(
          "public_capsule_key", "local_authority_sha256", "schema_sha256",
          "workload_contract_sha256", "manifest_sha256", "manifest_json")
        if (any(!vapply(prior, function(value) {
              identical(value[immutable], record[immutable])
            }, logical(1L)))) {
          .dsvert_dp_capsule_manifest_abort(
            "private_snapshot_version_conflict",
            paste(
              "A public capsule version is already bound to a different",
              "private snapshot, workload, or implementation"))
        }
      }
      DBI::dbExecute(connection, paste(
        "INSERT OR IGNORE INTO capsule_manifest_cache(",
        "cache_key, public_capsule_key, manifest_sha256, record_json, row_mac)",
        "VALUES(?, ?, ?, ?, ?)"), params = list(
          record$cache_key, record$public_capsule_key,
          record$manifest_sha256, json, mac))
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT cache_key, public_capsule_key, manifest_sha256,",
        "record_json, row_mac",
        "FROM capsule_manifest_cache WHERE cache_key = ?"),
        params = list(record$cache_key))
      observed <- .dsvert_dp_capsule_manifest_cache_decode(
        row, secret, expected_key = record$cache_key)
      if (!identical(observed, record)) {
        .dsvert_dp_capsule_manifest_abort(
          "manifest_cache_conflict",
          "A conflicting manifest already occupies this authority key")
      }
      DBI::dbExecute(connection, "COMMIT")
      committed <- TRUE
      observed
    })
}

.dsvert_dp_capsule_manifest_build_impl <- function(
    schema_json, workload_contract_json,
    .policy = NULL, .secret = NULL, .signer = NULL,
    .verifier = NULL, .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .cache_put = .dsvert_dp_capsule_manifest_cache_put) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  signed <- .dsvert_dp_capsule_manifest_signed_schema(
    schema_json, workload_contract_json, .policy, .verifier)
  specs <- signed$workload$specs
  primitive_scope <- .dsvert_dp_capsule_scope_policy_binding(
    .policy$capsule_workload_scope)
  local_authority <- .dsvert_dp_capsule_manifest_local_authority(
    .policy, .secret)
  public_capsule_key <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-public-authority-v3",
    capsule_schema = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    schema_sha256 = signed$validated$sha256,
    workload_contract_sha256 = signed$workload$sha256,
    primitive_scope = primitive_scope))
  cache_key <- .dsvert_joint_dp_hash(list(
    protocol = .DSVERT_DP_CAPSULE_MANIFEST_CACHE_VERSION,
    policy_hash = .dsvert_dp_policy_hash(.policy),
    local_draft = .dsvert_dp_capsule_manifest_draft_unsigned(.policy),
    primitive_scope = primitive_scope,
    signed_schema = signed$value,
    workload_contract = signed$workload$value))
  record <- .cache_get(.policy, .secret, cache_key = cache_key)
  if (is.null(record)) {
    manifest <- tryCatch(.dsvert_dp_capsule_workload_manifest(
      .policy, signed$validated$unsigned$logical_snapshot, signed$value,
      describe_specs = specs$describe,
      survival_specs = specs$survival,
      gaussian_specs = specs$gaussian,
      vertical_cross_specs = specs$vertical_cross,
      .signature_verifier = if (is.null(.verifier)) {
        .dsvert_relay_verify_message
      } else {
        .verifier
      }), error = function(error) {
        .dsvert_dp_capsule_manifest_abort(
          "custodian_workload_conflict",
          "The custodian workload cannot build this global schema")
      })
    manifest_json <- .dsvert_dp_canonical_json(manifest)
    if (nchar(manifest_json, type = "bytes") >
        .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES) {
      .dsvert_dp_capsule_manifest_abort(
        "manifest_too_large", "The biomedical capsule manifest is too large")
    }
    record <- .dsvert_dp_capsule_manifest_cache_record(
      cache_key, public_capsule_key, local_authority,
      signed$validated$sha256,
      signed$workload$sha256, manifest_json)
    record <- .cache_put(.policy, .secret, record)
  }
  if (!identical(record$schema_sha256, signed$validated$sha256)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_conflict",
      "The memoized manifest has a different signed schema")
  }
  if (!identical(record$public_capsule_key, public_capsule_key)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_conflict",
      "The memoized manifest has a different public capsule authority")
  }
  if (!identical(record$local_authority_sha256, local_authority)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_conflict",
      "The memoized manifest has a different local authority")
  }
  if (!identical(record$workload_contract_sha256,
                 signed$workload$sha256)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_cache_conflict",
      "The memoized manifest has a different workload contract")
  }
  manifest <- .dsvert_dp_capsule_source_manifest(record$manifest_json)
  artifact_index <- .dsvert_dp_capsule_artifact_commitment_index(
    manifest, .policy, record$manifest_sha256)
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_MANIFEST_BUILD_VERSION,
    phase = "server_authoritative_manifest_memoized",
    peer_name = .policy$peer_name,
    peer_identity_pk = unname(
      .policy$peer_pinset[[.policy$peer_name]]),
    peer_pinset_sha256 = .policy$peer_pinset_sha256,
    schema_sha256 = record$schema_sha256,
    workload_contract_sha256 = record$workload_contract_sha256,
    manifest_sha256 = record$manifest_sha256,
    manifest_bytes = as.numeric(nchar(
      record$manifest_json, type = "bytes")),
    capsule_id = manifest$capsule_identity$capsule_id,
    privacy_epoch = as.numeric(.policy$noise_root$epoch),
    noise_key_id = .policy$noise_root$key_id,
    artifact_commitment_count = artifact_index$count,
    artifact_commitments_root = artifact_index$root,
    artifact_commitments = artifact_index$value,
    manifest_json = record$manifest_json,
    durable_memoization = TRUE,
    deterministic_replay = TRUE,
    data_access = FALSE,
    operation_limit = FALSE,
    request_limit = FALSE,
    history_can_deny_operation = FALSE)
  signed_response <- .dsvert_dp_capsule_manifest_sign_object(
    unsigned, .policy, "build", .signer)
  .dsvert_dp_canonical_json(signed_response)
}

# Internal authorization gate for source transport and the vector sampler.
# The supplied manifest is accepted only if this exact byte string was built
# and authenticated locally under the current policy/root epoch.
.dsvert_dp_capsule_manifest_require_built <- function(
    policy, manifest_json, secret = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  if (!is.character(manifest_json) || length(manifest_json) != 1L ||
      is.na(manifest_json) || !nzchar(manifest_json) ||
      nchar(manifest_json, type = "bytes") >
        .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_not_server_authorized", "Invalid manifest authorization")
  }
  manifest_hash <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  record <- .cache_get(
    policy, secret, manifest_sha256 = manifest_hash)
  if (is.null(record) || !identical(record$manifest_json, manifest_json)) {
    .dsvert_dp_capsule_manifest_abort(
      "manifest_not_server_authorized",
      "The manifest was not emitted by this server authority")
  }
  invisible(record)
}

#' Emit the local custodian-owned biomedical capsule schema draft (AGGREGATE)
#'
#' @return Canonical signed public policy metadata.  Protected snapshot and
#'   alignment hashes, row counts and patient-derived digests are never read or
#'   returned.
#' @export
dsvertDPCapsuleManifestDraftDS <- function() {
  .dsvert_dp_capsule_manifest_public(
    "draft", .dsvert_dp_capsule_manifest_draft_impl())
}

#' Verify and sign the deterministic global biomedical schema (AGGREGATE)
#'
#' @param schema_json Canonical unsigned schema assembled from every signed
#'   server draft.
#' @param workload_contract_json Canonical workload contract assembled only
#'   from the custodian-signed draft fragments.
#' @return A policy-verified Ed25519 schema signature and public bindings.
#' @export
dsvertDPCapsuleManifestSignDS <- function(
    schema_json, workload_contract_json) {
  .dsvert_dp_capsule_manifest_public("schema_sign", {
    schema_json <- .dsvert_dsi_text_decode(
      schema_json, "biomedical capsule schema",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_SCHEMA_BYTES)
    workload_contract_json <- .dsvert_dsi_text_decode(
      workload_contract_json, "biomedical capsule workload contract",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_WORKLOAD_BYTES)
    .dsvert_dp_capsule_manifest_sign_impl(
      schema_json, workload_contract_json)
  })
}

#' Build and memoize the server-authoritative biomedical manifest (AGGREGATE)
#'
#' @param schema_json Canonical global schema signed by every pinned peer.
#' @param workload_contract_json Canonical contract containing exactly the
#'   workload fragments signed by their custodian owners.
#' @return A signed envelope containing the canonical, durably memoized
#'   manifest.  No protected object is resolved by this endpoint.
#' @export
dsvertDPCapsuleManifestBuildDS <- function(
    schema_json, workload_contract_json) {
  .dsvert_dp_capsule_manifest_public("build", {
    schema_json <- .dsvert_dsi_text_decode(
      schema_json, "signed biomedical capsule schema",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_SCHEMA_BYTES)
    workload_contract_json <- .dsvert_dsi_text_decode(
      workload_contract_json, "biomedical capsule workload contract",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_WORKLOAD_BYTES)
    .dsvert_dp_capsule_manifest_build_impl(
      schema_json, workload_contract_json)
  })
}
