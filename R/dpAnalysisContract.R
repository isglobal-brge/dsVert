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
  expected <- switch(mechanism$family,
    gaussian = c(
      version = "gaussian-output-perturbation-v1",
      sampler = "gaussian-one-draw-v1"),
    laplace = c(
      version = "laplace-output-perturbation-v1",
      sampler = "laplace-one-draw-v1"),
    discrete_laplace = c(
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
  numeric$fractional_bits <- .dsvert_dp_analysis_positive_integer(
    numeric$fractional_bits, "numeric fractional bits")
  if (numeric$fractional_bits >= numeric$value_bits) {
    stop("Invalid numeric scale in the analysis contract", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(
    numeric$sampler_encoding, "sampler encoding")
  .dsvert_dp_analysis_scalar_id(numeric$output_encoding, "output encoding")
  value$numeric <- numeric
  .dsvert_dp_analysis_named_list(value$public_shape, "public result shape")
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
  transport <- value$transport
  if (!is.list(transport) || is.null(names(transport)) ||
      !identical(names(transport), "chunk_coordinates")) {
    stop("Invalid execution transport", call. = FALSE)
  }
  transport$chunk_coordinates <- .dsvert_dp_analysis_positive_integer(
    transport$chunk_coordinates, "transport chunk coordinates")
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

.dsvert_dp_sticky_subseed_v1 <- function(
    contract, lane) {
  contract <- .dsvert_dp_analysis_contract_validate_v1(contract)
  .dsvert_dp_analysis_scalar_id(lane, "sticky randomness lane")
  lanes <- contract$semantic$privacy$mechanism$randomness$lanes
  if (!lane %in% names(lanes)) {
    stop("The sticky randomness lane is not declared by the analysis",
         call. = FALSE)
  }
  noise_authority <- .dsvert_dp_analysis_identity_pk(
    .get_identity_keypair()$identity_pk, "local noise authority")
  if (!noise_authority %in% unlist(
      contract$semantic$noise_authorities, use.names = FALSE)) {
    stop("The local identity is not a designated noise authority",
         call. = FALSE)
  }
  message <- .dsvert_dp_canonical_json(
    .dsvert_dp_analysis_canonical_value_v1(list(
      version = "dsvert-sticky-artifact-subseed-v1",
      artifact_key = contract$artifact_key,
      lane = lane,
      lane_descriptor = lanes[[lane]],
      noise_authority = noise_authority)))
  digest::hmac(
    key = .dsvert_dp_sticky_noise_key_v1(),
    object = charToRaw(paste0(.DSVERT_DP_STICKY_SUBSEED_DOMAIN, message)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}
