# Confidential Count adapter for the two-peer joint-DP control plane.
#
# This file contains only server-internal producer/finalizer boundaries.  It
# never returns a raw count, an additive source share, a noised input share or
# a pre-clamp value.  The analyst relays only authenticated ciphertext and the
# exact-GC record stream.  Both pinned peers reconstruct the same already-DP,
# clamped output after cross-signed delivery authorization and independently
# sign the durable release.

.DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION <-
  "dsvert-joint-dp-count-adapter-v1"
.DSVERT_JOINT_DP_COUNT_SOURCE_ROW_VERSION <-
  "dsvert-joint-dp-count-source-row-v1"
.DSVERT_JOINT_DP_COUNT_STAGE_ROW_VERSION <-
  "dsvert-joint-dp-count-final-stage-row-v1"
.DSVERT_JOINT_DP_COUNT_TRANSFER_VERSION <-
  "dsvert-joint-dp-count-source-transfer-v1"
.DSVERT_JOINT_DP_COUNT_RESULT_VERSION <-
  "dsvert-joint-dp-count-result-share-v1"
.DSVERT_JOINT_DP_COUNT_RELEASE_VERSION <-
  "dsvert-joint-dp-count-release-v1"
.DSVERT_JOINT_DP_COUNT_REPLAY_VERSION <-
  "dsvert-joint-dp-count-replay-v1"
.DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY <-
  "blob.joint-dp.count-source.v1"
.DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY <-
  "blob.joint-dp.count-final-share.v1"
.DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER <- "count.scalar.v1"
.DSVERT_JOINT_DP_COUNT_SOURCE_PURPOSE <- "joint-count-release"
.DSVERT_JOINT_DP_COUNT_GC_PRODUCER <-
  "joint.dp.count.noised-share-v1"
.DSVERT_JOINT_DP_COUNT_FINAL_TRANSFER_PRODUCER <-
  ".dsvert_joint_dp_count_mint_final_transfer"
.DSVERT_JOINT_DP_COUNT_BACKEND_PREPARE_RESPONSE <-
  "dsvert-joint-dp-count-backend-prepare-response-v1"
.DSVERT_JOINT_DP_COUNT_BACKEND_TOKEN_RESPONSE <-
  "dsvert-joint-dp-count-backend-token-response-v1"
.DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT <-
  "dsvert-joint-dp-laplace-worker-contract-input-v2"
.DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT <-
  "dsvert-joint-dp-laplace-worker-contract-v2"
.DSVERT_JOINT_DP_COUNT_EXACT_CAPABILITY <-
  "joint_dp_count_exact_gc_v1"

.dsvert_joint_dp_count_hex <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid joint-DP Count ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_count_ring128 <- function(value, what = "share") {
  value <- .dsvert_joint_dp_convolution_integer_text(
    value, FALSE, paste0("Count ", what))
  if (length(value) != 1L) {
    stop("A joint-DP Count residue must be a scalar.", call. = FALSE)
  }
  maximum <- "340282366920938463463374607431768211455"
  valid <- nchar(value, type = "bytes") < nchar(maximum) |
    (nchar(value, type = "bytes") == nchar(maximum) & value <= maximum)
  if (!all(valid)) {
    stop("A joint-DP Count residue is outside Ring128.", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_count_allocation_text <- function(value) {
  index <- .dsvert_joint_dp_index(value, "Count allocation index")
  format(index, scientific = FALSE, trim = TRUE, digits = 22L)
}

.dsvert_joint_dp_count_context <- function(
    query_id, capsule_release_id, allocation_index,
    source_contract_hash, purpose_hash, ring_bits = 128L) {
  list(
    query_id = .dsvert_joint_dp_count_hex(query_id, "query id"),
    capsule_release_id = .dsvert_joint_dp_count_hex(
      capsule_release_id, "capsule release id"),
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      allocation_index),
    source_contract_hash = .dsvert_joint_dp_count_hex(
      source_contract_hash, "source-contract hash"),
    purpose_hash = .dsvert_joint_dp_count_hex(
      purpose_hash, "purpose hash"),
    ring = as.character(as.integer(ring_bits)))
}

.dsvert_joint_dp_count_purpose <- function(
    query_id, capsule_release_id, allocation_index, source_contract_hash,
    result_contract_hash) {
  binding <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-count-exact-gc-purpose-v1",
    query_id = .dsvert_joint_dp_count_hex(query_id, "query id"),
    capsule_release_id = .dsvert_joint_dp_count_hex(
      capsule_release_id, "capsule release id"),
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      allocation_index),
    source_contract_hash = .dsvert_joint_dp_count_hex(
      source_contract_hash, "source-contract hash"),
    result_contract_hash = .dsvert_joint_dp_count_hex(
      result_contract_hash, "result-contract hash")))
  paste0("joint.dp.count.", binding)
}

.dsvert_joint_dp_count_result_contract <- function(
    query_id, allocation_index, source_contract, backend_source,
    unit_capacity) {
  source_hash <- .dsvert_joint_dp_hash(source_contract)
  backend_source_hash <- .dsvert_joint_dp_hash(backend_source)
  capacity <- .dsvert_joint_dp_convolution_integer_text(
    as.character(unit_capacity), FALSE, "Count release upper bound")
  contract <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_COUNT_RESULT_VERSION,
    query_id = .dsvert_joint_dp_count_hex(query_id, "query id"),
    capsule_release_id = .dsvert_joint_dp_count_hex(
      source_contract$capsule_release_id, "capsule release id"),
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      allocation_index),
    source_contract_hash = source_hash,
    backend_source_contract_hash = backend_source_hash,
    ring_bits = 127L, frac_bits = 0L, coordinate_count = 1L,
    signed_decode = "twos-complement-ring127",
    postprocessing = "one_joint_noise_draw_and_one_exact_saturation",
    release_lower_bound = "0", release_upper_bound = capacity,
    exact_operation = "joint-dp-laplace-v2",
    source_producer = .DSVERT_JOINT_DP_COUNT_GC_PRODUCER))
  list(contract = contract, hash = .dsvert_joint_dp_hash(contract))
}

.dsvert_joint_dp_count_source_mac <- function(secret, json, family) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(json) || length(json) != 1L || is.na(json) ||
      !family %in% c("source", "final-stage", "release")) {
    stop("Invalid joint-DP Count durable row input.", call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/count/", family, "-row/v1|", json)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_count_install_tables <- function(connection) {
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS joint_count_sources (",
    "query_id TEXT PRIMARY KEY, state TEXT NOT NULL,",
    "source_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS joint_count_final_stage (",
    "query_id TEXT PRIMARY KEY, stage_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS joint_count_releases (",
    "query_id TEXT PRIMARY KEY, release_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL)"))
  invisible(TRUE)
}

.dsvert_joint_dp_count_source_decode <- function(row, secret) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !identical(.dsvert_joint_dp_count_source_mac(
        secret, row$source_json[[1L]], "source"), row$row_mac[[1L]])) {
    stop("The joint-DP Count source ledger failed its integrity check.",
         call. = FALSE)
  }
  value <- tryCatch(jsonlite::fromJSON(
    row$source_json[[1L]], simplifyVector = FALSE),
    error = function(e) NULL)
  required <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "source_contract_hash",
    "mask_contract_hash", "source_peer", "recipient_peer", "role",
    "ring_bits", "coordinate_count", "local_share", "peer_share",
    "state")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), required) &&
    identical(value$version, .DSVERT_JOINT_DP_COUNT_SOURCE_ROW_VERSION) &&
    identical(value$query_id, row$query_id[[1L]]) &&
    identical(value$state, row$state[[1L]]) &&
    value$state %in% c("split_committed", "received_committed") &&
    value$role %in% c("source", "recipient") &&
    identical(as.numeric(value$ring_bits), 128) &&
    identical(as.numeric(value$coordinate_count), 1) &&
    !identical(value$source_peer, value$recipient_peer)
  if (!isTRUE(valid)) {
    stop("The joint-DP Count source ledger row is invalid.", call. = FALSE)
  }
  .dsvert_joint_dp_count_hex(value$query_id, "source query id")
  .dsvert_joint_dp_count_hex(
    value$capsule_release_id, "source capsule release id")
  .dsvert_joint_dp_count_allocation_text(value$allocation_index)
  .dsvert_joint_dp_count_hex(
    value$source_contract_hash, "source-contract hash")
  .dsvert_joint_dp_count_hex(value$mask_contract_hash, "mask-contract hash")
  value$source_peer <- .dsvert_validate_logical_peer_name(value$source_peer)
  value$recipient_peer <- .dsvert_validate_logical_peer_name(
    value$recipient_peer)
  value$local_share <- .dsvert_joint_dp_count_ring128(
    value$local_share, "local source share")
  if (identical(value$role, "source")) {
    if (!identical(value$state, "split_committed") ||
        !is.character(value$peer_share)) {
      stop("The joint-DP Count source row lost its peer share.",
           call. = FALSE)
    }
    value$peer_share <- .dsvert_joint_dp_count_ring128(
      value$peer_share, "peer source share")
  } else if (!identical(value$state, "received_committed") ||
             !is.null(value$peer_share)) {
    stop("The joint-DP Count recipient row is invalid.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_joint_dp_count_source_load <- function(
    connection, query_id, secret) {
  .dsvert_joint_dp_count_install_tables(connection)
  query_id <- .dsvert_joint_dp_count_hex(query_id, "source query id")
  row <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_count_sources WHERE query_id = ?",
    params = list(query_id))
  if (!nrow(row)) NULL else
    .dsvert_joint_dp_count_source_decode(row, secret)
}

.dsvert_joint_dp_count_source_insert <- function(
    connection, value, secret) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(value))
  mac <- .dsvert_joint_dp_count_source_mac(secret, json, "source")
  DBI::dbExecute(connection, paste(
    "INSERT INTO joint_count_sources(query_id, state, source_json, row_mac)",
    "VALUES(?, ?, ?, ?)"), params = list(
      value$query_id, value$state, json, mac))
  invisible(value)
}

.dsvert_joint_dp_count_stage_decode <- function(row, secret) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !identical(.dsvert_joint_dp_count_source_mac(
        secret, row$stage_json[[1L]], "final-stage"), row$row_mac[[1L]])) {
    stop("The joint-DP Count final-stage ledger failed its integrity check.",
         call. = FALSE)
  }
  value <- tryCatch(jsonlite::fromJSON(
    row$stage_json[[1L]], simplifyVector = FALSE),
    error = function(e) NULL)
  required <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "opening_set_hash",
    "result_contract_hash", "operation_id", "output_key", "payload_b64")
  payload <- if (is.list(value) && is.character(value$payload_b64)) {
    tryCatch(jsonlite::base64_dec(value$payload_b64), error = function(e) NULL)
  } else NULL
  canonical <- if (is.raw(payload)) {
    gsub("[\r\n]", "", jsonlite::base64_enc(payload))
  } else NULL
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), required) &&
    identical(value$version, .DSVERT_JOINT_DP_COUNT_STAGE_ROW_VERSION) &&
    identical(value$query_id, row$query_id[[1L]]) &&
    !is.null(canonical) && identical(canonical, value$payload_b64) &&
    is.character(value$operation_id) && length(value$operation_id) == 1L &&
    !is.na(value$operation_id) &&
    grepl("^op_[0-9a-f]{32}$", value$operation_id) &&
    is.character(value$output_key) && length(value$output_key) == 1L &&
    !is.na(value$output_key) &&
    grepl(.DSVERT_EXACT_GC_OUTPUT_RE, value$output_key)
  if (!isTRUE(valid)) {
    stop("The joint-DP Count final-stage row is invalid.", call. = FALSE)
  }
  .dsvert_joint_dp_count_hex(value$query_id, "staged query id")
  .dsvert_joint_dp_count_hex(
    value$capsule_release_id, "staged capsule release id")
  .dsvert_joint_dp_count_allocation_text(value$allocation_index)
  .dsvert_joint_dp_count_hex(value$opening_set_hash, "opening-set hash")
  .dsvert_joint_dp_count_hex(
    value$result_contract_hash, "result-contract hash")
  value <- .dsvert_dp_canonical_query_value(value)
  value$payload <- payload
  value
}

.dsvert_joint_dp_count_stage_load <- function(connection, query_id, secret) {
  .dsvert_joint_dp_count_install_tables(connection)
  query_id <- .dsvert_joint_dp_count_hex(query_id, "staged query id")
  row <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_count_final_stage WHERE query_id = ?",
    params = list(query_id))
  if (!nrow(row)) NULL else
    .dsvert_joint_dp_count_stage_decode(row, secret)
}

.dsvert_joint_dp_count_stage_insert <- function(
    connection, value, secret) {
  persisted <- value[setdiff(names(value), "payload")]
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(persisted))
  mac <- .dsvert_joint_dp_count_source_mac(secret, json, "final-stage")
  DBI::dbExecute(connection, paste(
    "INSERT INTO joint_count_final_stage(query_id, stage_json, row_mac)",
    "VALUES(?, ?, ?)"), params = list(value$query_id, json, mac))
  invisible(value)
}

.dsvert_joint_dp_count_release_decode <- function(row, secret) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !identical(.dsvert_joint_dp_count_source_mac(
        secret, row$release_json[[1L]], "release"), row$row_mac[[1L]])) {
    stop("The joint-DP Count release ledger failed its integrity check.",
         call. = FALSE)
  }
  value <- tryCatch(jsonlite::fromJSON(
    row$release_json[[1L]], simplifyVector = FALSE),
    error = function(e) NULL)
  required <- c(
    "version", "phase", "consortium_id", "peer_name",
    "peer_identity_pk", "capsule_id", "query_id", "allocation_index",
    "capsule_release_id", "source_contract_hash",
    "result_contract_hash", "result_set_hash",
    "delivery_commit_set_hash", "value", "lower_bound", "upper_bound",
    "mechanism", "sampler", "epsilon", "delta", "accuracy_95_abs",
    "accuracy_accounting", "implementation_delta", "backend",
    "postprocessing", "replay_contract", "intermediate_values_exposed",
    "payload_delivery_available", "capability_available", "signature")
  scalar <- function(x) {
    is.character(x) && length(x) == 1L && !is.na(x) && nzchar(x)
  }
  hash_fields <- c(
    "capsule_id", "query_id", "capsule_release_id",
    "source_contract_hash", "result_contract_hash", "result_set_hash",
    "delivery_commit_set_hash")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), required) &&
    identical(value$version, .DSVERT_JOINT_DP_COUNT_RELEASE_VERSION) &&
    identical(value$phase, "count_released") &&
    identical(value$query_id, row$query_id[[1L]]) &&
    identical(value$capsule_id, value$query_id) &&
    all(vapply(value[hash_fields], function(x) {
      scalar(x) && grepl("^[0-9a-f]{64}$", x)
    }, logical(1L))) &&
    all(vapply(value[c(
      "consortium_id", "peer_name", "peer_identity_pk", "value",
      "lower_bound", "upper_bound", "mechanism", "sampler", "epsilon",
      "delta", "accuracy_95_abs", "accuracy_accounting",
      "implementation_delta",
      "backend", "postprocessing", "replay_contract",
      "signature")], scalar, logical(1L))) &&
    is.finite(suppressWarnings(as.numeric(value$epsilon))) &&
    as.numeric(value$epsilon) > 0 &&
    is.finite(suppressWarnings(as.numeric(value$delta))) &&
    as.numeric(value$delta) > 0 && as.numeric(value$delta) < 1 &&
    grepl("^(0|[1-9][0-9]*)$", value$value) &&
    grepl("^(0|[1-9][0-9]*)$", value$accuracy_95_abs) &&
    identical(
      value$accuracy_accounting,
      "one-draw-marginal-95-mechanism-noise-only") &&
    identical(value$mechanism,
              "discrete-laplace-geometric-tv-v2") &&
    identical(value$sampler, .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2) &&
    identical(value$backend,
              "exact-gc-joint-dp-laplace-ring127-v2") &&
    identical(value$postprocessing,
              "one-joint-noise-draw-and-one-clamp-inside-exact-gc") &&
    is.finite(suppressWarnings(as.numeric(value$implementation_delta))) &&
    as.numeric(value$implementation_delta) > 0 &&
    as.numeric(value$implementation_delta) <= as.numeric(value$delta) &&
    identical(value$lower_bound, "0") &&
    grepl("^[1-9][0-9]*$", value$upper_bound) &&
    identical(value$intermediate_values_exposed, FALSE) &&
    identical(value$payload_delivery_available, TRUE) &&
    identical(value$capability_available, TRUE)
  if (!isTRUE(valid)) {
    stop("The joint-DP Count release ledger row is invalid.", call. = FALSE)
  }
  .dsvert_joint_dp_count_allocation_text(value$allocation_index)
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_joint_dp_count_release_load <- function(
    connection, query_id, secret) {
  .dsvert_joint_dp_count_install_tables(connection)
  query_id <- .dsvert_joint_dp_count_hex(query_id, "release query id")
  row <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_count_releases WHERE query_id = ?",
    params = list(query_id))
  if (!nrow(row)) NULL else
    .dsvert_joint_dp_count_release_decode(row, secret)
}

.dsvert_joint_dp_count_release_insert <- function(
    connection, value, secret) {
  value <- .dsvert_dp_canonical_query_value(value)
  json <- .dsvert_dp_canonical_json(value)
  mac <- .dsvert_joint_dp_count_source_mac(secret, json, "release")
  DBI::dbExecute(connection, paste(
    "INSERT INTO joint_count_releases(query_id, release_json, row_mac)",
    "VALUES(?, ?, ?)"), params = list(value$query_id, json, mac))
  invisible(value)
}

.dsvert_joint_dp_count_contracts <- function(policy, dataset_public) {
  context <- .dsvert_joint_dp_policy_context(policy)
  if (!identical(policy$adjacency, "add_remove_patient")) {
    stop(paste(
      "The noisy joint-DP Count finalizer is only valid for add/remove",
      "adjacency; fixed-cohort Count is a zero-cost public policy value."),
      call. = FALSE)
  }
  required <- c(
    "data_name", "id", "version", "alignment_manifest_hash",
    "alignment_manifest_version")
  if (!is.list(dataset_public) || is.null(names(dataset_public)) ||
      !setequal(names(dataset_public), required)) {
    stop("The joint-DP Count dataset binding is invalid.", call. = FALSE)
  }
  alignment_version <- dataset_public$alignment_manifest_version
  if (is.null(alignment_version)) alignment_version <- 1L
  logical_snapshot <- .dsvert_dp_canonical_query_value(list(
    logical_snapshot_id = dataset_public$id,
    version = dataset_public$version,
    alignment_protocol_version = as.integer(alignment_version)))
  admission <- .dsvert_dp_admission_public(policy)
  source_context_hash <- .dsvert_joint_dp_hash(list(
    protocol = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    consortium_id = context$consortium_id,
    logical_snapshot = logical_snapshot,
    admission = admission))
  producer_attestation_hash <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-count-producer-attestation-v1",
    adapter = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    producer = .DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER,
    statistic = "admitted-privacy-unit-count",
    split = .DSVERT_JOINT_DP_UNIFORM_SPLIT_VERSION,
    finalizer = "exact-gc-joint-dp-laplace-ring127-v2"))
  capacity <- format(
    as.numeric(policy$unit_capacity), scientific = FALSE, trim = TRUE)
  source_template <- .dsvert_joint_dp_convolution_source_contract(
    producer = .DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER,
    purpose = .DSVERT_JOINT_DP_COUNT_SOURCE_PURPOSE,
    source_context_hash = source_context_hash,
    # A self identifier cannot be part of the hash that creates itself.  The
    # source-binding projection below excludes only this placeholder.
    capsule_release_id = strrep("0", 64L),
    ring_bits = 128L, frac_bits = 0L,
    statistic_lower_bounds = "0", statistic_upper_bounds = capacity,
    release_lower_bounds = "0", release_upper_bounds = capacity,
    producer_attestation_hash = producer_attestation_hash)
  source_binding_hash <-
    .dsvert_joint_dp_convolution_source_binding_hash(source_template)
  backend_source <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_BACKEND_SOURCE_V2,
    producer = source_template$producer, purpose = source_template$purpose,
    source_context_hash = source_template$source_context_hash,
    ring_bits = 127L, frac_bits = 0L, coordinate_count = 1L,
    encoded_lower = "0", encoded_upper = capacity,
    sensitivity_steps = "1"))
  backend_source_hash <- .dsvert_joint_dp_hash(backend_source)
  mechanism <- .dsvert_dp_canonical_query_value(list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = source_template$producer, purpose = source_template$purpose,
    source_context_hash = source_template$source_context_hash,
    mechanism = "discrete-laplace-geometric-tv-v2",
    mechanism_version = "joint-sampler-v2",
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    sensitivity_norm = "l1", sensitivity = 1,
    coordinate_count = 1L,
    # The finite exact-GC sampler consumes an explicit implementation-delta
    # reserve certified by its exact-rational public planner.
    uses_delta = TRUE,
    clipping_hash = backend_source_hash,
    ring_bits = 127L, frac_bits = 0L))
  mask_mechanism <- .dsvert_dp_canonical_query_value(list(
    producer = source_template$producer, purpose = source_template$purpose,
    source_context_hash = source_template$source_context_hash,
    coordinate_count = 1L, ring_bits = 128L, frac_bits = 0L,
    clipping_hash = source_binding_hash))
  bounds <- .dsvert_dp_canonical_query_value(list(
    source_binding_hash = source_binding_hash,
    backend_source_contract_hash = backend_source_hash,
    statistic_lower_bound = "0", statistic_upper_bound = capacity,
    release_lower_bound = "0", release_upper_bound = capacity,
    exact_postprocessing =
      "one-joint-noise-draw-and-one-clamp-inside-exact-gc"))
  workload <- .dsvert_dp_canonical_query_value(list(
    workload_version = "dsvert-joint-dp-count-coordinate-workload-v1",
    capsule_scope = "transitional_single_admitted_count_coordinate",
    coordinate_family = "admitted_count", coordinate_count = 1L,
    whole_biomedical_workload = FALSE,
    capsule_mechanism = mechanism,
    source_binding_hash = source_binding_hash,
    backend_source_contract_hash = backend_source_hash,
    finalizer = "exact-gc-joint-dp-laplace-ring127-v2"))
  capsule_identity <- .dsvert_joint_dp_capsule_identity(
    policy, logical_snapshot,
    capsule_schema = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    admission = admission, bounds = bounds, workload = workload)
  capsule_release_id <- capsule_identity$capsule_id
  source <- .dsvert_joint_dp_convolution_source_contract(
    producer = .DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER,
    purpose = .DSVERT_JOINT_DP_COUNT_SOURCE_PURPOSE,
    source_context_hash = source_context_hash,
    capsule_release_id = capsule_release_id,
    ring_bits = 128L, frac_bits = 0L,
    statistic_lower_bounds = "0", statistic_upper_bounds = capacity,
    release_lower_bounds = "0", release_upper_bounds = capacity,
    producer_attestation_hash = producer_attestation_hash)
  if (!identical(
      .dsvert_joint_dp_convolution_source_binding_hash(source),
      source_binding_hash)) {
    stop("The Count source changed while finalizing its capsule identity.",
         call. = FALSE)
  }
  arguments <- .dsvert_dp_canonical_query_value(list(
    adapter_version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    capsule_release_id = capsule_release_id,
    admission = admission, source_contract = source,
    source_mask_mechanism = mask_mechanism,
    backend_source_contract = backend_source))
  list(
    context = context, logical_snapshot = logical_snapshot,
    arguments = arguments, source = source, backend_source = backend_source,
    mechanism = mechanism,
    capsule_identity = capsule_identity)
}

.dsvert_joint_dp_count_dataset_public <- function(policy, data_name) {
  .validate_data_name(data_name)
  descriptor <- policy$datasets[[data_name]]
  if (!is.list(descriptor)) {
    stop("The protected Count object is absent from the dataset manifest.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    data_name = data_name,
    id = descriptor$id,
    version = descriptor$version,
    alignment_manifest_hash = descriptor$alignment_manifest_hash,
    alignment_manifest_version = descriptor$alignment_manifest_version))
}

.dsvert_joint_dp_count_mint_proposal <- function(
    policy, data_name, envir, .secret = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  snapshot <- .dsvert_dp_resolve_snapshot(policy, data_name, envir, .secret)
  # Admission is part of the producer boundary.  Its exact unit cardinality
  # remains local and is intentionally absent from the returned token.
  invisible(.dsvert_dp_admit_units(snapshot$data, policy))
  contracts <- .dsvert_joint_dp_count_contracts(
    policy, snapshot$dataset$public)
  proposal <- .dsvert_joint_dp_proposal(
    policy, contracts$logical_snapshot, "unit_count",
    contracts$arguments, snapshot$dataset$fingerprint,
    contracts$mechanism,
    capsule_identity = contracts$capsule_identity, .secret = .secret)
  list(
    version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    proposal_token = .dsvert_joint_dp_dsi_mint_proposal(
      policy, proposal, .secret = .secret),
    query_id = proposal$query_id,
    capability_available = FALSE,
    unavailable_reason =
      "joint_dp_count_delivery_not_e2e_promoted")
}

.dsvert_joint_dp_count_open_state <- function(
    policy, own_opening_token, peer_opening_token,
    .secret = NULL, .verifier = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  state <- .dsvert_joint_dp_backend_open_record_v2(
    policy, own_opening_token, peer_opening_token, .secret, .verifier)
  mechanism <- state$record$common_query$mechanism
  arguments <- state$record$common_query$arguments
  source <- if (is.list(arguments)) arguments$source_contract else NULL
  backend_source <- if (is.list(arguments)) {
    arguments$backend_source_contract
  } else NULL
  mask_mechanism <- if (is.list(arguments)) {
    arguments$source_mask_mechanism
  } else NULL
  valid <- is.list(source) && is.list(backend_source) &&
    is.list(mask_mechanism) && is.list(mechanism) &&
    identical(state$record$common_query$method, "unit_count") &&
    identical(arguments$adapter_version,
              .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION) &&
    identical(arguments$capsule_release_id,
              source$capsule_release_id) &&
    identical(mechanism$producer, .DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER) &&
    identical(mechanism$purpose, .DSVERT_JOINT_DP_COUNT_SOURCE_PURPOSE) &&
    identical(mechanism$sampler,
              .DSVERT_JOINT_DP_SAMPLER) &&
    identical(mechanism$mechanism_version, "joint-sampler-v2") &&
    identical(mechanism$mechanism,
              "discrete-laplace-geometric-tv-v2") &&
    identical(mechanism$sensitivity_norm, "l1") &&
    identical(as.numeric(mechanism$sensitivity), 1) &&
    identical(as.numeric(mechanism$coordinate_count), 1) &&
    identical(mechanism$uses_delta, TRUE) &&
    as.numeric(state$record$delta) > 0 &&
    identical(as.numeric(mechanism$ring_bits), 127) &&
    identical(as.numeric(mechanism$frac_bits), 0)
  if (!isTRUE(valid)) {
    stop("The allocation is not a purpose-bound joint-DP Count.",
         call. = FALSE)
  }
  source <- .dsvert_joint_dp_convolution_validate_source(
    source, mask_mechanism)
  backend_source <- .dsvert_joint_dp_backend_source_v2(
    backend_source, mechanism)
  state$source <- source
  state$source_hash <- .dsvert_joint_dp_hash(source)
  state$backend_source <- backend_source
  state$backend_source_hash <- .dsvert_joint_dp_hash(backend_source)
  state$mask_hash <- .dsvert_joint_dp_hash(source$mask)
  state$secret <- .secret
  state
}

.dsvert_joint_dp_count_bound_snapshot <- function(
    state, policy, data_name, envir) {
  snapshot <- .dsvert_dp_resolve_snapshot(
    policy, data_name, envir, state$secret)
  contracts <- .dsvert_joint_dp_count_contracts(
    policy, snapshot$dataset$public)
  proposal <- .dsvert_joint_dp_proposal(
    policy, contracts$logical_snapshot, "unit_count",
    contracts$arguments, snapshot$dataset$fingerprint,
    contracts$mechanism,
    capsule_identity = contracts$capsule_identity, .secret = state$secret)
  record <- state$record
  if (!identical(proposal$query_id, record$query_id) ||
      !identical(proposal$snapshot_binding,
                 record$own_prepare$snapshot_binding) ||
      !identical(.dsvert_joint_dp_hash(contracts$source),
                 state$source_hash) ||
      !identical(.dsvert_joint_dp_hash(contracts$backend_source),
                 state$backend_source_hash)) {
    stop("The protected Count snapshot does not match its durable allocation.",
         call. = FALSE)
  }
  admission <- .dsvert_dp_admit_units(snapshot$data, policy)
  list(snapshot = snapshot, admission = admission, contracts = contracts)
}

.dsvert_joint_dp_count_source_record <- function(
    state, role, local_share, peer_share = NULL) {
  peers <- sort(state$context$common$designated_noise_peers, method = "radix")
  if (length(peers) != 2L) {
    stop("Joint-DP Count requires exactly two designated peers.",
         call. = FALSE)
  }
  source_peer <- peers[[1L]]
  recipient_peer <- peers[[2L]]
  if (!role %in% c("source", "recipient") ||
      (identical(role, "source") &&
       !identical(state$context$peer_name, source_peer)) ||
      (identical(role, "recipient") &&
       !identical(state$context$peer_name, recipient_peer))) {
    stop("The local peer has the wrong Count source role.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_COUNT_SOURCE_ROW_VERSION,
    query_id = state$record$query_id,
    capsule_release_id = state$source$capsule_release_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      state$record$allocation_index),
    source_contract_hash = state$source_hash,
    mask_contract_hash = state$mask_hash,
    source_peer = source_peer, recipient_peer = recipient_peer,
    role = role, ring_bits = 128L, coordinate_count = 1L,
    local_share = .dsvert_joint_dp_count_ring128(local_share),
    peer_share = if (identical(role, "source")) {
      .dsvert_joint_dp_count_ring128(peer_share)
    } else NULL,
    state = if (identical(role, "source")) {
      "split_committed"
    } else "received_committed"))
}

# The only function allowed to observe the exact admitted count.  It replaces
# that scalar with a uniformly masked Ring128 pair and commits both shares
# before returning an opaque acknowledgement.  Neither share is returned.
.dsvert_joint_dp_count_commit_split <- function(
    policy, own_opening_token, peer_opening_token,
    data_name, envir, .secret = NULL, .verifier = NULL,
    .splitter = NULL, .phase_hook = NULL) {
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  peers <- sort(state$context$common$designated_noise_peers, method = "radix")
  if (!identical(state$context$peer_name, peers[[1L]])) {
    stop("Only the deterministic designated Count source may split.",
         call. = FALSE)
  }
  load_existing <- function() {
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, state$secret, .verifier)
    existing <- .dsvert_joint_dp_count_source_load(
      handle$connection, state$record$query_id, state$secret)
    if (!is.null(existing)) {
      expected <- .dsvert_joint_dp_count_source_record(
        state, "source", existing$local_share, existing$peer_share)
      if (!identical(existing, expected)) {
        stop("Conflicting replay of the durable Count split.",
             call. = FALSE)
      }
    }
    existing
  }
  record <- load_existing()
  if (is.null(record)) {
    bound <- .dsvert_joint_dp_count_bound_snapshot(
      state, policy, data_name, envir)
    exact_count <- sum(bound$admission$present)
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    record <- .dsvert_joint_dp_transaction(handle$connection, {
      .dsvert_joint_dp_initialize_validate(
        handle$connection, policy, state$secret, .verifier)
      .dsvert_joint_dp_count_install_tables(handle$connection)
      raced <- .dsvert_joint_dp_count_source_load(
        handle$connection, state$record$query_id, state$secret)
      if (!is.null(raced)) {
        expected <- .dsvert_joint_dp_count_source_record(
          state, "source", raced$local_share, raced$peer_share)
        if (!identical(raced, expected)) {
          stop("Conflicting concurrent Count split commit.",
               call. = FALSE)
        }
        raced
      } else {
        split <- .dsvert_joint_dp_uniform_split_ring128(
          exact_count, state$record$query_id,
          state$record$allocation_index, state$source,
          coordinate_index = 0, .splitter = .splitter)
        created <- .dsvert_joint_dp_count_source_record(
          state, "source", split$left_share, split$right_share)
        .dsvert_joint_dp_count_source_insert(
          handle$connection, created, state$secret)
        created
      }
    })
    rm(exact_count)
  }
  if (is.function(.phase_hook)) .phase_hook("after_count_split_commit")
  # Neither half of the masking pair crosses this producer boundary.  The
  # source peer later loads the recipient half directly into authenticated
  # peer transport; callers receive only a replay-safe acknowledgement.
  list(
    version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    state = record$state, stored = TRUE, query_id = record$query_id,
    capsule_release_id = record$capsule_release_id,
    capability_available = FALSE)
}

.dsvert_joint_dp_count_transfer_binding <- function(state, policy) {
  upper <- unlist(
    state$source$release_upper_bounds, use.names = FALSE)[[1L]]
  result <- .dsvert_joint_dp_count_result_contract(
    state$record$query_id, state$record$allocation_index,
    state$source, state$backend_source, upper)
  purpose <- .dsvert_joint_dp_count_purpose(
    state$record$query_id, state$source$capsule_release_id,
    state$record$allocation_index,
    state$source_hash, result$hash)
  purpose_hash <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-count-purpose-hash-v1",
    purpose = purpose))
  list(
    result_contract = result$contract,
    result_contract_hash = result$hash,
    purpose = purpose, purpose_hash = purpose_hash,
    context = .dsvert_joint_dp_count_context(
      state$record$query_id, state$source$capsule_release_id,
      state$record$allocation_index,
      state$source_hash, purpose_hash))
}

.dsvert_joint_dp_count_transfer_body <- function(
    state, binding, share) {
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_COUNT_TRANSFER_VERSION,
    query_id = state$record$query_id,
    capsule_release_id = state$source$capsule_release_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      state$record$allocation_index),
    source_contract_hash = state$source_hash,
    mask_contract_hash = state$mask_hash,
    result_contract_hash = binding$result_contract_hash,
    purpose = binding$purpose, purpose_hash = binding$purpose_hash,
    ring_bits = 128L, coordinate_index = 0L,
    share = .dsvert_joint_dp_count_ring128(share, "transferred share")))
}

.dsvert_joint_dp_count_decode_transfer <- function(raw_value) {
  value <- tryCatch(jsonlite::fromJSON(
    rawToChar(raw_value), simplifyVector = FALSE),
    error = function(e) NULL)
  canonical <- tryCatch(charToRaw(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(value))), error = function(e) NULL)
  required <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "source_contract_hash",
    "mask_contract_hash", "result_contract_hash", "purpose",
    "purpose_hash", "ring_bits", "coordinate_index", "share")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), required) ||
      !identical(value$version, .DSVERT_JOINT_DP_COUNT_TRANSFER_VERSION) ||
      !identical(canonical, raw_value) ||
      !identical(as.numeric(value$ring_bits), 128) ||
      !identical(as.numeric(value$coordinate_index), 0)) {
    stop("The encrypted joint-DP Count source transfer is invalid.",
         call. = FALSE)
  }
  .dsvert_joint_dp_count_hex(value$query_id, "transfer query id")
  .dsvert_joint_dp_count_hex(
    value$capsule_release_id, "transfer capsule release id")
  .dsvert_joint_dp_count_allocation_text(value$allocation_index)
  for (name in c(
      "source_contract_hash", "mask_contract_hash",
      "result_contract_hash", "purpose_hash")) {
    .dsvert_joint_dp_count_hex(value[[name]], paste(name, "transfer field"))
  }
  value$share <- .dsvert_joint_dp_count_ring128(
    value$share, "transferred share")
  value
}

.dsvert_joint_dp_count_load_source_row <- function(
    policy, state, .verifier = NULL) {
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_initialize_validate(
    handle$connection, policy, state$secret, .verifier)
  value <- .dsvert_joint_dp_count_source_load(
    handle$connection, state$record$query_id, state$secret)
  if (is.null(value) ||
      !identical(value$capsule_release_id,
                 state$source$capsule_release_id) ||
      !identical(value$source_contract_hash, state$source_hash) ||
      !identical(value$mask_contract_hash, state$mask_hash) ||
      !identical(value$allocation_index,
                 .dsvert_joint_dp_count_allocation_text(
                   state$record$allocation_index))) {
    stop("The durable joint-DP Count source share is unavailable.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_count_backend_receipt_json <- function(
    value, policy, version, phase, .verifier = NULL, what = "backend receipt") {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 64L * 1024L) {
    stop("Invalid joint-DP Count ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(e) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded)), error = function(e) NULL)
  if (is.null(decoded) || !identical(canonical, value)) {
    stop("Invalid joint-DP Count ", what, ".", call. = FALSE)
  }
  .dsvert_joint_dp_backend_verify_v2(
    decoded, policy, version, phase, .verifier)
  decoded
}

.dsvert_joint_dp_count_backend_set <- function(
    policy, first_json, second_json, version, phase,
    .verifier = NULL, what = "backend receipts") {
  values <- list(
    .dsvert_joint_dp_count_backend_receipt_json(
      first_json, policy, version, phase, .verifier, what),
    .dsvert_joint_dp_count_backend_receipt_json(
      second_json, policy, version, phase, .verifier, what))
  names(values) <- vapply(values, `[[`, character(1L), "peer_name")
  context <- .dsvert_joint_dp_policy_context(policy)
  peers <- .dsvert_joint_dp_backend_peers_v2(context)
  if (anyDuplicated(names(values)) || !setequal(names(values), peers)) {
    stop("Joint-DP Count requires one signed backend receipt per pinned peer.",
         call. = FALSE)
  }
  values[peers]
}

.dsvert_joint_dp_count_backend_prepare <- function(
    policy, own_opening_token, peer_opening_token,
    .secret = NULL, .signer = NULL, .verifier = NULL) {
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  .dsvert_joint_dp_backend_prepare_v2(
    policy, own_opening_token, peer_opening_token,
    state$backend_source, .secret = state$secret,
    .signer = .signer, .verifier = .verifier)
}

.dsvert_joint_dp_count_backend_token <- function(
    policy, first_prepare_json, second_prepare_json,
    .signer = NULL, .verifier = NULL) {
  prepares <- .dsvert_joint_dp_count_backend_set(
    policy, first_prepare_json, second_prepare_json,
    .DSVERT_JOINT_DP_BACKEND_PREPARE_V2, "backend_prepared",
    .verifier, "backend prepare")
  context <- .dsvert_joint_dp_policy_context(policy)
  .dsvert_joint_dp_backend_token_v2(
    policy, prepares[[1L]], prepares[[2L]],
    .signer = .signer, .verifier = .verifier)
}

.dsvert_joint_dp_count_accuracy95 <- function(plan) {
  denominator <- 2^as.integer(plan$bernoulli_bits)
  continuation <- (denominator - as.numeric(plan$stop_numerator)) /
    denominator
  maximum <- as.integer(plan$max_geometric_steps)
  for (radius in 0:maximum) {
    if (2 * continuation^(radius + 1L) / (1 + continuation) <= 0.05) {
      return(as.character(radius))
    }
  }
  as.character(maximum)
}

.dsvert_joint_dp_count_worker_contract <- function(
    policy, state, prepares, tokens,
    .verifier = NULL, .compiler = NULL) {
  context <- state$context
  peers <- .dsvert_joint_dp_backend_peers_v2(context)
  if (!is.list(prepares) || !identical(names(prepares), peers) ||
      !is.list(tokens) || !identical(names(tokens), peers)) {
    stop("The joint-DP Count backend transcript is incomplete.",
         call. = FALSE)
  }
  for (peer in peers) {
    .dsvert_joint_dp_backend_verify_v2(
      prepares[[peer]], policy, .DSVERT_JOINT_DP_BACKEND_PREPARE_V2,
      "backend_prepared", .verifier)
    .dsvert_joint_dp_backend_verify_v2(
      tokens[[peer]], policy, .DSVERT_JOINT_DP_BACKEND_TOKEN_V2,
      "backend_preflight_only", .verifier)
  }
  plan <- .dsvert_joint_dp_laplace_plan_v2(
    state$record$epsilon, state$record$delta,
    state$backend_source$sensitivity_steps,
    state$backend_source$coordinate_count, 8L, 4096L)
  plan_hash <- .dsvert_joint_dp_hash(plan)
  token_hashes <- lapply(state$tokens, .dsvert_joint_dp_hash)
  transcript <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-backend-transcript-v2",
    consortium_id = context$consortium_id,
    query_id = state$record$query_id,
    allocation_index = state$record$allocation_index,
    ordered_v1_opening_token_hashes = token_hashes,
    ordered_peer_pinset = as.list(context$pins),
    source_contract = state$backend_source, sampler_plan = plan))
  common <- c(
    "consortium_id", "query_id", "allocation_index", "transcript_hash",
    "source_contract_hash", "plan_hash")
  expected_common <- list(
    consortium_id = context$consortium_id,
    query_id = state$record$query_id,
    allocation_index = state$record$allocation_index,
    transcript_hash = transcript,
    source_contract_hash = state$backend_source_hash,
    plan_hash = plan_hash)
  if (!all(vapply(prepares, function(value) {
    identical(value[common], expected_common)
  }, logical(1L)))) {
    stop("The Count backend prepares do not match the durable allocation.",
         call. = FALSE)
  }
  roles <- vapply(prepares, `[[`, character(1L), "role")
  if (!identical(unname(roles), c("garbler", "evaluator"))) {
    stop("The Count backend roles do not match exact-GC peer ordering.",
         call. = FALSE)
  }
  for (peer in peers) {
    expected_context <- .dsvert_joint_dp_backend_commitment_context_v2(
      transcript, prepares[[peer]]$role, peer)
    if (!identical(prepares[[peer]]$commitment_context,
                   expected_context)) {
      stop("A Count backend seed commitment has the wrong context.",
           call. = FALSE)
    }
  }
  commitments <- lapply(prepares, `[[`, "seed_commitment_v2")
  prepare_set_hash <- .dsvert_joint_dp_hash(prepares)
  semantic_hash <- .dsvert_joint_dp_hash(list(
    template = .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2,
    sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
    transcript_hash = transcript,
    ordered_seed_commitments = commitments,
    source_contract_hash = state$backend_source_hash,
    plan_hash = plan_hash))
  token_common <- list(
    consortium_id = context$consortium_id,
    query_id = state$record$query_id,
    allocation_index = state$record$allocation_index,
    transcript_hash = transcript,
    prepare_set_hash = prepare_set_hash,
    ordered_seed_commitments = commitments,
    source_contract_hash = state$backend_source_hash,
    plan_hash = plan_hash,
    semantic_circuit_contract_hash = semantic_hash,
    worker_attestation_available = FALSE,
    capability_available = FALSE,
    unavailable_reason = .DSVERT_JOINT_DP_BACKEND_UNAVAILABLE_V2)
  if (!all(vapply(tokens, function(value) {
    identical(value[names(token_common)], token_common)
  }, logical(1L)))) {
    stop("The Count backend tokens do not cross-authorize one transcript.",
         call. = FALSE)
  }
  input <- list(
    version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT,
    ring_bits = 127L, frac_bits = 0L, coordinate_count = 1L,
    epsilon = state$record$epsilon,
    allocated_delta = state$record$delta,
    sensitivity_steps = state$backend_source$sensitivity_steps,
    encoded_lower = state$backend_source$encoded_lower,
    encoded_upper = state$backend_source$encoded_upper,
    bernoulli_bits = 8L, max_steps = 4096L,
    transcript_hash = transcript,
    garbler_commitment_context = prepares[[peers[[1L]]]]$commitment_context,
    evaluator_commitment_context = prepares[[peers[[2L]]]]$commitment_context,
    garbler_seed_commitment = prepares[[peers[[1L]]]]$seed_commitment_v2,
    evaluator_seed_commitment = prepares[[peers[[2L]]]]$seed_commitment_v2)
  compiler <- if (is.null(.compiler)) function(value) {
    .callMpcTool("joint-dp-laplace-worker-contract-v2", value)
  } else .compiler
  if (!is.function(compiler)) {
    stop("Invalid joint-DP Count contract compiler.", call. = FALSE)
  }
  value <- compiler(input)
  fields <- c(
    "version", "capability_id", "operation", "purpose",
    "circuit_digest", "input_contract", "protected_inputs_accepted",
    "private_seed_accepted", "worker_policy", "capability_available")
  policy_fields <- c(
    "version", "sampler", "bernoulli_bits", "stop_numerator",
    "max_geometric_steps", "sensitivity_steps", "epsilon",
    "allocated_delta", "encoded_lower", "encoded_upper", "transcript_hash",
    "garbler_commitment_context", "evaluator_commitment_context",
    "garbler_seed_commitment", "evaluator_seed_commitment",
    "circuit_digest", "implementation_delta_numerator",
    "implementation_delta_denominator")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) && is.list(value$worker_policy) &&
    !is.null(names(value$worker_policy)) &&
    setequal(names(value$worker_policy), policy_fields) &&
    identical(value$version, .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT) &&
    identical(value$capability_id,
              .DSVERT_JOINT_DP_COUNT_EXACT_CAPABILITY) &&
    identical(value$operation, "joint-dp-laplace-v2") &&
    identical(value$input_contract, "public-data-free-count-v1") &&
    identical(value$protected_inputs_accepted, FALSE) &&
    identical(value$private_seed_accepted, FALSE) &&
    identical(value$capability_available, TRUE) &&
    is.character(value$circuit_digest) &&
    grepl("^[0-9a-f]{64}$", value$circuit_digest) &&
    identical(value$purpose,
              paste0("joint-dp-laplace-v2/", value$circuit_digest)) &&
    identical(value$worker_policy$circuit_digest, value$circuit_digest) &&
    identical(value$worker_policy$version,
              .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2) &&
    identical(value$worker_policy$sampler,
              .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2) &&
    identical(as.integer(value$worker_policy$bernoulli_bits),
              as.integer(plan$bernoulli_bits)) &&
    identical(value$worker_policy$stop_numerator, plan$stop_numerator) &&
    identical(as.integer(value$worker_policy$max_geometric_steps),
              as.integer(plan$max_geometric_steps)) &&
    identical(value$worker_policy$sensitivity_steps,
              state$backend_source$sensitivity_steps) &&
    identical(value$worker_policy$epsilon, state$record$epsilon) &&
    identical(value$worker_policy$allocated_delta, state$record$delta) &&
    identical(value$worker_policy$encoded_lower,
              state$backend_source$encoded_lower) &&
    identical(value$worker_policy$encoded_upper,
              state$backend_source$encoded_upper) &&
    identical(value$worker_policy$transcript_hash, transcript) &&
    identical(value$worker_policy$garbler_commitment_context,
              input$garbler_commitment_context) &&
    identical(value$worker_policy$evaluator_commitment_context,
              input$evaluator_commitment_context) &&
    identical(value$worker_policy$garbler_seed_commitment,
              input$garbler_seed_commitment) &&
    identical(value$worker_policy$evaluator_seed_commitment,
              input$evaluator_seed_commitment) &&
    identical(value$worker_policy$implementation_delta_numerator,
              plan$implementation_delta_numerator) &&
    identical(value$worker_policy$implementation_delta_denominator,
              plan$implementation_delta_denominator)
  if (!isTRUE(valid)) {
    stop("The Count worker compiler returned a misbound contract.",
         call. = FALSE)
  }
  seed <- .dsvert_joint_dp_backend_private_seed_v2(policy, state)
  own_prepare <- prepares[[context$peer_name]]
  commitment <- .dsvert_joint_dp_backend_hash_raw_v2(c(
    .dsvert_joint_dp_backend_hex_raw_v2(
      own_prepare$commitment_context, "commitment context"), seed))
  if (!identical(commitment, own_prepare$seed_commitment_v2)) {
    rm(seed)
    stop("The local Count worker seed conflicts with its signed commitment.",
         call. = FALSE)
  }
  seed_b64 <- gsub("[\r\n]", "", jsonlite::base64_enc(seed))
  rm(seed)
  list(
    contract = value, plan = plan, private_seed = seed_b64,
    accuracy_95_abs = .dsvert_joint_dp_count_accuracy95(plan),
    implementation_delta = state$record$delta)
}

# Mint a one-shot ticket only after the uniformly split peer share is durable.
# The analyst receives authenticated ciphertext plus a typed ticket, never the
# source share or its plaintext commitment.
.dsvert_joint_dp_count_mint_transfer <- function(
    ss, session_id, policy, own_opening_token, peer_opening_token,
    .secret = NULL, .verifier = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count producer session.", call. = FALSE)
  }
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  source <- .dsvert_joint_dp_count_load_source_row(
    policy, state, .verifier)
  if (!identical(source$role, "source") ||
      !identical(source$source_peer, state$context$peer_name)) {
    stop("The local peer does not own the durable Count split.",
         call. = FALSE)
  }
  binding <- .dsvert_joint_dp_count_transfer_binding(state, policy)
  recipient <- source$recipient_peer
  peer_pk <- (ss$peer_transport_pks %||% list())[[recipient]]
  if (is.null(peer_pk)) {
    stop("The Count recipient is absent from the pinned transport map.",
         call. = FALSE)
  }
  request <- list(
    session_id = session_id, query_id = source$query_id,
    capsule_release_id = source$capsule_release_id,
    allocation_index = source$allocation_index,
    source_contract_hash = source$source_contract_hash,
    purpose_hash = binding$purpose_hash, recipient_name = recipient)
  replay <- .dsvert_typed_blob_operation_replay(
    ss, ".dsvert_joint_dp_count_mint_transfer", request)
  if (isTRUE(replay$hit)) return(replay$result)

  body <- .dsvert_joint_dp_count_transfer_body(
    state, binding, source$peer_share)
  plaintext <- charToRaw(.dsvert_dp_canonical_json(body))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
    recipient_pk = peer_pk))
  payload <- base64_to_base64url(sealed$sealed)
  transfer <- .dsvert_typed_blob_mint(
    ss, session_id, .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY,
    base64_to_base64url(peer_pk), payload, binding$context,
    producer = ".dsvert_joint_dp_count_mint_transfer")
  result <- list(
    peer_blob = payload, peer_transfer = transfer,
    query_id = source$query_id,
    source_contract_hash = source$source_contract_hash,
    result_contract_hash = binding$result_contract_hash,
    capability_available = FALSE)
  .dsvert_typed_blob_operation_commit(
    ss, ".dsvert_joint_dp_count_mint_transfer", request, result)
}

.dsvert_joint_dp_count_receive_transfer <- function(
    ss, session_id, policy, own_opening_token, peer_opening_token,
    .secret = NULL, .verifier = NULL, .phase_hook = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count recipient session.", call. = FALSE)
  }
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  peers <- sort(state$context$common$designated_noise_peers, method = "radix")
  source_peer <- peers[[1L]]
  recipient_peer <- peers[[2L]]
  if (!identical(state$context$peer_name, recipient_peer)) {
    stop("Only the designated Count recipient may consume the source share.",
         call. = FALSE)
  }
  binding <- .dsvert_joint_dp_count_transfer_binding(state, policy)

  # Do not retain the global ledger lock while waiting for typed transport or
  # asymmetric decryption.  A second transaction below resolves a race.
  existing <- local({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, state$secret, .verifier)
    .dsvert_joint_dp_count_source_load(
      handle$connection, state$record$query_id, state$secret)
  })
  if (!is.null(existing)) {
    expected <- .dsvert_joint_dp_count_source_record(
      state, "recipient", existing$local_share)
    if (!identical(existing, expected)) {
      stop("Conflicting replay of the received Count source share.",
           call. = FALSE)
    }
    return(list(
      version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
      state = "received_committed", stored = TRUE,
      query_id = existing$query_id, capability_available = FALSE))
  }

  encrypted <- .dsvert_typed_blob_consume(
    ss, .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY,
    binding$context, sender_name = source_peer, consume = FALSE)
  opened <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(encrypted),
    recipient_sk = .key_get("transport_sk", ss)))
  plaintext <- tryCatch(jsonlite::base64_dec(opened$data),
                        error = function(e) NULL)
  if (!is.raw(plaintext)) {
    stop("The encrypted joint-DP Count source share could not be opened.",
         call. = FALSE)
  }
  body <- .dsvert_joint_dp_count_decode_transfer(plaintext)
  expected_body <- .dsvert_joint_dp_count_transfer_body(
    state, binding, body$share)
  if (!identical(body, expected_body)) {
    stop("The joint-DP Count source transfer has the wrong context.",
         call. = FALSE)
  }
  record <- .dsvert_joint_dp_count_source_record(
    state, "recipient", body$share)
  local({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_transaction(handle$connection, {
      .dsvert_joint_dp_initialize_validate(
        handle$connection, policy, state$secret, .verifier)
      .dsvert_joint_dp_count_install_tables(handle$connection)
      raced <- .dsvert_joint_dp_count_source_load(
        handle$connection, state$record$query_id, state$secret)
      if (is.null(raced)) {
        .dsvert_joint_dp_count_source_insert(
          handle$connection, record, state$secret)
      } else if (!identical(raced, record)) {
        stop("Conflicting concurrent Count source-share commit.",
             call. = FALSE)
      }
    })
  })
  if (is.function(.phase_hook)) .phase_hook("after_count_receive_commit")
  consumed <- .dsvert_typed_blob_consume(
    ss, .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY,
    binding$context, sender_name = source_peer)
  if (!identical(consumed, encrypted)) {
    stop("The committed Count source ciphertext changed before consumption.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    state = "received_committed", stored = TRUE,
    query_id = record$query_id, capability_available = FALSE)
}

.dsvert_joint_dp_count_gc_state <- function(ss) {
  if (!is.environment(ss)) stop("Invalid joint-DP Count session.", call. = FALSE)
  if (!is.environment(ss$.joint_dp_count_gc)) {
    ss$.joint_dp_count_gc <- new.env(parent = emptyenv())
  }
  ss$.joint_dp_count_gc
}

.dsvert_joint_dp_count_validate_gc_adapter <- function(value, expected) {
  extras <- c("accuracy_95_abs", "implementation_delta")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), c(names(expected), extras)) &&
    identical(value[names(expected)], expected) &&
    is.character(value$accuracy_95_abs) &&
    length(value$accuracy_95_abs) == 1L &&
    grepl("^(0|[1-9][0-9]*)$", value$accuracy_95_abs) &&
    is.character(value$implementation_delta) &&
    length(value$implementation_delta) == 1L &&
    is.finite(suppressWarnings(as.numeric(value$implementation_delta))) &&
    as.numeric(value$implementation_delta) > 0
  if (!isTRUE(valid)) {
    stop("The joint-DP Count GC state is not fully bound.", call. = FALSE)
  }
  value
}

# Reduce the uniformly masked Ring128 source share modulo 2^127.  Because
# 2^127 divides 2^128, the two reduced shares still reconstruct the exact
# bounded Count in Ring127; neither share is revealed during this conversion.
.dsvert_joint_dp_count_ring127_share <- function(value) {
  encoded <- .exact_gc_decimal_residues_b64(
    .dsvert_joint_dp_count_ring128(value), 128L)
  raw_value <- jsonlite::base64_dec(encoded)
  raw_value[[16L]] <- as.raw(bitwAnd(as.integer(raw_value[[16L]]), 127L))
  result <- gsub("[\r\n]", "", jsonlite::base64_enc(raw_value))
  .exact_gc_validate_residue_records(
    result, 127L, 1L, "joint-DP Count Ring127 source share")
  rm(raw_value)
  result
}

# The exact circuit reconstructs the bounded Count, verifies its source bounds,
# combines both committed private seeds into one joint discrete-Laplace draw,
# and clamps once.  No noise value or pre-clamp statistic exists outside GC.
.dsvert_joint_dp_count_start_gc <- function(
    ss, session_id, operation_id, source_key, output_key,
    policy, own_opening_token, peer_opening_token,
    backend_prepares, backend_tokens,
    .secret = NULL, .verifier = NULL,
    binary = .findMpcBinary(), .compiler = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  source_key <- .exact_gc_validate_key(source_key)
  output_key <- .exact_gc_validate_key(output_key, output = TRUE)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count exact-GC session.", call. = FALSE)
  }
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  source_row <- .dsvert_joint_dp_count_load_source_row(
    policy, state, .verifier)
  if (!identical(source_row$role,
                 if (identical(source_row$source_peer,
                               state$context$peer_name)) {
                   "source"
                 } else "recipient")) {
    stop("The durable Count share has the wrong peer role.", call. = FALSE)
  }
  binding <- .dsvert_joint_dp_count_transfer_binding(state, policy)
  worker <- .dsvert_joint_dp_count_worker_contract(
    policy, state, backend_prepares, backend_tokens,
    .verifier = .verifier, .compiler = .compiler)
  requested <- list(
    version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
    session_id = session_id, operation_id = operation_id,
    source_key = source_key, output_key = output_key,
    query_id = state$record$query_id,
    capsule_release_id = state$source$capsule_release_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      state$record$allocation_index),
    source_contract_hash = state$source_hash,
    backend_source_contract_hash = state$backend_source_hash,
    result_contract_hash = binding$result_contract_hash,
    purpose = worker$contract$purpose,
    circuit_digest = worker$contract$circuit_digest,
    upper_bound = binding$result_contract$release_upper_bound)
  adapter_state <- .dsvert_joint_dp_count_gc_state(ss)
  previous <- adapter_state[[operation_id]]
  if (!is.null(previous)) {
    .dsvert_joint_dp_count_validate_gc_adapter(previous, requested)
  }
  if (!is.null(previous) && !is.null(.exact_gc_operation_state(
      ss, operation_id, required = FALSE))) {
    initialized <- .exact_gc_init_impl(
      ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
      source_key, output_key, "joint-dp-laplace-v2", 127L, 0L, 1L,
      worker$contract$purpose,
      joint_dp = worker$contract$worker_policy,
      private_seed = worker$private_seed,
      binary = binary)
    worker$private_seed <- NULL
    return(initialized)
  }
  encoded <- .dsvert_joint_dp_count_ring127_share(source_row$local_share)
  requested$accuracy_95_abs <- worker$accuracy_95_abs
  requested$implementation_delta <- .dsvert_joint_dp_decimal(
    worker$implementation_delta, "Count sampler implementation delta",
    minimum = 0, maximum = 1, open_minimum = TRUE)
  .dsvert_joint_dp_count_validate_gc_adapter(
    requested, requested[setdiff(names(requested), c(
      "accuracy_95_abs", "implementation_delta"))])
  .exact_gc_stage_share(
    ss, source_key, encoded, 127L, 1L,
    .DSVERT_JOINT_DP_COUNT_GC_PRODUCER,
    "joint-dp-laplace-v2", worker$contract$purpose, 0L,
    "joint-dp-ring-share-v2")
  rm(encoded)
  adapter_state[[operation_id]] <- requested
  initialized <- .exact_gc_init_impl(
    ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    source_key, output_key, "joint-dp-laplace-v2", 127L, 0L, 1L,
    worker$contract$purpose,
    joint_dp = worker$contract$worker_policy,
    private_seed = worker$private_seed,
    binary = binary)
  worker$private_seed <- NULL
  initialized
}

.dsvert_joint_dp_count_result_payload <- function(
    share, validity_share, query_id, capsule_release_id, allocation_index,
    source_contract_hash,
    result_contract_hash, accuracy_95_abs, implementation_delta) {
  .exact_gc_validate_residue_records(
    share, 127L, 1L, "joint-DP Count final share")
  validity <- .exact_gc_standard_b64_raw(
    validity_share, 1L, "joint-DP Count validity share")
  if (!as.integer(validity[[1L]]) %in% 0:1) {
    stop("A joint-DP Count validity share is non-canonical.", call. = FALSE)
  }
  value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_COUNT_RESULT_VERSION,
    query_id = .dsvert_joint_dp_count_hex(query_id, "result query id"),
    capsule_release_id = .dsvert_joint_dp_count_hex(
      capsule_release_id, "result capsule release id"),
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      allocation_index),
    source_contract_hash = .dsvert_joint_dp_count_hex(
      source_contract_hash, "result source-contract hash"),
    result_contract_hash = .dsvert_joint_dp_count_hex(
      result_contract_hash, "result-contract hash"),
    ring_bits = 127L, vector_len = 1L,
    postprocessing = "one-joint-noise-draw-and-one-clamp-inside-exact-gc",
    accuracy_95_abs = .dsvert_joint_dp_convolution_integer_text(
      accuracy_95_abs, FALSE, "Count accuracy radius"),
    accuracy_accounting =
      "one-draw-marginal-95-mechanism-noise-only",
    implementation_delta = .dsvert_joint_dp_decimal(
      as.numeric(implementation_delta), "Count implementation delta",
      minimum = 0, maximum = 1, open_minimum = TRUE),
    share = share, validity_share = validity_share))
  charToRaw(.dsvert_dp_canonical_json(value))
}

.dsvert_joint_dp_count_decode_result_payload <- function(value) {
  if (!is.raw(value)) {
    stop("A joint-DP Count result payload must be raw bytes.", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::fromJSON(
    rawToChar(value), simplifyVector = FALSE), error = function(e) NULL)
  canonical <- tryCatch(charToRaw(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded))), error = function(e) NULL)
  required <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "source_contract_hash", "result_contract_hash", "ring_bits",
    "vector_len", "postprocessing", "accuracy_95_abs",
    "accuracy_accounting", "implementation_delta", "share",
    "validity_share")
  valid <- is.list(decoded) && !is.null(names(decoded)) &&
    !anyNA(names(decoded)) && !anyDuplicated(names(decoded)) &&
    setequal(names(decoded), required) && identical(canonical, value) &&
    identical(decoded$version, .DSVERT_JOINT_DP_COUNT_RESULT_VERSION) &&
    identical(as.numeric(decoded$ring_bits), 127) &&
    identical(as.numeric(decoded$vector_len), 1) &&
    identical(decoded$postprocessing,
              "one-joint-noise-draw-and-one-clamp-inside-exact-gc") &&
    identical(decoded$accuracy_accounting,
              "one-draw-marginal-95-mechanism-noise-only") &&
    is.character(decoded$accuracy_95_abs) &&
    length(decoded$accuracy_95_abs) == 1L &&
    grepl("^(0|[1-9][0-9]*)$", decoded$accuracy_95_abs) &&
    is.character(decoded$implementation_delta) &&
    length(decoded$implementation_delta) == 1L &&
    is.finite(suppressWarnings(as.numeric(decoded$implementation_delta))) &&
    as.numeric(decoded$implementation_delta) > 0 &&
    as.numeric(decoded$implementation_delta) < 1
  if (!isTRUE(valid)) {
    stop("The joint-DP Count result payload is invalid.", call. = FALSE)
  }
  .dsvert_joint_dp_count_hex(decoded$query_id, "payload query id")
  .dsvert_joint_dp_count_hex(
    decoded$capsule_release_id, "payload capsule release id")
  .dsvert_joint_dp_count_allocation_text(decoded$allocation_index)
  .dsvert_joint_dp_count_hex(
    decoded$source_contract_hash, "payload source-contract hash")
  .dsvert_joint_dp_count_hex(
    decoded$result_contract_hash, "payload result-contract hash")
  decoded$share_raw <- .exact_gc_validate_residue_records(
    decoded$share, 127L, 1L, "joint-DP Count final share")
  decoded$validity_raw <- .exact_gc_standard_b64_raw(
    decoded$validity_share, 1L, "joint-DP Count validity share")
  if (!as.integer(decoded$validity_raw[[1L]]) %in% 0:1) {
    stop("The joint-DP Count validity share is non-canonical.", call. = FALSE)
  }
  decoded
}

.dsvert_joint_dp_count_add_ring127 <- function(left, right) {
  if (!is.raw(left) || !is.raw(right) ||
      length(left) != 16L || length(right) != 16L) {
    stop("Joint-DP Count release requires two Ring127 output shares.",
         call. = FALSE)
  }
  output <- raw(16L)
  carry <- 0L
  for (index in seq_len(16L)) {
    total <- as.integer(left[[index]]) + as.integer(right[[index]]) + carry
    output[[index]] <- as.raw(total %% 256L)
    carry <- total %/% 256L
  }
  output[[16L]] <- as.raw(bitwAnd(as.integer(output[[16L]]), 127L))
  output
}

.dsvert_joint_dp_count_delivery_state <- function(
    policy, own_delivery_token, peer_delivery_token,
    .secret = NULL, .verifier = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  tokens <- .dsvert_joint_dp_receipt_set(
    own_delivery_token, peer_delivery_token, policy,
    .DSVERT_JOINT_DP_DELIVERY_VERSION, "delivery_authorized", .verifier)
  own <- tokens[[context$peer_name]]
  peer <- tokens[[setdiff(names(tokens), context$peer_name)]]
  contract <- .dsvert_joint_dp_delivery_contract(
    policy, own, peer, .secret = .secret, .verifier = .verifier)

  durable <- local({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, .secret, .verifier)
    list(
      record = .dsvert_joint_dp_load(
        handle$connection, contract$query_id, .secret),
      output = .dsvert_joint_dp_output_load(
        handle$connection, contract$query_id, .secret))
  })
  record <- durable$record
  output <- durable$output
  if (is.null(record) || is.null(output) ||
      !identical(output$state, "delivery_authorized") ||
      !identical(output$result_contract_hash,
                 contract$result_contract_hash) ||
      !identical(output$result_set_hash, contract$result_set_hash) ||
      !identical(output$delivery_token, own)) {
    stop("The Count delivery is not bound to a durable local result.",
         call. = FALSE)
  }
  .dsvert_joint_dp_validate_output_record(
    output, record, policy, context, .verifier)
  state <- .dsvert_joint_dp_count_open_state(
    policy, output$own_opening_token, output$peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  binding <- .dsvert_joint_dp_count_transfer_binding(state, policy)
  if (!identical(binding$result_contract_hash,
                 contract$result_contract_hash)) {
    stop("The Count delivery result contract changed after exact GC.",
         call. = FALSE)
  }
  list(
    context = context, tokens = tokens, contract = contract,
    state = state, binding = binding, output = output)
}

.dsvert_joint_dp_count_final_transfer_context <- function(delivery) {
  context <- .dsvert_joint_dp_count_context(
    delivery$state$record$query_id,
    delivery$state$source$capsule_release_id,
    delivery$state$record$allocation_index,
    delivery$state$source_hash,
    .dsvert_joint_dp_hash(list(
      protocol = "dsvert-joint-dp-count-final-transfer-purpose-v1",
      result_contract_hash = delivery$contract$result_contract_hash,
      result_set_hash = delivery$contract$result_set_hash,
      delivery_commit_set_hash =
        delivery$contract$delivery_commit_set_hash)),
    ring_bits = 127L)
  .dsvert_dp_canonical_query_value(c(context, list(
      result_contract_hash = delivery$contract$result_contract_hash,
      result_set_hash = delivery$contract$result_set_hash,
      delivery_commit_set_hash =
        delivery$contract$delivery_commit_set_hash)))
}

.dsvert_joint_dp_count_mint_final_transfer <- function(
    ss, session_id, policy, own_delivery_token, peer_delivery_token,
    .secret = NULL, .verifier = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count final-transfer session.", call. = FALSE)
  }
  delivery <- .dsvert_joint_dp_count_delivery_state(
    policy, own_delivery_token, peer_delivery_token,
    .secret = .secret, .verifier = .verifier)
  peers <- sort(
    delivery$context$common$designated_noise_peers, method = "radix")
  sender <- delivery$context$peer_name
  recipient <- setdiff(peers, sender)
  if (length(recipient) != 1L) {
    stop("The Count final-share recipient is ambiguous.", call. = FALSE)
  }
  peer_pk <- (ss$peer_transport_pks %||% list())[[recipient]]
  if (is.null(peer_pk)) {
    stop("The Count final-share peer is absent from the pinned transport map.",
         call. = FALSE)
  }
  transfer_context <- .dsvert_joint_dp_count_final_transfer_context(delivery)
  request <- list(
    session_id = session_id, query_id = delivery$contract$query_id,
    result_contract_hash = delivery$contract$result_contract_hash,
    result_set_hash = delivery$contract$result_set_hash,
    delivery_commit_set_hash = delivery$contract$delivery_commit_set_hash,
    recipient_name = recipient)
  replay <- .dsvert_typed_blob_operation_replay(
    ss, .DSVERT_JOINT_DP_COUNT_FINAL_TRANSFER_PRODUCER, request)
  if (isTRUE(replay$hit)) return(replay$result)

  local_payload <- delivery$output$payload
  invisible(.dsvert_joint_dp_count_decode_result_payload(local_payload))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = gsub("[\r\n]", "", jsonlite::base64_enc(local_payload)),
    recipient_pk = peer_pk))
  ciphertext <- base64_to_base64url(sealed$sealed)
  transfer <- .dsvert_typed_blob_mint(
    ss, session_id, .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
    base64_to_base64url(peer_pk), ciphertext, transfer_context,
    producer = .DSVERT_JOINT_DP_COUNT_FINAL_TRANSFER_PRODUCER)
  result <- list(
    ciphertext = ciphertext, transfer = transfer,
    query_id = delivery$contract$query_id,
    result_contract_hash = delivery$contract$result_contract_hash,
    capability_available = TRUE, payload_delivery_available = FALSE)
  .dsvert_typed_blob_operation_commit(
    ss, .DSVERT_JOINT_DP_COUNT_FINAL_TRANSFER_PRODUCER, request, result)
}

.dsvert_joint_dp_count_existing_result <- function(
    policy, state, result_contract_hash, .verifier = NULL) {
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_initialize_validate(
    handle$connection, policy, state$secret, .verifier)
  existing <- .dsvert_joint_dp_output_load(
    handle$connection, state$record$query_id, state$secret)
  if (is.null(existing)) return(NULL)
  .dsvert_joint_dp_validate_output_record(
    existing, state$record, policy, state$context, .verifier)
  if (!identical(existing$result_contract_hash, result_contract_hash)) {
    stop("The persisted Count result uses a different result contract.",
         call. = FALSE)
  }
  existing$own_result_prepare
}

.dsvert_joint_dp_count_stage_final_share <- function(
    policy, state, value, .verifier = NULL) {
  payload <- value$payload
  value$payload <- NULL
  value <- .dsvert_dp_canonical_query_value(value)
  value$payload <- payload
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, state$secret, .verifier)
    .dsvert_joint_dp_count_install_tables(handle$connection)
    existing <- .dsvert_joint_dp_count_stage_load(
      handle$connection, state$record$query_id, state$secret)
    if (is.null(existing)) {
      .dsvert_joint_dp_count_stage_insert(
        handle$connection, value, state$secret)
      value
    } else {
      expected <- value
      expected$payload <- NULL
      existing_compare <- existing
      existing_compare$payload <- NULL
      if (!identical(existing_compare, expected)) {
        stop("Conflicting replay of the staged Count result share.",
             call. = FALSE)
      }
      existing
    }
  })
}

.dsvert_joint_dp_count_load_final_stage <- function(
    policy, state, .verifier = NULL) {
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_initialize_validate(
    handle$connection, policy, state$secret, .verifier)
  .dsvert_joint_dp_count_stage_load(
    handle$connection, state$record$query_id, state$secret)
}

# Consume only the post-clamp GC share.  A private authenticated staging row is
# committed before the existing schema-v2 result ledger, closing the crash
# window between one-shot GC consumption and durable result preparation.
.dsvert_joint_dp_count_prepare_result <- function(
    ss, session_id, operation_id,
    policy, own_opening_token, peer_opening_token,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count result session.", call. = FALSE)
  }
  state <- .dsvert_joint_dp_count_open_state(
    policy, own_opening_token, peer_opening_token,
    .secret = .secret, .verifier = .verifier)
  binding <- .dsvert_joint_dp_count_transfer_binding(state, policy)
  existing <- .dsvert_joint_dp_count_existing_result(
    policy, state, binding$result_contract_hash, .verifier)
  if (!is.null(existing)) return(existing)

  openings <- state$tokens
  opening_set_hash <- .dsvert_joint_dp_hash(openings)
  staged <- .dsvert_joint_dp_count_load_final_stage(
    policy, state, .verifier)
  if (is.null(staged)) {
    adapter <- if (is.environment(ss$.joint_dp_count_gc)) {
      ss$.joint_dp_count_gc[[operation_id]]
    } else NULL
    adapter_purpose <- if (is.list(adapter)) adapter$purpose else NULL
    adapter_digest <- if (is.list(adapter)) adapter$circuit_digest else NULL
    if (!is.character(adapter_purpose) || length(adapter_purpose) != 1L ||
        !is.character(adapter_digest) || length(adapter_digest) != 1L ||
        !grepl("^[0-9a-f]{64}$", adapter_digest) ||
        !identical(adapter_purpose,
                   paste0("joint-dp-laplace-v2/", adapter_digest))) {
      stop("The Count exact-GC worker attestation is unavailable.",
           call. = FALSE)
    }
    expected_adapter <- list(
      version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
      session_id = session_id, operation_id = operation_id,
      source_key = if (is.list(adapter)) adapter$source_key else NULL,
      output_key = if (is.list(adapter)) adapter$output_key else NULL,
      query_id = state$record$query_id,
      capsule_release_id = state$source$capsule_release_id,
      allocation_index = .dsvert_joint_dp_count_allocation_text(
        state$record$allocation_index),
      source_contract_hash = state$source_hash,
      backend_source_contract_hash = state$backend_source_hash,
      result_contract_hash = binding$result_contract_hash,
      purpose = adapter_purpose, circuit_digest = adapter_digest,
      upper_bound = binding$result_contract$release_upper_bound)
    adapter <- .dsvert_joint_dp_count_validate_gc_adapter(
      adapter, expected_adapter)
    output <- .exact_gc_consume_output(
      ss, adapter$output_key, operation_id, "joint-dp-ring-share-v2",
      "joint-dp-laplace-v2", adapter$purpose, 127L, 0L, 1L,
      .DSVERT_JOINT_DP_COUNT_GC_PRODUCER, consume = FALSE)
    payload <- .dsvert_joint_dp_count_result_payload(
      output$share, output$validity_share, state$record$query_id,
      state$source$capsule_release_id,
      state$record$allocation_index, state$source_hash,
      binding$result_contract_hash, adapter$accuracy_95_abs,
      adapter$implementation_delta)
    stage <- list(
      version = .DSVERT_JOINT_DP_COUNT_STAGE_ROW_VERSION,
      query_id = state$record$query_id,
      capsule_release_id = state$source$capsule_release_id,
      allocation_index = .dsvert_joint_dp_count_allocation_text(
        state$record$allocation_index),
      opening_set_hash = opening_set_hash,
      result_contract_hash = binding$result_contract_hash,
      operation_id = operation_id, output_key = adapter$output_key,
      payload_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(payload)),
      payload = payload)
    staged <- .dsvert_joint_dp_count_stage_final_share(
      policy, state, stage, .verifier)
    if (is.function(.phase_hook)) .phase_hook("after_count_final_stage_commit")
    consumed <- .exact_gc_consume_output(
      ss, adapter$output_key, operation_id, "joint-dp-ring-share-v2",
      "joint-dp-laplace-v2", adapter$purpose, 127L, 0L, 1L,
      .DSVERT_JOINT_DP_COUNT_GC_PRODUCER)
    if (!identical(consumed, output)) {
      stop("The committed Count GC output changed before consumption.",
           call. = FALSE)
    }
  }
  expected_stage <- list(
    query_id = state$record$query_id,
    capsule_release_id = state$source$capsule_release_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      state$record$allocation_index),
    opening_set_hash = opening_set_hash,
    result_contract_hash = binding$result_contract_hash)
  if (!identical(staged[names(expected_stage)], expected_stage) ||
      !identical(staged$result_contract_hash,
                 binding$result_contract_hash)) {
    stop("The staged Count result has the wrong opening context.",
         call. = FALSE)
  }
  .dsvert_joint_dp_result_prepare(
    policy, own_opening_token, peer_opening_token,
    staged$payload, binding$result_contract_hash,
    .secret = state$secret, .signer = .signer,
    .verifier = .verifier, .phase_hook = .phase_hook)
}

.dsvert_joint_dp_count_release_existing <- function(
    policy, delivery, .verifier = NULL) {
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_initialize_validate(
    handle$connection, policy, delivery$state$secret, .verifier)
  value <- .dsvert_joint_dp_count_release_load(
    handle$connection, delivery$contract$query_id, delivery$state$secret)
  if (is.null(value)) return(NULL)
  expected <- list(
    consortium_id = delivery$context$consortium_id,
    peer_name = delivery$context$peer_name,
    capsule_id = delivery$contract$capsule_id,
    query_id = delivery$contract$query_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      delivery$contract$allocation_index),
    capsule_release_id = delivery$state$source$capsule_release_id,
    source_contract_hash = delivery$state$source_hash,
    result_contract_hash = delivery$contract$result_contract_hash,
    result_set_hash = delivery$contract$result_set_hash,
    delivery_commit_set_hash = delivery$contract$delivery_commit_set_hash)
  if (!identical(value[names(expected)], expected)) {
    stop("The durable Count release conflicts with its authorization.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_count_release <- function(
    ss, session_id, policy, own_delivery_token, peer_delivery_token,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  delivery <- .dsvert_joint_dp_count_delivery_state(
    policy, own_delivery_token, peer_delivery_token,
    .secret = .secret, .verifier = .verifier)
  peers <- sort(
    delivery$context$common$designated_noise_peers, method = "radix")
  recipient <- delivery$context$peer_name
  sender <- setdiff(peers, recipient)
  if (length(sender) != 1L) {
    stop("The Count final-share sender is ambiguous.", call. = FALSE)
  }
  existing <- .dsvert_joint_dp_count_release_existing(
    policy, delivery, .verifier)
  if (!is.null(existing)) {
    return(.dsvert_dp_canonical_json(existing))
  }
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid joint-DP Count release session.", call. = FALSE)
  }

  transfer_context <- .dsvert_joint_dp_count_final_transfer_context(delivery)
  encrypted <- .dsvert_typed_blob_consume(
    ss, .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
    transfer_context, sender_name = sender, consume = FALSE)
  opened <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(encrypted),
    recipient_sk = .key_get("transport_sk", ss)))
  peer_payload <- tryCatch(
    jsonlite::base64_dec(opened$data), error = function(e) NULL)
  if (!is.raw(peer_payload)) {
    stop("The encrypted Count final share could not be opened.",
         call. = FALSE)
  }
  own <- .dsvert_joint_dp_count_decode_result_payload(
    delivery$output$payload)
  peer <- .dsvert_joint_dp_count_decode_result_payload(peer_payload)
  fields <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "source_contract_hash", "result_contract_hash", "ring_bits",
    "vector_len", "postprocessing", "accuracy_95_abs",
    "accuracy_accounting", "implementation_delta")
  if (!identical(own[fields], peer[fields]) ||
      !identical(own$query_id, delivery$contract$query_id) ||
      !identical(own$capsule_release_id,
                 delivery$state$source$capsule_release_id) ||
      !identical(own$source_contract_hash, delivery$state$source_hash) ||
      !identical(own$result_contract_hash,
                 delivery$contract$result_contract_hash)) {
    stop("The two Count output shares do not match the authorized result.",
         call. = FALSE)
  }
  valid_source <- bitwXor(
    as.integer(own$validity_raw[[1L]]),
    as.integer(peer$validity_raw[[1L]]))
  if (!identical(valid_source, 1L)) {
    stop("The Count exact-GC source-bound certificate is invalid.",
         call. = FALSE)
  }
  residue <- .dsvert_joint_dp_count_add_ring127(
    own$share_raw, peer$share_raw)
  exact <- openssl::bignum(rev(residue))
  upper_text <- delivery$binding$result_contract$release_upper_bound
  upper <- tryCatch(openssl::bignum(upper_text), error = function(e) NULL)
  if (is.null(upper) || exact > upper ||
      upper > openssl::bignum(as.character(.dsvert_dp_exact_integer_limit))) {
    stop("The Count exact-GC output violates its signed clamp bounds.",
         call. = FALSE)
  }
  value_text <- as.character(exact)
  unsigned <- list(
    version = .DSVERT_JOINT_DP_COUNT_RELEASE_VERSION,
    phase = "count_released",
    consortium_id = delivery$context$consortium_id,
    peer_name = delivery$context$peer_name,
    peer_identity_pk = unname(
      delivery$context$pins[[delivery$context$peer_name]]),
    capsule_id = delivery$contract$capsule_id,
    query_id = delivery$contract$query_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      delivery$contract$allocation_index),
    capsule_release_id = delivery$state$source$capsule_release_id,
    source_contract_hash = delivery$state$source_hash,
    result_contract_hash = delivery$contract$result_contract_hash,
    result_set_hash = delivery$contract$result_set_hash,
    delivery_commit_set_hash = delivery$contract$delivery_commit_set_hash,
    value = value_text, lower_bound = "0", upper_bound = upper_text,
    mechanism = "discrete-laplace-geometric-tv-v2",
    sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
    epsilon = delivery$state$record$epsilon,
    delta = delivery$state$record$delta,
    accuracy_95_abs = own$accuracy_95_abs,
    accuracy_accounting = own$accuracy_accounting,
    implementation_delta = own$implementation_delta,
    backend = "exact-gc-joint-dp-laplace-ring127-v2",
    postprocessing =
      "one-joint-noise-draw-and-one-clamp-inside-exact-gc",
    replay_contract = "durable-byte-identical-query-bound-v1",
    intermediate_values_exposed = FALSE,
    payload_delivery_available = TRUE,
    capability_available = TRUE)
  release <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
  release <- .dsvert_dp_canonical_query_value(release)

  committed <- local({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_transaction(handle$connection, {
      .dsvert_joint_dp_initialize_validate(
        handle$connection, policy, delivery$state$secret, .verifier)
      .dsvert_joint_dp_count_install_tables(handle$connection)
      raced <- .dsvert_joint_dp_count_release_load(
        handle$connection, delivery$contract$query_id,
        delivery$state$secret)
      if (is.null(raced)) {
        .dsvert_joint_dp_count_release_insert(
          handle$connection, release, delivery$state$secret)
        release
      } else {
        if (!identical(raced, release)) {
          stop("Conflicting concurrent Count final release.", call. = FALSE)
        }
        raced
      }
    })
  })
  rm(residue, exact, own, peer, peer_payload, valid_source)
  if (is.function(.phase_hook)) .phase_hook("after_count_release_commit")
  consumed <- .dsvert_typed_blob_consume(
    ss, .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
    transfer_context, sender_name = sender, required = FALSE)
  if (!is.null(consumed) && !identical(consumed, encrypted)) {
    stop("The committed Count final ciphertext changed before consumption.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_json(committed)
}

.dsvert_joint_dp_count_verify_release_signature <- function(
    release, context, .verifier = NULL) {
  public_key <- unname(context$pins[[release$peer_name]])
  valid <- if (is.null(.verifier)) {
    .dsvert_relay_verify_message(
      .dsvert_joint_dp_receipt_message(release),
      public_key, release$signature)
  } else {
    if (!is.function(.verifier)) {
      stop("Invalid Count replay verifier.", call. = FALSE)
    }
    .verifier(
      .dsvert_joint_dp_receipt_message(release),
      public_key, release$signature, release$peer_name)
  }
  if (!isTRUE(valid)) {
    stop("The durable Count release signature is invalid.", call. = FALSE)
  }
  invisible(release)
}

# Resolve a completed release directly from the authenticated durable ledger.
# Capsule identity depends only on the custodian-owned policy/dataset manifest,
# so this lookup does not inspect protected rows, draw noise, allocate another
# index, or enter an exact-GC session.  A missing row has one fixed response.
.dsvert_joint_dp_count_replay <- function(
    policy, data_name, .secret = NULL, .verifier = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  peers <- sort(
    context$common$designated_noise_peers, method = "radix")
  if (!context$peer_name %in% peers) {
    stop("Only a designated pinned Count peer may replay.", call. = FALSE)
  }
  contracts <- .dsvert_joint_dp_count_contracts(
    policy, .dsvert_joint_dp_count_dataset_public(policy, data_name))
  query_id <- contracts$capsule_identity$capsule_id

  durable <- local({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, .secret, .verifier)
    .dsvert_joint_dp_count_install_tables(handle$connection)
    release <- .dsvert_joint_dp_count_release_load(
      handle$connection, query_id, .secret)
    if (is.null(release)) return(list(release = NULL))
    list(
      release = release,
      record = .dsvert_joint_dp_load(
        handle$connection, query_id, .secret),
      output = .dsvert_joint_dp_output_load(
        handle$connection, query_id, .secret),
      source = .dsvert_joint_dp_count_source_load(
        handle$connection, query_id, .secret))
  })
  if (is.null(durable$release)) {
    return(.dsvert_dp_canonical_query_value(list(
      version = .DSVERT_JOINT_DP_COUNT_REPLAY_VERSION,
      state = "not_materialized", query_id = query_id,
      release_json = "", intermediate_values_exposed = FALSE,
      capability_available = TRUE,
      payload_delivery_available = TRUE)))
  }

  record <- durable$record
  output <- durable$output
  source <- durable$source
  release <- durable$release
  if (is.null(record) || is.null(output) || is.null(source) ||
      !identical(output$state, "delivery_authorized")) {
    stop("The durable Count release lacks its authorized transcript.",
         call. = FALSE)
  }
  .dsvert_joint_dp_validate_output_record(
    output, record, policy, context, .verifier)
  delivery <- output$delivery_token
  expected <- list(
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    peer_identity_pk = unname(context$pins[[context$peer_name]]),
    capsule_id = query_id,
    query_id = query_id,
    allocation_index = .dsvert_joint_dp_count_allocation_text(
      record$allocation_index),
    capsule_release_id = query_id,
    source_contract_hash = source$source_contract_hash,
    result_contract_hash = output$result_contract_hash,
    result_set_hash = output$result_set_hash,
    delivery_commit_set_hash = delivery$delivery_commit_set_hash,
    upper_bound = format(
      as.numeric(policy$unit_capacity), scientific = FALSE, trim = TRUE),
    epsilon = record$epsilon,
    delta = record$delta,
    mechanism = "discrete-laplace-geometric-tv-v2",
    sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
    backend = "exact-gc-joint-dp-laplace-ring127-v2",
    postprocessing =
      "one-joint-noise-draw-and-one-clamp-inside-exact-gc",
    replay_contract = "durable-byte-identical-query-bound-v1",
    intermediate_values_exposed = FALSE,
    payload_delivery_available = TRUE,
    capability_available = TRUE)
  if (!identical(release[names(expected)], expected) ||
      !identical(delivery$result_contract_hash,
                 release$result_contract_hash) ||
      !identical(delivery$result_set_hash, release$result_set_hash)) {
    stop("The durable Count replay conflicts with its authorization.",
         call. = FALSE)
  }
  .dsvert_joint_dp_count_verify_release_signature(
    release, context, .verifier)
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_COUNT_REPLAY_VERSION,
    state = "released", query_id = query_id,
    release_json = .dsvert_dp_canonical_json(release),
    intermediate_values_exposed = FALSE,
    capability_available = TRUE,
    payload_delivery_available = TRUE))
}

.dsvert_joint_dp_count_dsi_pair <- function(
    policy, first_json, second_json, version, phase, .verifier = NULL) {
  first <- .dsvert_joint_dp_dsi_receipt(first_json, "first Count token")
  second <- .dsvert_joint_dp_dsi_receipt(second_json, "second Count token")
  values <- .dsvert_joint_dp_receipt_set(
    first, second, policy, version, phase, .verifier)
  context <- .dsvert_joint_dp_policy_context(policy)
  list(
    own = values[[context$peer_name]],
    peer = values[[setdiff(names(values), context$peer_name)]])
}

.dsvert_joint_dp_count_public <- function(phase, code) {
  tryCatch(
    force(code), interrupt = function(e) stop(e),
    error = function(e) stop(
      "Joint-DP Count ", phase, " failed closed.", call. = FALSE))
}

#' Replay a completed purpose-bound joint-DP Count (AGGREGATE)
#' @param data_name Protected data-frame name from the policy manifest.
#' @return The durable signed release, or a fixed not-materialized response.
#' @keywords internal
dsvertJointDPCountReplayDS <- function(data_name) {
  .dsvert_joint_dp_count_public("replay", {
    .dsvert_joint_dp_count_replay(.dsvert_dp_policy(), data_name)
  })
}

#' Mint a purpose-bound joint-DP Count proposal (AGGREGATE)
#' @param data_name Protected data-frame name.
#' @return An authenticated proposal token; no statistic is returned.
#' @keywords internal
dsvertJointDPCountProposalDS <- function(data_name) {
  data_envir <- parent.frame()
  .dsvert_joint_dp_count_public("proposal", {
    policy <- .dsvert_dp_policy()
    minted <- .dsvert_joint_dp_count_mint_proposal(
      policy, data_name, data_envir)
    list(
      version = .DSVERT_JOINT_DP_COUNT_ADAPTER_VERSION,
      proposal_token = minted$proposal_token,
      query_id = minted$query_id,
      capability_available = TRUE,
      payload_delivery_available = FALSE)
  })
}

#' Commit the local private Count sampler seed (AGGREGATE)
#' @param first_opening_json,second_opening_json Cross-signed opening tokens.
#' @return A signed public commitment receipt. No seed is returned.
#' @keywords internal
dsvertJointDPCountBackendPrepareDS <- function(
    first_opening_json, second_opening_json) {
  .dsvert_joint_dp_count_public("backend preparation", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_opening_json, second_opening_json,
      .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized")
    value <- .dsvert_joint_dp_count_backend_prepare(
      policy, pair$own, pair$peer)
    list(
      version = .DSVERT_JOINT_DP_COUNT_BACKEND_PREPARE_RESPONSE,
      receipt_json = .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)),
      query_id = value$query_id,
      capability_available = TRUE,
      payload_delivery_available = FALSE)
  })
}

#' Cross-authorize the two public Count sampler commitments (AGGREGATE)
#' @param first_prepare_json,second_prepare_json Signed backend preparations.
#' @return A signed public cross-authorization receipt. No seed is returned.
#' @keywords internal
dsvertJointDPCountBackendTokenDS <- function(
    first_prepare_json, second_prepare_json) {
  .dsvert_joint_dp_count_public("backend authorization", {
    policy <- .dsvert_dp_policy()
    value <- .dsvert_joint_dp_count_backend_token(
      policy, first_prepare_json, second_prepare_json)
    list(
      version = .DSVERT_JOINT_DP_COUNT_BACKEND_TOKEN_RESPONSE,
      receipt_json = .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)),
      query_id = value$query_id,
      capability_available = TRUE,
      payload_delivery_available = FALSE)
  })
}

#' Commit and encrypt the Count source split (AGGREGATE)
#' @param session_id Pinned exact-GC session.
#' @param data_name Protected data-frame name.
#' @param first_opening_json,second_opening_json Cross-signed opening tokens.
#' @return One opaque ciphertext and producer-minted transfer ticket.
#' @keywords internal
dsvertJointDPCountSourceDS <- function(
    session_id, data_name, first_opening_json, second_opening_json) {
  data_envir <- parent.frame()
  .dsvert_joint_dp_count_public("source", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_opening_json, second_opening_json,
      .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized")
    .dsvert_joint_dp_count_commit_split(
      policy, pair$own, pair$peer, data_name, data_envir)
    value <- .dsvert_joint_dp_count_mint_transfer(
      .S(session_id), session_id, policy, pair$own, pair$peer)
    list(
      ciphertext = value$peer_blob, transfer = value$peer_transfer,
      query_id = value$query_id,
      source_contract_hash = value$source_contract_hash,
      result_contract_hash = value$result_contract_hash,
      capability_available = TRUE,
      payload_delivery_available = FALSE)
  })
}

#' Start the purpose-bound Count exact-GC finalizer (AGGREGATE)
#' @param session_id,operation_id,source_key,output_key Exact-GC identifiers.
#' @param first_opening_json,second_opening_json Cross-signed opening tokens.
#' @param first_backend_prepare_json,second_backend_prepare_json Signed public
#'   backend seed-commitment preparations.
#' @param first_backend_token_json,second_backend_token_json Signed bilateral
#'   authorizations for those commitments.
#' @return Redacted exact-GC transport state.
#' @keywords internal
dsvertJointDPCountStartDS <- function(
    session_id, operation_id, source_key, output_key,
    first_opening_json, second_opening_json,
    first_backend_prepare_json, second_backend_prepare_json,
    first_backend_token_json, second_backend_token_json) {
  .dsvert_joint_dp_count_public("GC start", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_opening_json, second_opening_json,
      .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized")
    prepares <- .dsvert_joint_dp_count_backend_set(
      policy, first_backend_prepare_json, second_backend_prepare_json,
      .DSVERT_JOINT_DP_BACKEND_PREPARE_V2, "backend_prepared",
      what = "backend prepare")
    tokens <- .dsvert_joint_dp_count_backend_set(
      policy, first_backend_token_json, second_backend_token_json,
      .DSVERT_JOINT_DP_BACKEND_TOKEN_V2, "backend_preflight_only",
      what = "backend token")
    context <- .dsvert_joint_dp_policy_context(policy)
    peers <- sort(context$common$designated_noise_peers, method = "radix")
    ss <- .S(session_id)
    if (identical(context$peer_name, peers[[2L]])) {
      .dsvert_joint_dp_count_receive_transfer(
        ss, session_id, policy, pair$own, pair$peer)
    }
    .dsvert_joint_dp_count_start_gc(
      ss, session_id, operation_id, source_key, output_key,
      policy, pair$own, pair$peer, prepares, tokens)
  })
}

#' Persist one post-clamp Count output share (AGGREGATE)
#' @param session_id,operation_id Exact-GC identifiers.
#' @param first_opening_json,second_opening_json Cross-signed opening tokens.
#' @return A signed payload commitment; no share is returned.
#' @keywords internal
dsvertJointDPCountResultDS <- function(
    session_id, operation_id, first_opening_json, second_opening_json) {
  .dsvert_joint_dp_count_public("result preparation", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_opening_json, second_opening_json,
      .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized")
    .dsvert_joint_dp_dsi_receipt_json(
      .dsvert_joint_dp_count_prepare_result(
        .S(session_id), session_id, operation_id,
        policy, pair$own, pair$peer),
      "Count result receipt")
  })
}

#' Encrypt the authorized post-clamp share to the pinned deliverer (AGGREGATE)
#' @param session_id Pinned exact-GC session.
#' @param first_delivery_json,second_delivery_json Delivery authorizations.
#' @return Opaque ciphertext and producer-minted transfer ticket.
#' @keywords internal
dsvertJointDPCountFinalShareDS <- function(
    session_id, first_delivery_json, second_delivery_json) {
  .dsvert_joint_dp_count_public("final-share transfer", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_delivery_json, second_delivery_json,
      .DSVERT_JOINT_DP_DELIVERY_VERSION, "delivery_authorized")
    .dsvert_joint_dp_count_mint_final_transfer(
      .S(session_id), session_id, policy, pair$own, pair$peer)
  })
}

#' Release only the durable authorized joint-DP Count (AGGREGATE)
#' @param session_id Pinned exact-GC session.
#' @param first_delivery_json,second_delivery_json Delivery authorizations.
#' @return A byte-identical signed Count release. No share is returned.
#' @keywords internal
dsvertJointDPCountReleaseDS <- function(
    session_id, first_delivery_json, second_delivery_json) {
  .dsvert_joint_dp_count_public("release", {
    policy <- .dsvert_dp_policy()
    pair <- .dsvert_joint_dp_count_dsi_pair(
      policy, first_delivery_json, second_delivery_json,
      .DSVERT_JOINT_DP_DELIVERY_VERSION, "delivery_authorized")
    .dsvert_joint_dp_count_release(
      .S(session_id), session_id, policy, pair$own, pair$peer)
  })
}
