# Closed server surface for one stateless sticky synopsis.  Every evidence
# object crosses DSI as framed canonical JSON; dependencies stay server-owned.

.DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES <- 32L * 1024L^2
.DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES <- 2L * 1024L^2
.DSVERT_DP_SYNOPSIS_REMOTE_TICKET_MAX_BYTES <- 64L * 1024L
.DSVERT_DP_SYNOPSIS_LOCAL_COMPILE_ENVELOPE_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-compile-envelope-v1"
.DSVERT_DP_SYNOPSIS_REMOTE_EXACT_START_RESPONSE_VERSION <-
  "dsvert-stateless-catalog-synopsis-exact-gc-start-response-v1"

.dsvert_dp_synopsis_remote_public_v1 <- function(code) {
  tryCatch(force(code), error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_synopsis_remote_json_v1 <- function(value, what, maximum_bytes) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  parsed <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(parsed)), error = function(error) NULL)
  if (is.null(parsed) || is.null(canonical) || !identical(canonical, value)) {
    stop("Invalid or non-canonical synopsis ", what, ".", call. = FALSE)
  }
  parsed
}

.dsvert_dp_synopsis_remote_decode_v1 <- function(
    value, what, maximum_bytes =
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES) {
  json <- .dsvert_dp_synopsis_remote_text_v1(value, what, maximum_bytes)
  .dsvert_dp_synopsis_remote_json_v1(json, what, maximum_bytes)
}

.dsvert_dp_synopsis_remote_text_v1 <- function(
    value, what, maximum_bytes =
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES) {
  json <- .dsvert_dsi_text_decode(value, what, maximum_bytes)
  .dsvert_dp_synopsis_remote_json_v1(json, what, maximum_bytes)
  json
}

.dsvert_dp_synopsis_remote_encode_v1 <- function(
    value, what, maximum_bytes =
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES) {
  if (is.character(value) && length(value) == 1L && !is.na(value)) {
    .dsvert_dp_synopsis_remote_json_v1(value, what, maximum_bytes)
    return(value)
  }
  encoded <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(value))
  if (nchar(encoded, type = "bytes") > maximum_bytes) {
    stop("The synopsis ", what, " exceeds its protocol byte bound.",
         call. = FALSE)
  }
  encoded
}

.dsvert_dp_synopsis_remote_exact_start_response_v1 <- function(ss, receipt) {
  is_exact <- is.list(receipt) && identical(
    receipt$version, .DSVERT_DP_SYNOPSIS_EXECUTION_EXACT_START_VERSION) &&
    identical(receipt$phase, "synopsis_exact_gc_initialized")
  if (!isTRUE(is_exact)) return(receipt)
  state <- .exact_gc_operation_state(ss, receipt$operation_id,
                                     required = FALSE)
  if (is.null(state)) {
    stop("The synopsis exact-GC START operation is unavailable.",
         call. = FALSE)
  }
  initialization <- .exact_gc_public_state(state)
  valid <- is.list(initialization) &&
    identical(initialization$operation,
              .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION) &&
    identical(initialization$purpose, receipt$purpose) &&
    identical(as.numeric(initialization$ring_bits), 128) &&
    identical(as.numeric(initialization$frac_bits), 0) &&
    identical(as.numeric(initialization$vector_len),
              as.numeric(receipt$coordinate_count)) &&
    initialization$state %in% c("running", "complete") &&
    identical(isTRUE(initialization$stored),
              identical(initialization$state, "complete"))
  if (!isTRUE(valid)) {
    stop("The synopsis exact-GC START initialization is inconsistent.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_REMOTE_EXACT_START_RESPONSE_VERSION,
    receipt = receipt, initialization = initialization)
}

.dsvert_dp_synopsis_remote_compilation_v1 <- function(value) {
  compilation <- .dsvert_dp_synopsis_remote_decode_v1(
    value, "compilation", .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
  fields <- c("version", "artifact", "receipts", "receipt_set_sha256")
  if (!is.list(compilation) || is.null(names(compilation)) ||
      anyNA(names(compilation)) || anyDuplicated(names(compilation)) ||
      !setequal(names(compilation), fields) || !identical(
        compilation$version,
        .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_VERSION) ||
      !is.list(compilation$artifact) || !is.list(compilation$receipts) ||
      !length(compilation$receipts)) {
    stop("Invalid synopsis compilation.", call. = FALSE)
  }
  declared <- .dsvert_dp_synopsis_hex_v1(
    compilation$receipt_set_sha256, "compile receipt-set hash")
  if (!identical(
        declared,
        .dsvert_dp_synopsis_compile_receipt_set_hash_v1(
          compilation$receipts))) {
    stop("Invalid synopsis compilation receipt-set hash.", call. = FALSE)
  }
  compilation
}

.dsvert_dp_synopsis_remote_manifest_v1 <- function(manifest_sha256) {
  .dsvert_dp_synopsis_remote_public_v1({
    secret <- .dsvert_dp_secret()
    policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, secret)
    manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
      manifest_sha256, policy, secret,
      .dsvert_dp_synopsis_manifest_cache_get_readonly_v1)
    list(
      policy = policy, secret = secret,
      manifest = .dsvert_dp_capsule_source_manifest(manifest_json))
  })
}

.dsvert_dp_synopsis_effective_cross_v1 <- function(manifest) {
  workload <- if (is.list(manifest)) manifest$workload else NULL
  vertical <- if (is.list(workload)) workload$vertical_crosses else NULL
  zero_coordinates <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value == 0
  }
  reserved_only <- function(value) {
    if (is.null(value)) return(FALSE)
    if (!is.list(value)) return(TRUE)
    any(vapply(value, function(entry) {
      if (!is.list(entry) || !identical(
            entry$implementation_state, "reserved_not_materialized")) {
        return(TRUE)
      }
      included <- entry$included_coordinate_count
      !is.null(included) && !zero_coordinates(included)
    }, logical(1L)))
  }

  if (!is.null(vertical)) {
    if (!is.list(vertical)) return(TRUE)
    state <- vertical$implementation_state
    known_unmaterialized <- is.character(state) && length(state) == 1L &&
      !is.na(state) && state %in% c(
        "not_required_by_signed_schema", "reserved_not_materialized")
    if (!is.null(state) && !known_unmaterialized) {
      return(TRUE)
    }
    included <- vertical$included_coordinate_count
    if (!is.null(included) && !zero_coordinates(included)) return(TRUE)
    configured <- vertical$configured_crosses
    if (!is.null(configured) &&
        (!is.list(configured) || length(configured) > 0L)) return(TRUE)
    if (reserved_only(vertical$cross_owner_sets) ||
        reserved_only(vertical$categorical_pair_sets)) return(TRUE)
  }

  families <- if (is.list(workload)) workload$families else NULL
  if (!is.null(families) && !is.list(families)) return(TRUE)
  categorical <- if (is.list(families)) families$categorical_pairs else NULL
  if (!is.null(categorical) && !is.list(categorical)) return(TRUE)
  pair_cross <- if (is.list(categorical)) {
    categorical$cross_artifacts
  } else NULL
  if (!is.null(pair_cross) &&
      (!is.list(pair_cross) || length(pair_cross) > 0L)) return(TRUE)
  gaussian_family <- if (is.list(families)) {
    families$gaussian_models
  } else NULL
  if (!is.null(gaussian_family) && !is.list(gaussian_family)) return(TRUE)
  gaussian <- if (is.list(gaussian_family)) gaussian_family$artifacts else NULL
  if (!is.null(gaussian) && !is.list(gaussian)) return(TRUE)
  if (is.list(gaussian) && any(vapply(gaussian, function(artifact) {
        !is.list(artifact) || !artifact$version %in% c(
          "bounded-normalized-gaussian-sufficient-statistics-v1",
          "bounded-normalized-random-intercept-moments-v1",
          "bounded-normalized-random-intercept-fixed-sufficient-statistics-v2",
          "bounded-normalized-random-intercept-fixed-sufficient-statistics-v3",
          "bounded-binary-random-intercept-likelihood-grid-v1",
          "bounded-negative-binomial-likelihood-grid-v1")
      }, logical(1L)))) return(TRUE)
  FALSE
}

.dsvert_dp_synopsis_remote_reject_cross_v1 <- function(manifest) {
  if (.dsvert_dp_synopsis_effective_cross_v1(manifest) &&
      !.dsvert_dp_synopsis_supported_categorical_cross_v1(manifest)) {
    stop("Cross-owner synopsis catalogs are not supported by this surface.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_synopsis_supported_categorical_cross_v1 <- function(manifest) {
  workload <- if (is.list(manifest)) manifest$workload else NULL
  families <- if (is.list(workload)) workload$families else NULL
  categorical <- if (is.list(families)) {
    families$categorical_pairs
  } else NULL
  artifacts <- if (is.list(categorical)) {
    categorical$cross_artifacts
  } else NULL
  vertical <- if (is.list(workload)) workload$vertical_crosses else NULL
  scope <- if (is.list(workload)) workload$primitive_scope else NULL
  explicit <- tryCatch(
    scope$selection$explicit_catalog, error = function(error) NULL)
  empty <- function(value) {
    (is.list(value) || is.character(value)) && length(value) == 0L
  }
  artifact <- if (is.list(artifacts) && length(artifacts) == 1L) {
    artifacts[[1L]]
  } else NULL
  configured <- if (is.list(vertical)) vertical$configured_crosses else NULL
  configured_artifact <- if (is.list(configured) &&
      length(configured) == 1L) configured[[1L]] else NULL
  structured <- c(
    "numeric_moments", "numeric_pair_moments", "gaussian_models",
    "fixed_numeric_histograms")
  direct <- c(
    "correlation_artifacts", "describe_artifacts", "survival_artifacts")
  other_empty <- is.list(families) && all(vapply(
    structured, function(name) {
      candidate <- families[[name]]
      is.list(candidate) && is.list(candidate$artifacts) &&
        length(candidate$artifacts) == 0L
    }, logical(1L))) && all(vapply(
      direct, function(name) {
        candidate <- families[[name]]
        is.list(candidate) && length(candidate) == 0L
      }, logical(1L)))
  set_empty <- is.list(categorical) &&
    is.list(categorical$sets) && length(categorical$sets) == 0L
  explicit_empty <- is.list(explicit) && all(vapply(c(
    "numeric_moments", "categorical_marginals", "categorical_pairs",
    "correlations"), function(name) empty(explicit[[name]]), logical(1L)))
  is.list(artifact) && identical(
    artifact$version,
    "fixed-domain-categorical-cross-contingency-v1") &&
    identical(artifact$spec_version, "v2") &&
    identical(artifact$implementation_state,
              "cross_owner_exact_gc_materialized") &&
    is.list(configured_artifact) &&
    identical(configured_artifact$version, artifact$version) &&
    identical(configured_artifact$analysis_id, artifact$analysis_id) &&
    identical(vertical$implementation_state,
              "categorical_pair_exact_gc_materialized") &&
    identical(as.numeric(vertical$included_coordinate_count),
              as.numeric(artifact$coordinate_count)) &&
    identical(scope$mode, "catalog_v1") && isTRUE(explicit_empty) &&
    isTRUE(set_empty) && isTRUE(other_empty)
}

.dsvert_dp_synopsis_remote_session_v1 <- function(session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  .dsvert_enforce_release_mode()
  storage <- .session_storage()
  ss <- storage[[session_id]]
  if (!is.environment(ss)) {
    stop("The synopsis session has not been prepared.", call. = FALSE)
  }
  .dsvert_dp_synopsis_session_context_v1(ss, session_id)
}

dsvertDPSynopsisClaimDS <- function(manifest_sha256) {
  envir <- parent.frame()
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_manifest_v1(manifest_sha256)
    .dsvert_dp_synopsis_remote_reject_cross_v1(context$manifest)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_local_claim_v1(
        manifest_sha256, .policy = context$policy,
        .secret = context$secret, .envir = envir), "local Claim")
  })
}

dsvertDPSynopsisCompileDS <- function(manifest_sha256, claims_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_manifest_v1(manifest_sha256)
    .dsvert_dp_synopsis_remote_reject_cross_v1(context$manifest)
    claims <- .dsvert_dp_synopsis_remote_decode_v1(
      claims_json, "source Claims")
    claim_set <- .dsvert_dp_synopsis_source_claim_set_v1(
      context$policy, context$manifest, claims)
    compiled <- .dsvert_dp_synopsis_local_compile_v1(
      manifest_sha256, claim_set, .policy = context$policy,
      .secret = context$secret)
    .dsvert_dp_synopsis_compilation_register_v1(
      manifest_sha256, compiled$artifact, compiled$receipt,
      context$policy, context$secret)
    .dsvert_dp_synopsis_remote_encode_v1(list(
      version = .DSVERT_DP_SYNOPSIS_LOCAL_COMPILE_ENVELOPE_VERSION,
      claim_set = claim_set, artifact = compiled$artifact,
      receipt = compiled$receipt), "local compilation")
  })
}

dsvertDPSynopsisPrepareDS <- function(
    session_id, manifest_sha256, claim_set_json, compilation_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    session_id <- .dsvert_relay_validate_session_id(session_id)
    context <- .dsvert_dp_synopsis_remote_manifest_v1(manifest_sha256)
    .dsvert_dp_synopsis_remote_reject_cross_v1(context$manifest)
    claim_set <- .dsvert_dp_synopsis_remote_decode_v1(
      claim_set_json, "source Claim set")
    compilation <- .dsvert_dp_synopsis_remote_compilation_v1(compilation_json)
    preflight <- .dsvert_dp_synopsis_compile_v1(
      compilation$receipts, compilation$artifact, claim_set,
      context$policy, context$manifest)
    local_receipt <- preflight$receipts[[context$policy$peer_name]]
    .dsvert_dp_synopsis_compilation_register_v1(
      manifest_sha256, preflight$artifact, local_receipt,
      context$policy, context$secret,
      receipts = preflight$receipts,
      receipt_set_sha256 = preflight$receipt_set_sha256)
    ss <- .S(session_id)
    .dsvert_dp_synopsis_authorize_session_v1(
      ss, session_id, manifest_sha256, preflight$artifact,
      claim_set, preflight$receipts, .policy = context$policy,
      .secret = context$secret)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_execution_prepare_v1(
        ss, session_id, .policy = context$policy,
        .secret = context$secret), "PREPARE")
  })
}

dsvertDPSynopsisStartDS <- function(
    session_id, first_prepare_json, second_prepare_json, chunk_index) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_session_v1(session_id)
    first <- .dsvert_dp_synopsis_remote_text_v1(
      first_prepare_json, "first PREPARE",
      .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_text_v1(
      second_prepare_json, "second PREPARE",
      .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_remote_exact_start_response_v1(
        context$ss, .dsvert_dp_synopsis_execution_start_v1(
        context$ss, session_id, first, second, chunk_index,
        .policy = context$policy, .secret = context$secret,
        .cache_get = context$cache_get)), "START",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}

dsvertDPSynopsisResultDS <- function(
    session_id, first_prepare_json, second_prepare_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_session_v1(session_id)
    first <- .dsvert_dp_synopsis_remote_text_v1(
      first_prepare_json, "first PREPARE",
      .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_text_v1(
      second_prepare_json, "second PREPARE",
      .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_execution_result_v1(
        context$ss, session_id, first, second,
        .policy = context$policy, .secret = context$secret,
        .cache_get = context$cache_get), "RESULT",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}

dsvertDPSynopsisFinalShareDS <- function(
    session_id, first_result_json, second_result_json,
    public_chunk_index) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_session_v1(session_id)
    first <- .dsvert_dp_synopsis_remote_decode_v1(
      first_result_json, "first RESULT",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_decode_v1(
      second_result_json, "second RESULT",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_execution_final_share_v1(
        context$ss, session_id, first, second, public_chunk_index,
        .policy = context$policy, .secret = context$secret,
        .cache_get = context$cache_get),
      "FINAL_SHARE", .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}

dsvertDPSynopsisReleaseDS <- function(
    session_id, first_result_json, second_result_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_session_v1(session_id)
    first <- .dsvert_dp_synopsis_remote_decode_v1(
      first_result_json, "first RESULT",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_decode_v1(
      second_result_json, "second RESULT",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_execution_release_v1(
        context$ss, session_id, first, second,
        .policy = context$policy, .secret = context$secret,
        .cache_get = context$cache_get), "RELEASE",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}

.dsvert_dp_synopsis_remote_source_context_v1 <- function(
    manifest_sha256, claim_set_json, compilation_json) {
  context <- .dsvert_dp_synopsis_remote_manifest_v1(manifest_sha256)
  .dsvert_dp_synopsis_remote_reject_cross_v1(context$manifest)
  list(
    policy = context$policy, secret = context$secret,
    claim_set = .dsvert_dp_synopsis_remote_decode_v1(
      claim_set_json, "source Claim set"),
    compilation = .dsvert_dp_synopsis_remote_compilation_v1(
      compilation_json))
}

dsvertDPSynopsisSourceTicketDS <- function(
    manifest_sha256, claim_set_json, compilation_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_source_transport_ticket_v1(
        manifest_sha256, context$compilation$artifact,
        context$claim_set, context$compilation$receipts,
        .policy = context$policy, .secret = context$secret),
      "source ticket")
  })
}

dsvertDPSynopsisSourcePrepareDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    first_ticket_json, second_ticket_json) {
  envir <- parent.frame()
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    first <- .dsvert_dp_synopsis_remote_text_v1(
      first_ticket_json, "first source ticket",
      .DSVERT_DP_SYNOPSIS_REMOTE_TICKET_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_text_v1(
      second_ticket_json, "second source ticket",
      .DSVERT_DP_SYNOPSIS_REMOTE_TICKET_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_source_transport_prepare_v1(
        manifest_sha256, context$compilation$artifact,
        context$claim_set, context$compilation$receipts, first, second,
        .policy = context$policy, .secret = context$secret,
        .envir = envir), "source PREPARE")
  })
}

dsvertDPSynopsisSourceChunkDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    source_transfer_id, chunk_index) {
  envir <- parent.frame()
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_source_transport_chunk_v1(
        manifest_sha256, context$compilation$artifact,
        context$claim_set, context$compilation$receipts,
        source_transfer_id, chunk_index,
        .policy = context$policy, .secret = context$secret,
        .envir = envir), "source chunk")
  })
}

dsvertDPSynopsisSourceAcceptDS <- function(manifest_sha256, envelope_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    .dsvert_enforce_release_mode()
    secret <- .dsvert_dp_secret()
    policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, secret)
    envelope_json <- .dsvert_dsi_text_decode(
      envelope_json, "biomedical synopsis encrypted chunk",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
    .dsvert_dp_capsule_source_accept_impl(
      envelope_json, .policy = policy, .secret = secret)
  })
}

.dsvert_dp_synopsis_remote_cross_source_context_v1 <- function(
    manifest_sha256, claim_set_json, compilation_json) {
  context <- .dsvert_dp_synopsis_remote_source_context_v1(
    manifest_sha256, claim_set_json, compilation_json)
  source <- .dsvert_dp_synopsis_source_transport_context_v1(
    manifest_sha256, context$compilation$artifact,
    context$claim_set, context$compilation$receipts,
    .policy = context$policy, .secret = context$secret)
  manifest <- .dsvert_dp_capsule_source_manifest(source$manifest_json)
  if (!.dsvert_dp_synopsis_supported_categorical_cross_v1(manifest)) {
    stop("The Synopsis manifest is not one projected categorical cross.",
         call. = FALSE)
  }
  c(context, list(
    manifest_json = source$manifest_json,
    source_contract = source$source_contract))
}

dsvertDPSynopsisCategoricalCrossBindDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    analysis_id, session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    gates <- .dsvert_dp_synopsis_source_transport_allocation_gates_v1(
      context$manifest_json, context$policy, context$secret)
    .dsvert_dp_categorical_cross_bind_impl(
      context$manifest_json, analysis_id, session_id,
      NULL, NULL, .policy = context$policy, .secret = context$secret,
      .allocation_observer = gates$observe,
      source_contract = context$source_contract)
  })
}

dsvertDPSynopsisCategoricalCrossFinalizeDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    analysis_id, session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_categorical_cross_finalize_impl(
      context$manifest_json, analysis_id, session_id,
      .policy = context$policy, .secret = context$secret,
      source_contract = context$source_contract)
  })
}

dsvertDPSynopsisAlignmentMaskStartDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    batch_operation_id, operation_id, chunk_index, chunk_count,
    session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_alignment_mask_start_impl(
      context$manifest_json, batch_operation_id, operation_id,
      chunk_index, chunk_count, session_id,
      .policy = context$policy, .secret = context$secret,
      source_contract = context$source_contract)
  })
}

dsvertDPSynopsisAlignmentMaskStoreDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    batch_operation_id, operation_id, chunk_index, chunk_count,
    session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_alignment_mask_store_impl(
      context$manifest_json, batch_operation_id, operation_id,
      chunk_index, chunk_count, session_id,
      .policy = context$policy,
      source_contract = context$source_contract)
  })
}

dsvertDPSynopsisAlignmentMaskSealDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    batch_operation_id, session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_alignment_mask_seal_impl(
      context$manifest_json, batch_operation_id, session_id,
      .policy = context$policy,
      source_contract = context$source_contract)
  })
}

dsvertDPSynopsisAlignmentMaskReceiveDS <- function(
    manifest_sha256, claim_set_json, compilation_json,
    peer_blob, batch_operation_id, session_id) {
  .dsvert_dp_synopsis_remote_public_v1({
    context <- .dsvert_dp_synopsis_remote_cross_source_context_v1(
      manifest_sha256, claim_set_json, compilation_json)
    .dsvert_dp_alignment_mask_receive_impl(
      peer_blob, context$manifest_json, batch_operation_id, session_id,
      .policy = context$policy,
      source_contract = context$source_contract)
  })
}
