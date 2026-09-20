# All functions in this file are internal. Public dispatch authenticates a
# Synopsis compilation before binding. Neither inputs nor shares leave R.
.dsvert_dp_glm_grid_cross_key <- function(manifest, artifact, source_contract) {
  .dsvert_joint_dp_hash(list(version = "cross-grid-semantic-release-key-v2",
    capsule_id = source_contract$capsule_id,
    source_contract_sha256 = .dsvert_joint_dp_hash(source_contract),
    signed_contract = artifact$signed_contract,
    family = artifact$family, version_family = artifact$spec_version,
    mechanism = manifest$workload$capsule_mechanism,
    alignment = .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec$alignment,
    caps = artifact$sensitivity))
}

.dsvert_dp_glm_grid_cross_load <- function(connection, secret, capsule_id,
                                          analysis_id, batch) {
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json,row_mac FROM source_cross_grid_records",
    "WHERE capsule_id=? AND analysis_id=? AND batch_index=?"),
    params = list(capsule_id, analysis_id, batch))
  if (!nrow(rows)) return(NULL)
  record <- .dsvert_dp_capsule_source_record_decode(rows, secret,
    "source_cross_grid_records", "cross-grid result")
  if (!identical(record$capsule_id, capsule_id) ||
      !identical(record$analysis_id, analysis_id) ||
      (batch != 0 && !identical(as.numeric(record$batch), as.numeric(batch)))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  record
}

.dsvert_dp_glm_grid_cross_save <- function(connection, secret, record, batch) {
  prior <- .dsvert_dp_glm_grid_cross_load(connection, secret,
    record$capsule_id, record$analysis_id, batch)
  if (!is.null(prior)) {
    .dsvert_dp_glm_grid_cross_equal(prior, record)
    return(invisible(prior))
  }
  .dsvert_dp_capsule_source_record_insert(connection, "source_cross_grid_records",
    c("capsule_id", "analysis_id", "batch_index"),
    list(record$capsule_id, record$analysis_id, batch), record, secret)
  invisible(record)
}

.dsvert_dp_glm_grid_cross_persisted <- function(con, secret, binding, stage) {
  record <- .dsvert_dp_glm_grid_cross_load(con, secret,
    binding$contract$capsule_id, binding$analysis_id, stage$batch)
  if (is.null(record)) return(NULL)
  if (!identical(record$version, "cross-grid-persisted-batch-v2") ||
      !identical(record$semantic_key, binding$semantic_key) ||
      !identical(record$plan_sha256, .dsvert_joint_dp_hash(stage$plan))) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  .exact_gc_standard_b64_raw(record$share, 16 * stage$vector_len,
                            "cross-grid private result")
  validity <- .exact_gc_standard_b64_raw(record$validity_share, 1L,
                                        "cross-grid private validity")
  if (!as.integer(validity[[1L]]) %in% 0:1) .dsvert_dp_glm_grid_cross_fail()
  record
}

.dsvert_dp_glm_grid_cross_binding <- function(ss, analysis_id) {
  binding <- ss$.dp_glm_grid_cross[[analysis_id]]
  if (!is.list(binding) || !identical(binding$peer_binding_digest,
      ss$.exact_gc_peer_binding_digest)) .dsvert_dp_glm_grid_cross_fail()
  binding
}

.dsvert_dp_glm_grid_cross_public <- function(binding, policy, phase, extra = list()) {
  unsigned <- c(list(version = "dsvert-cross-grid-receipt-v2", phase = phase,
    capsule_id = binding$contract$capsule_id, analysis_id = binding$analysis_id,
    peer_name = policy$peer_name,
    peer_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    semantic_key = binding$semantic_key,
    artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact),
    source_contract_sha256 = binding$contract_hash,
    profile_sha256 = binding$artifact$numeric_certificate$profile_sha256,
    certificate_sha256 = binding$artifact$numeric_certificate$certificate_sha256,
    private_result_exposed = FALSE), extra)
  .dsvert_dp_capsule_source_encode_json(.dsvert_dp_capsule_source_sign(
    unsigned, policy, "cross-grid-result"))
}

.dsvert_dp_glm_grid_cross_bind <- function(policy, secret, manifest_json,
    source_contract, analysis_id, ss) {
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  artifact <- .dsvert_dp_glm_grid_cross_artifacts(manifest)[[analysis_id]]
  if (!is.list(artifact)) .dsvert_dp_glm_grid_cross_fail()
  .dsvert_dp_glm_grid_cross_equal(artifact,
    .dsvert_dp_glm_grid_cross_workload_artifact(.dsvert_dp_glm_grid_cross_embedded_contract(artifact)))
  parties <- .exact_gc_vecmul_party_context(ss)
  if (!setequal(c(parties$self_name, parties$peer_name),
      unlist(artifact$computation_peers, use.names = FALSE)) ||
      !identical(parties$self_name, policy$peer_name)) .dsvert_dp_glm_grid_cross_fail()
  loaded <- .dsvert_dp_gaussian_cross_load_inputs(policy, secret, manifest,
    artifact, analysis_id, ss, source_contract)
  alignment <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    state <- .dsvert_dp_capsule_source_incoming_load(con,
      loaded$contract$capsule_id, secret)
    .dsvert_dp_alignment_mask_digest_records(state,
      unlist(artifact$participating_peers, use.names = FALSE))
  })
  cache_directory <- file.path(.ensure_session_dir(ss), "grid-circuits-v1")
  if (!dir.exists(cache_directory) && !dir.create(cache_directory, mode = "0700", showWarnings = FALSE)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  if (.dsvert_dp_path_is_link(cache_directory) ||
      !.dsvert_dp_private_mode(cache_directory, directory = TRUE)) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  cache_key <- .dsvert_dp_capsule_source_mac(secret,
    "cross-grid-circuit-cache-v1", "public-topology-only")
  binding <- list(analysis_id = analysis_id, artifact = artifact,
    circuit_cache = list(directory = normalizePath(cache_directory),
      key = gsub("[\r\n]", "", jsonlite::base64_enc(
        .dsvert_dp_capsule_source_hex_raw(cache_key, "cross-grid circuit cache")))),
    contract = loaded$contract, contract_hash = loaded$contract_hash,
    semantic_key = .dsvert_dp_glm_grid_cross_key(manifest, artifact, loaded$contract),
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    values = lapply(loaded$values, jsonlite::base64_dec),
    validities = lapply(loaded$validities, jsonlite::base64_dec),
    alignment = alignment, stages = list())
  binding$batch_count <- ceiling(artifact$observation_capacity / artifact$transcript$row_batch_size) *
    ceiling(artifact$coordinate_count / 8)
  previous <- ss$.dp_glm_grid_cross[[analysis_id]]
  if (!is.null(previous)) {
    if (!identical(previous$semantic_key, binding$semantic_key)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    binding <- previous
  }
  ss$.dp_glm_grid_cross[[analysis_id]] <- binding
  .dsvert_dp_glm_grid_cross_public(binding, policy, "bound",
    list(batch_count = binding$batch_count))
}

.dsvert_dp_glm_grid_cross_prepare <- function(policy, secret, ss, analysis_id, batch) {
  binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
  batch <- .dsvert_dp_glm_grid_cross_integer(batch, 1, binding$batch_count)
  artifact <- binding$artifact
  spec <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec
  columns <- ceiling(artifact$coordinate_count / 8)
  row_batch_size <- artifact$transcript$row_batch_size
  row <- floor((batch - 1) / columns) * row_batch_size + 1
  col <- ((batch - 1) %% columns) * 8 + 1
  rows <- min(row_batch_size, spec$observation_capacity - row + 1)
  candidates <- seq.int(col, length.out = min(8, length(spec$beta_grid) - col + 1))
  plan <- list(Family = spec$family, Rows = rows,
    Predictors = length(spec$predictor_order), Owners = length(spec$participating_peers),
    A = spec$numeric_contract$profile_envelope, GridBits = spec$numeric_grid_bits,
    MaxOutcome = spec$max_outcome, Beta = spec$beta_encoded[candidates],
    Caps = lapply(spec$sensitivity$candidate_bounds[candidates], `[[`, "per_patient_cap"))
  if (identical(spec$family, "nb")) {
    plan$A <- 16
    plan$ThetaExponents <- as.list(log2(unlist(spec$theta_grid[candidates])))
  }
  if (spec$family %in% c("multinomial", "ordinal")) {
    plan$A <- if (identical(spec$family, "ordinal")) 8 else 16
    plan$Classes <- spec$class_count
    if (identical(spec$family, "ordinal")) {
      plan$Thresholds <- lapply(spec$candidate_encoded[candidates], `[[`, "thresholds")
    }
  }
  public <- .callMpcTool("cross-grid-batch-plan-v2", plan)
  if (!is.list(public) || !is.character(public$purpose) ||
      public$input_bits > .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  namespace <- substr(.dsvert_joint_dp_hash(list(binding$semantic_key, batch)), 1, 32)
  stage <- list(operation_id = paste0("op_", namespace),
    source_key = paste0("exact_gc_in_", namespace), output_key = paste0("exact_gc_out_", namespace),
    purpose = public$purpose, operation = "glm-grid-profile-v2", vector_len = length(candidates),
    candidates = candidates, plan = plan, batch = batch)
  previous <- binding$stages[[as.character(batch)]]
  if (!is.null(previous)) {
    .dsvert_dp_glm_grid_cross_equal(previous, stage)
  } else {
    input <- do.call(c, lapply(seq.int(row, length.out = rows), function(r) {
      bytes <- seq.int((r - 1) * 16 + 1, length.out = 16)
      do.call(c, lapply(seq_along(binding$values), function(i) {
        c(binding$values[[i]][bytes], binding$validities[[i]][bytes])
      }))
    }))
    input <- c(input, binding$alignment)
    if (length(input) != 16 * public$source_records) .dsvert_dp_glm_grid_cross_fail()
    producer <- paste0("dp.", spec$family, "-grid-cross.v1")
    seed <- .dsvert_dp_capsule_source_mac(secret, "cross-grid-output-mask-v2",
      .dsvert_joint_dp_hash(list(binding$semantic_key, batch)))
    ss$.exact_gc_inputs[[stage$source_key]] <- list(
      share = gsub("[\r\n]", "", jsonlite::base64_enc(input)), ring_bits = 128L,
      vector_len = as.integer(length(candidates)), producer = producer,
      allowed_spec = .exact_gc_allowed_spec(stage$operation, stage$purpose,
        0L, "cross-grid-ring128-share-v2", 128L), claimed_by = NULL,
      cross_grid = plan, cross_grid_cache = binding$circuit_cache, cross_grid_mask_seed = gsub("[\r\n]", "", jsonlite::base64_enc(
        .dsvert_dp_capsule_source_hex_raw(seed, "cross-grid mask seed"))))
    binding$stages[[as.character(batch)]] <- stage
    ss$.dp_glm_grid_cross[[analysis_id]] <- binding
  }
  persisted <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    !is.null(.dsvert_dp_glm_grid_cross_persisted(con, secret, binding, stage))
  })
  .dsvert_dp_glm_grid_cross_public(binding, policy, "prepared", c(
    stage[c("operation_id", "source_key", "output_key", "purpose", "operation",
            "vector_len", "batch")], list(persisted = persisted)))
}

.dsvert_dp_glm_grid_cross_start <- function(policy, ss, analysis_id, session_id, batch) {
  binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
  batch <- .dsvert_dp_glm_grid_cross_integer(batch, 1, binding$batch_count)
  stage <- binding$stages[[as.character(batch)]]
  if (is.null(stage)) .dsvert_dp_glm_grid_cross_fail()
  .exact_gc_init_impl(ss, session_id, stage$operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    stage$source_key, stage$output_key, stage$operation, 128L, 0L,
    stage$vector_len, stage$purpose)
}

.dsvert_dp_glm_grid_cross_store <- function(policy, secret, ss, analysis_id, batch) {
  binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
  stage <- binding$stages[[as.character(batch)]]
  if (is.null(stage)) .dsvert_dp_glm_grid_cross_fail()
  value <- .exact_gc_consume_output(ss, stage$output_key, stage$operation_id,
    "cross-grid-ring128-share-v2", stage$operation, stage$purpose, 128L, 0L,
    stage$vector_len, paste0("dp.", binding$artifact$family, "-grid-cross.v1"),
    consume = FALSE)
  # The existing private alignment gate has already completed bilaterally.
  # The kernel repeats that check without publishing another per-batch bit.
  record <- list(version = "cross-grid-persisted-batch-v2",
    capsule_id = binding$contract$capsule_id, analysis_id = analysis_id,
    semantic_key = binding$semantic_key, batch = batch,
    plan_sha256 = .dsvert_joint_dp_hash(stage$plan),
    share = value$share, validity_share = value$validity_share)
  .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    .dsvert_dp_capsule_source_transaction(con,
      .dsvert_dp_glm_grid_cross_save(con, secret, record, batch))
  })
  .dsvert_dp_glm_grid_cross_public(binding, policy, "batch_persisted", list(batch = batch))
}

.dsvert_dp_glm_grid_cross_finalize <- function(policy, secret, ss, analysis_id) {
  binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
  result <- raw(16 * binding$artifact$coordinate_count)
  .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    .dsvert_dp_capsule_source_transaction(con, {
      for (batch in seq_len(binding$batch_count)) {
        stage <- binding$stages[[as.character(batch)]]
        if (is.null(stage)) .dsvert_dp_glm_grid_cross_fail()
        record <- .dsvert_dp_glm_grid_cross_persisted(con, secret, binding, stage)
        if (is.null(record)) .dsvert_dp_glm_grid_cross_fail()
        share <- .exact_gc_standard_b64_raw(record$share,
          16 * stage$vector_len, "cross-grid private result")
        bytes <- seq.int((stage$candidates[[1]] - 1) * 16 + 1, length.out = length(share))
        result[bytes] <- .dsvert_dp_capsule_source_add_ring128(result[bytes], share)
      }
      record <- list(version = "cross-grid-complete-result-v2",
        capsule_id = binding$contract$capsule_id, analysis_id = analysis_id,
        semantic_key = binding$semantic_key,
        artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact),
        source_contract_sha256 = binding$contract_hash,
        share = gsub("[\r\n]", "", jsonlite::base64_enc(result)))
      .dsvert_dp_glm_grid_cross_save(con, secret, record, 0)
    })
  })
  .dsvert_dp_glm_grid_cross_public(binding, policy, "complete",
    list(coordinate_count = binding$artifact$coordinate_count,
      implementation_state = "cross_owner_exact_gc_materialized",
      cross_owner_state = "exact_gc_to_joint_dp_vector_v1"))
}

.dsvert_dp_glm_grid_cross_inject <- function(con, secret, manifest, contract, chunk, share) {
  if (!is.raw(share) || length(share) != chunk$count * 16L) {
    .dsvert_dp_glm_grid_cross_fail()
  }
  artifacts <- .dsvert_dp_glm_grid_cross_artifacts(manifest)
  artifacts <- Filter(function(artifact) !.dsvert_dp_staged_grouped_artifact(artifact), artifacts)
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  for (id in names(artifacts)) {
    record <- .dsvert_dp_glm_grid_cross_load(con, secret, contract$capsule_id, id, 0)
    artifact <- artifacts[[id]]
    if (is.null(record) || !identical(record$version, "cross-grid-complete-result-v2") ||
        !identical(record$semantic_key, .dsvert_dp_glm_grid_cross_key(manifest, artifact, contract)) ||
        !identical(record$artifact_sha256, .dsvert_joint_dp_hash(artifact)) ||
        !identical(record$source_contract_sha256, .dsvert_joint_dp_hash(contract))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    block <- layout$blocks[[paste("gaussian_models", id, sep = "::")]]
    result <- .exact_gc_standard_b64_raw(record$share, 16 * block$length,
                                        "cross-grid result injection")
    first <- max(block$start, chunk$offset + 1)
    last <- min(block$end, chunk$offset + chunk$count)
    if (first > last) next
    target <- seq.int((first - chunk$offset - 1) * 16 + 1, length.out = (last-first+1)*16)
    source <- seq.int((first - block$start) * 16 + 1, length.out = length(target))
    # Add once to the freshly loaded original aggregate; never persist an
    # injected aggregate. Repeated reads therefore return identical shares.
    share[target] <- .dsvert_dp_capsule_source_add_ring128(share[target], result[source])
  }
  share
}

.dsvert_dp_synopsis_supported_glm_grid_cross_v1 <- function(manifest) {
  artifacts <- .dsvert_dp_glm_grid_cross_artifacts(manifest)
  length(artifacts) == 1L && length(manifest$workload$families$gaussian_models$artifacts) == 1L &&
    all(vapply(artifacts, function(artifact) {
      identical(artifact$implementation_state, "cross_owner_exact_gc_materialized") &&
        identical(artifact$cross_owner_state, "exact_gc_to_joint_dp_vector_v1")
    }, logical(1L)))
}

#' Execute a signed cross-owner finite-grid lifecycle stage (AGGREGATE)
#'
#' Internal DataSHIELD wiring for certified binomial and Poisson candidate
#' losses. Requires the signed Synopsis compilation and both pinned computation
#' peers. Returns authenticated public receipts only; no exact loss, input,
#' predictor, alignment digest or result share is returned.
#' @param manifest_sha256 Signed Synopsis manifest hash.
#' @param claim_set_json Authenticated source claim set.
#' @param compilation_json Authenticated Synopsis compilation.
#' @param analysis_id Custodian-signed analysis identifier.
#' @param session_id Existing two-peer exact-computation session.
#' @param action One of bind, prepare, start, store, finalize or evidence.
#' @param batch Public row/candidate batch index; zero outside batch stages.
#' @param routing_receipt_json Signed Cox owner routing receipt for bind only;
#'   empty on the owner's first bind and for all other families/actions.
#' @return Authenticated public lifecycle receipts only.
#' @export
dsvertDPSynopsisGLMGridCrossDS <- function(manifest_sha256, claim_set_json,
    compilation_json, analysis_id, session_id, action, batch = 0, routing_receipt_json = "") {
  .dsvert_dp_synopsis_remote_public_v1({
    if (!is.character(action) || length(action) != 1L || is.na(action) ||
        !action %in% c("bind", "prepare", "start", "store", "finalize", "evidence")) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    if (!is.character(routing_receipt_json) || length(routing_receipt_json) != 1L ||
        is.na(routing_receipt_json)) .dsvert_dp_glm_grid_cross_fail()
    if (nzchar(routing_receipt_json)) {
      routing_receipt_json <- .dsvert_dsi_text_decode(routing_receipt_json,
        "Cox routing receipt", .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
    }
    if (!identical(action, "bind") && nzchar(routing_receipt_json)) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    session_id <- .dsvert_relay_validate_session_id(session_id)
    analysis_id <- .dsvert_dp_capsule_id(analysis_id, "cross-grid analysis")
    request <- list(manifest_sha256 = manifest_sha256,
      claim_set_json = claim_set_json, compilation_json = compilation_json)
    if (action %in% c("bind", "evidence")) {
      context <- .dsvert_dp_synopsis_remote_manifest_v1(manifest_sha256)
      compilation <- .dsvert_dp_synopsis_remote_compilation_v1(compilation_json)
      if (identical(action, "evidence")) {
        if (!identical(as.numeric(batch), 0)) .dsvert_dp_grouped_cross_fail()
        publication <- .dsvert_dp_synopsis_publication_v1(manifest_sha256,
          context$policy, context$secret)
        .dsvert_dp_glm_grid_cross_equal(compilation$artifact, publication$artifact)
        .dsvert_dp_glm_grid_cross_equal(compilation$receipts, publication$compile_receipts)
        manifest <- context$manifest
        artifact <- manifest$workload$families$gaussian_models$artifacts[[analysis_id]]
        cox <- identical(artifact$version, .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION)
        if (!cox && !.dsvert_dp_synopsis_supported_glm_grid_cross_v1(manifest)) {
          .dsvert_dp_glm_grid_cross_fail()
        }
        source_contract <- .dsvert_dp_synopsis_source_contract_from_hashes_v1(
          context$policy, manifest, publication$artifact_key,
          publication$artifact$semantic$source_claim_set_sha256)
        if (cox) {
          schema <- .dsvert_dp_lmm_cross_signed_schema(context$policy, context$secret,
            manifest_sha256, manifest)
          return(.dsvert_dp_cox_cross_evidence(context$policy, context$secret,
            manifest, source_contract, schema, analysis_id, manifest_sha256,
            publication$artifact_key))
        }
        return(.dsvert_dp_lmm_cross_evidence(context$policy, context$secret,
          manifest, source_contract, analysis_id, manifest_sha256,
          publication$artifact_key))
      }
      claims <- .dsvert_dp_synopsis_remote_decode_v1(claim_set_json, "source Claim set")
      source <- .dsvert_dp_synopsis_source_transport_context_v1(manifest_sha256,
        compilation$artifact, claims, compilation$receipts,
        .policy = context$policy, .secret = context$secret)
      manifest <- .dsvert_dp_capsule_source_manifest(source$manifest_json)
      artifact <- manifest$workload$families$gaussian_models$artifacts[[analysis_id]]
      cox <- identical(artifact$version, .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION)
      if (cox) {
        if (!identical(as.numeric(batch), 0)) .dsvert_dp_cox_grid_cross_fail()
        routing_receipt <- if (nzchar(routing_receipt_json)) {
          .dsvert_dp_synopsis_remote_json_v1(routing_receipt_json, "Cox routing receipt",
            .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
        } else NULL
        # The Cox adapter authenticates the exact single-artifact projection,
        # signed schema and source contract; no generic/grouped source fallback.
        return(.dsvert_dp_cox_cross_remote_bind(context, source, compilation,
          claims, request, analysis_id, .S(session_id), parent.frame(), routing_receipt))
      }
      if (nzchar(routing_receipt_json) ||
          !.dsvert_dp_synopsis_supported_glm_grid_cross_v1(manifest)) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      ss <- .S(session_id)
      if (.dsvert_dp_staged_grouped_artifact(manifest$workload$families$gaussian_models$artifacts[[analysis_id]])) {
        if (!identical(as.numeric(batch), 0)) .dsvert_dp_grouped_cross_fail()
        return(.dsvert_dp_lmm_cross_remote_bind(context, source, compilation,
          claims, request, analysis_id, ss, parent.frame()))
      }
      result <- .dsvert_dp_glm_grid_cross_bind(context$policy, context$secret,
        source$manifest_json, source$source_contract, analysis_id, ss)
      # Admission is immutable within this bound computation session. Retain the
      # validated public bytes, not a caller-selectable shortcut or new token.
      binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
      if (!is.null(binding$admission) &&
          !identical(binding$admission$request, request)) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      binding$admission <- list(request = request, policy = context$policy,
        secret = context$secret, contract_hash = binding$contract_hash,
        artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact))
      ss$.dp_glm_grid_cross[[analysis_id]] <- binding
      return(result)
    }
    ss <- .S(session_id)
    if (!is.null(ss$.dp_lmm_grid_cross[[analysis_id]])) {
      return(.dsvert_dp_lmm_cross_dispatch(ss, analysis_id, session_id, request, action, batch))
    }
    binding <- .dsvert_dp_glm_grid_cross_binding(ss, analysis_id)
    admission <- binding$admission
    if (!is.list(admission) || !identical(admission$request, request) ||
        !identical(admission$contract_hash, binding$contract_hash) ||
        !identical(admission$artifact_sha256, .dsvert_joint_dp_hash(binding$artifact))) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    context <- admission
    switch(action,
      prepare = .dsvert_dp_glm_grid_cross_prepare(context$policy, context$secret,
        ss, analysis_id, batch),
      start = .dsvert_dp_glm_grid_cross_start(context$policy, ss, analysis_id, session_id, batch),
      store = .dsvert_dp_glm_grid_cross_store(context$policy, context$secret,
        ss, analysis_id, batch),
      finalize = .dsvert_dp_glm_grid_cross_finalize(context$policy,
        context$secret, ss, analysis_id))
  })
}
