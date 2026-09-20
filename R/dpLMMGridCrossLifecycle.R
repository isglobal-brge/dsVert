# Private staged LMM lifecycle. The signed catalog remains responsible for
# admission; these helpers expose public receipts and keep all shares local.
.dsvert_dp_lmm_cross_binding <- function(ss, analysis_id) {
  binding <- ss$.dp_lmm_grid_cross[[analysis_id]]
  if (!is.list(binding) || !identical(binding$peer_binding_digest,
      ss$.exact_gc_peer_binding_digest)) .dsvert_dp_grouped_cross_fail()
  binding
}

.dsvert_dp_lmm_cross_public <- function(binding, policy, phase, extra = list()) {
  unsigned <- c(list(version = .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-receipt-v1", "dsvert-"), phase = phase,
    capsule_id = binding$contract$capsule_id, analysis_id = binding$analysis_id,
    peer_name = policy$peer_name,
    peer_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    semantic_key = binding$semantic_key,
    artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact),
    source_contract_sha256 = binding$contract_hash,
    profile_sha256 = binding$artifact$numeric_certificate$profile_sha256,
    certificate_sha256 = binding$artifact$numeric_certificate$certificate_sha256,
    stage_plan_digest = binding$stage$stage_plan_digest,
    private_result_exposed = FALSE), extra)
  .dsvert_dp_capsule_source_encode_json(.dsvert_dp_capsule_source_sign(
    unsigned, policy, "cross-grid-result"))
}

.dsvert_dp_lmm_cross_bind <- function(policy, secret, manifest,
    source_contract, schema_manifest, analysis_id, ss,
    routing_sidecar = NULL, producer = NULL) {
  context <- .dsvert_dp_lmm_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  worker <- .dsvert_dp_lmm_cross_prepare_worker(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id, routing_sidecar, producer)
  .dsvert_dp_staged_cross_bind_worker(policy, manifest, source_contract,
    analysis_id, ss, context, worker)
}

.dsvert_dp_staged_cross_bind_worker <- function(policy, manifest, source_contract,
    analysis_id, ss, context, worker) {
  semantic_key <- .dsvert_dp_glm_grid_cross_key(manifest, context$artifact, source_contract)
  suffix <- substr(.dsvert_joint_dp_hash(list(semantic_key = semantic_key,
    operation = worker$operation)), 1L, 32L)
  stage <- c(list(operation_id = paste0("op_", suffix),
    source_key = paste0("exact_gc_in_", suffix), output_key = paste0("exact_gc_out_", suffix)),
    worker[c("operation", "purpose", "vector_len", "stage_plan_digest")])
  binding <- list(analysis_id = analysis_id, artifact = context$artifact,
    contract = context$source_contract, contract_hash = context$source_hash,
    semantic_key = semantic_key, peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    stage = stage, worker_input = worker[[.dsvert_dp_staged_grouped_input_key(context$artifact$family)]])
  previous <- ss$.dp_lmm_grid_cross[[analysis_id]]
  if (!is.null(previous)) {
    .dsvert_dp_glm_grid_cross_equal(previous[setdiff(names(previous), "admission")], binding)
    binding <- previous
  }
  ss$.dp_lmm_grid_cross[[analysis_id]] <- binding
  .dsvert_dp_lmm_cross_public(binding, policy, "bound")
}

.dsvert_dp_lmm_cross_remote_bind <- function(context, source, compilation,
    claims, request, analysis_id, ss, envir) {
  manifest <- .dsvert_dp_capsule_source_manifest(source$manifest_json)
  artifact <- manifest$workload$families$gaussian_models$artifacts[[analysis_id]]
  contract <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)
  policy <- context$policy
  secret <- context$secret
  schema <- .dsvert_dp_lmm_cross_signed_schema(policy, secret,
    request$manifest_sha256, manifest)
  producer <- routing <- NULL
  if (identical(policy$peer_name, contract$spec$grouping$owner_peer)) {
    gate <- .dsvert_dp_synopsis_source_transport_gate_v1(request$manifest_sha256,
      compilation$artifact, claims, compilation$receipts, .policy = policy, .secret = secret)
    .dsvert_dp_glm_grid_cross_equal(gate$source_contract, source$source_contract)
    snapshots <- setNames(lapply(names(policy$datasets), function(name) {
      .dsvert_dp_resolve_snapshot(policy, name, envir, secret)
    }), names(policy$datasets))
    producer <- gate$materializer(policy, manifest, snapshots,
      compute_commitment = TRUE, include_release = TRUE)
    if (!is.list(producer) || !is.function(producer$reset)) .dsvert_dp_grouped_cross_fail()
    on.exit(try(producer$reset(), silent = TRUE), add = TRUE)
    if (!isTRUE(gate$producer_validator(producer, policy, manifest, source$source_contract))) {
      .dsvert_dp_grouped_cross_fail()
    }
    hash <- .dsvert_joint_dp_hash(source$source_contract)
    private <- .dsvert_dp_capsule_source_producer_private(secret, producer, hash,
      require_commitment = TRUE)
    .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
      outbound <- .dsvert_dp_capsule_source_outbound_load(con,
        .dsvert_dp_capsule_source_transfer_id(source$source_contract, policy$peer_name), secret)
      if (is.null(outbound) || !outbound$status %in% c("ready", "complete") ||
          !identical(outbound$contract_hash, hash) ||
          !.dsvert_joint_dp_dsi_hex_equal(outbound$private_snapshot_mac, private$snapshot_mac) ||
          !.dsvert_joint_dp_dsi_hex_equal(outbound$private_value_mac, private$value_mac) ||
          !identical(outbound$private_alignment_consensus_hash, private$alignment_consensus_hash)) {
        .dsvert_dp_capsule_source_snapshot_changed()
      }
    })
    routing <- .dsvert_dp_lmm_cross_route_sidecar(policy, secret, manifest,
      source$source_contract, schema, analysis_id, producer)
  }
  result <- .dsvert_dp_lmm_cross_bind(policy, secret, manifest, source$source_contract,
    schema, analysis_id, ss, routing, producer)
  binding <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)
  if (!is.null(binding$admission) && !identical(binding$admission$request, request)) {
    .dsvert_dp_grouped_cross_fail()
  }
  binding$admission <- list(request = request, policy = policy, secret = secret,
    contract_hash = binding$contract_hash, artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact))
  ss$.dp_lmm_grid_cross[[analysis_id]] <- binding
  result
}

.dsvert_dp_lmm_cross_dispatch <- function(ss, analysis_id, session_id, request, action, batch) {
  if (!identical(as.numeric(batch), 0)) .dsvert_dp_grouped_cross_fail()
  binding <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)
  admission <- binding$admission
  if (!is.list(admission) || !identical(admission$request, request) ||
      !identical(admission$contract_hash, binding$contract_hash) ||
      !identical(admission$artifact_sha256, .dsvert_joint_dp_hash(binding$artifact))) {
    .dsvert_dp_grouped_cross_fail()
  }
  switch(action,
    prepare = .dsvert_dp_lmm_cross_prepare(admission$policy, admission$secret, ss, analysis_id),
    start = .dsvert_dp_lmm_cross_start(admission$policy, ss, analysis_id, session_id),
    store = .dsvert_dp_lmm_cross_store(admission$policy, admission$secret, ss, analysis_id),
    finalize = .dsvert_dp_lmm_cross_finalize(admission$policy, admission$secret, ss, analysis_id),
    .dsvert_dp_grouped_cross_fail())
}

.dsvert_dp_lmm_cross_record <- function(con, secret, manifest, artifact, contract,
    batch = 0L, stage = NULL) {
  record <- .dsvert_dp_glm_grid_cross_load(con, secret,
    contract$capsule_id, artifact$analysis_id, batch)
  if (is.null(record)) return(NULL)
  expected <- list(version = if (batch == 0L) .dsvert_dp_staged_grouped_tag(artifact, "-staged-complete-result-v1") else
      .dsvert_dp_staged_grouped_tag(artifact, "-staged-persisted-result-v1"), capsule_id = contract$capsule_id,
    analysis_id = artifact$analysis_id,
    semantic_key = .dsvert_dp_glm_grid_cross_key(manifest, artifact, contract),
    artifact_sha256 = .dsvert_joint_dp_hash(artifact),
    source_contract_sha256 = .dsvert_joint_dp_hash(contract))
  .dsvert_dp_glm_grid_cross_equal(record[names(expected)], expected)
  .exact_gc_standard_b64_raw(record$share, 16 * artifact$coordinate_count,
    "staged LMM result")
  .exact_gc_validate_packed_bits(record$validity_share, artifact$coordinate_count,
    "staged LMM result validity")
  for (field in c("stage_receipt", "stage_plan_digest")) {
    value <- record[[field]]
    if (!is.character(value) || length(value) != 1L || is.na(value) ||
        !grepl("^[0-9a-f]{64}$", value) || identical(value, strrep("0", 64))) {
      .dsvert_dp_grouped_cross_fail()
    }
  }
  if (!is.null(stage) && (!identical(record$stage_plan_digest, stage$stage_plan_digest) ||
      !identical(record$purpose, stage$purpose))) .dsvert_dp_grouped_cross_fail()
  record
}

.dsvert_dp_lmm_cross_persisted <- function(con, secret, binding, batch) {
  # The semantic key is already authenticated by the bound manifest. Reuse the
  # exact record validator without reconstructing a caller-selectable manifest.
  record <- .dsvert_dp_glm_grid_cross_load(con, secret,
    binding$contract$capsule_id, binding$analysis_id, batch)
  if (is.null(record)) return(NULL)
  expected <- list(version = if (batch == 0L) .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-complete-result-v1") else
      .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-persisted-result-v1"), capsule_id = binding$contract$capsule_id,
    analysis_id = binding$analysis_id, semantic_key = binding$semantic_key,
    artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact),
    source_contract_sha256 = binding$contract_hash,
    stage_plan_digest = binding$stage$stage_plan_digest, purpose = binding$stage$purpose)
  .dsvert_dp_glm_grid_cross_equal(record[names(expected)], expected)
  .exact_gc_standard_b64_raw(record$share, 16 * binding$stage$vector_len, "staged LMM result")
  .exact_gc_validate_packed_bits(record$validity_share, binding$stage$vector_len,
    "staged LMM result validity")
  .dsvert_joint_dp_vector_exact_gc_hex(record$stage_receipt, "staged LMM terminal receipt")
  if (identical(record$stage_receipt, strrep("0", 64))) .dsvert_dp_grouped_cross_fail()
  record
}

.dsvert_dp_lmm_cross_prepare <- function(policy, secret, ss, analysis_id) {
  binding <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)
  stage <- binding$stage
  source <- list(share = "", ring_bits = 128L, vector_len = as.integer(stage$vector_len),
    producer = .dsvert_dp_staged_grouped_tag(binding$artifact, "-grid-cross.staged-v1", "dp."),
    allowed_spec = .exact_gc_allowed_spec(stage$operation, stage$purpose, 0L,
      paste0(.dsvert_dp_staged_native_kind(binding$artifact), "-staged-ring128-share-v1"), 128L), claimed_by = NULL,
    grouped_lmm = binding$worker_input)
  names(source)[names(source) == "grouped_lmm"] <-
    .dsvert_dp_staged_grouped_input_key(binding$artifact$family)
  previous <- ss$.exact_gc_inputs[[stage$source_key]]
  if (is.null(previous)) ss$.exact_gc_inputs[[stage$source_key]] <- source else {
    .dsvert_dp_glm_grid_cross_equal(previous[setdiff(names(previous), "claimed_by")],
      source[setdiff(names(source), "claimed_by")])
  }
  persisted <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    !is.null(.dsvert_dp_lmm_cross_persisted(con, secret, binding, 1L))
  })
  .dsvert_dp_lmm_cross_public(binding, policy, "prepared", c(
    stage[setdiff(names(stage), "stage_plan_digest")], list(persisted = persisted)))
}

.dsvert_dp_lmm_cross_start <- function(policy, ss, analysis_id, session_id) {
  stage <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)$stage
  .exact_gc_init_impl(ss, session_id, stage$operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    stage$source_key, stage$output_key, stage$operation, 128L, 0L,
    stage$vector_len, stage$purpose)
}

.dsvert_dp_lmm_cross_store <- function(policy, secret, ss, analysis_id) {
  binding <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)
  stage <- binding$stage
  value <- .exact_gc_consume_output(ss, stage$output_key, stage$operation_id,
    paste0(.dsvert_dp_staged_native_kind(binding$artifact), "-staged-ring128-share-v1"), stage$operation, stage$purpose,
    128L, 0L, stage$vector_len,
    .dsvert_dp_staged_grouped_tag(binding$artifact, "-grid-cross.staged-v1", "dp."), consume = FALSE)
  if (!identical(value$stage_plan_digest, stage$stage_plan_digest)) .dsvert_dp_grouped_cross_fail()
  .exact_gc_standard_b64_raw(value$share, 16 * stage$vector_len, "staged LMM result")
  .exact_gc_validate_packed_bits(value$validity_share, stage$vector_len, "staged LMM result validity")
  .dsvert_joint_dp_vector_exact_gc_hex(value$stage_receipt, "staged LMM terminal receipt")
  if (identical(value$stage_receipt, strrep("0", 64))) .dsvert_dp_grouped_cross_fail()
  record <- c(list(version = .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-persisted-result-v1"),
    capsule_id = binding$contract$capsule_id, analysis_id = analysis_id,
    semantic_key = binding$semantic_key, batch = 1L,
    artifact_sha256 = .dsvert_joint_dp_hash(binding$artifact),
    source_contract_sha256 = binding$contract_hash, purpose = stage$purpose),
    value[c("share", "validity_share", "stage_receipt", "stage_plan_digest")])
  .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    .dsvert_dp_capsule_source_transaction(con,
      .dsvert_dp_glm_grid_cross_save(con, secret, record, 1L))
  })
  .dsvert_dp_lmm_cross_public(binding, policy, "persisted",
    list(stage_receipt = record$stage_receipt))
}

.dsvert_dp_lmm_cross_finalize <- function(policy, secret, ss, analysis_id) {
  binding <- .dsvert_dp_lmm_cross_binding(ss, analysis_id)
  record <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    .dsvert_dp_capsule_source_transaction(con, {
      record <- .dsvert_dp_lmm_cross_persisted(con, secret, binding, 1L)
      if (is.null(record)) .dsvert_dp_grouped_cross_fail()
      record$version <- .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-complete-result-v1")
      record$batch <- NULL
      .dsvert_dp_glm_grid_cross_save(con, secret, record, 0L)
      public <- record[setdiff(names(record), c("share", "validity_share"))]
      public$version <- .dsvert_dp_staged_grouped_tag(binding$artifact, "-staged-terminal-binding-v1")
      public$batch <- -1L
      .dsvert_dp_glm_grid_cross_save(con, secret, public, -1L)
      record
    })
  })
  .dsvert_dp_lmm_cross_public(binding, policy, "complete", list(
    coordinate_count = binding$stage$vector_len, stage_receipt = record$stage_receipt))
}

.dsvert_dp_lmm_cross_artifacts <- function(manifest) {
  Filter(.dsvert_dp_staged_grouped_artifact,
    manifest$workload$families$gaussian_models$artifacts)
}

.dsvert_dp_lmm_cross_public_record <- function(policy, secret, manifest, contract) {
  artifacts <- .dsvert_dp_lmm_cross_artifacts(manifest)
  if (!length(artifacts)) return(NULL)
  if (length(artifacts) != 1L) .dsvert_dp_grouped_cross_fail()
  .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    # The sampler compiler runs before the sticky START claim. Read only the
    # separately authenticated public terminal identity at this point.
    artifact <- artifacts[[1L]]
    record <- .dsvert_dp_glm_grid_cross_load(con, secret, contract$capsule_id, artifact$analysis_id, -1L)
    .dsvert_dp_lmm_cross_public_record_validate(record, manifest, artifact, contract)
  })
}

.dsvert_dp_lmm_cross_public_record_validate <- function(record, manifest, artifact, contract) {
  cox <- identical(artifact$family, "cox") &&
    identical(artifact$version, .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION) &&
    identical(artifact$spec_version, .DSVERT_DP_COX_GRID_CROSS_SPEC_VERSION)
  if (is.null(record) || !(cox || .dsvert_dp_staged_grouped_artifact(artifact))) .dsvert_dp_grouped_cross_fail()
  expected <- list(version = .dsvert_dp_staged_grouped_tag(artifact, "-staged-terminal-binding-v1"), capsule_id = contract$capsule_id,
    analysis_id = artifact$analysis_id, batch = -1L,
    semantic_key = .dsvert_dp_glm_grid_cross_key(manifest, artifact, contract),
    artifact_sha256 = .dsvert_joint_dp_hash(artifact), source_contract_sha256 = .dsvert_joint_dp_hash(contract))
  .dsvert_dp_glm_grid_cross_fields(record, c(names(expected), "purpose", "stage_receipt", "stage_plan_digest"))
  .dsvert_dp_glm_grid_cross_equal(record[names(expected)], expected)
  for (field in c("stage_receipt", "stage_plan_digest")) {
    .dsvert_joint_dp_vector_exact_gc_hex(record[[field]], "staged LMM public terminal identity")
    if (identical(record[[field]], strrep("0", 64))) .dsvert_dp_grouped_cross_fail()
  }
  if (!is.character(record$purpose) || length(record$purpose) != 1L || is.na(record$purpose) ||
      !grepl(paste0("^", .dsvert_dp_staged_native_kind(artifact), "-staged-v1/[0-9a-f]{64}$"), record$purpose)) .dsvert_dp_grouped_cross_fail()
  record
}

.dsvert_dp_lmm_cross_compaction_evidence <- function(con, secret, manifest, contract) {
  rows <- DBI::dbGetQuery(con, paste("SELECT record_json, row_mac FROM source_cross_grid_records",
    "WHERE capsule_id = ? AND batch_index < 0"), params = list(contract$capsule_id))
  if (!nrow(rows)) return(invisible(NULL))
  artifacts <- .dsvert_dp_lmm_cross_artifacts(manifest)
  # One small public identity fits the existing 16 KiB retained-receipt budget.
  # Validate before retaining: an arbitrary negative-index private row cannot
  # bypass compaction merely by using the public record's index.
  if (nrow(rows) != 1L || length(artifacts) != 1L ||
      nchar(rows$record_json[[1L]], type = "bytes") > 4096L) .dsvert_dp_grouped_cross_fail()
  record <- .dsvert_dp_capsule_source_record_decode(rows, secret,
    "source_cross_grid_records", "staged LMM public terminal identity")
  .dsvert_dp_lmm_cross_public_record_validate(record, manifest, artifacts[[1L]], contract)
  invisible(NULL)
}

.dsvert_dp_lmm_cross_sampler_binding <- function(policy, secret, manifest, contract) {
  record <- .dsvert_dp_lmm_cross_public_record(policy, secret, manifest, contract)
  if (is.null(record)) return(NULL)
  record[c("stage_receipt", "stage_plan_digest")]
}

.dsvert_dp_lmm_cross_evidence <- function(policy, secret, manifest, contract, analysis_id,
    manifest_sha256, artifact_key) {
  schema <- .dsvert_dp_lmm_cross_signed_schema(policy, secret, manifest_sha256, manifest)
  context <- .dsvert_dp_lmm_cross_source_context(policy, manifest, contract,
    schema, analysis_id)
  if (!policy$peer_name %in% unlist(context$spec$computation_peers, use.names = FALSE)) {
    .dsvert_dp_grouped_cross_fail()
  }
  record <- .dsvert_dp_lmm_cross_public_record(policy, secret, manifest, contract)
  if (is.null(record) || !identical(record$analysis_id, analysis_id)) .dsvert_dp_grouped_cross_fail()
  publication <- .dsvert_dp_synopsis_publication_v1(manifest_sha256, policy, secret)
  released <- publication$release_receipt
  if (!identical(publication$artifact_key, artifact_key) ||
      !identical(released$artifact_key, artifact_key) ||
      !identical(released$source_contract_sha256, context$source_hash)) .dsvert_dp_grouped_cross_fail()
  binding <- list(contract = context$source_contract, analysis_id = analysis_id,
    semantic_key = record$semantic_key, artifact = context$artifact,
    contract_hash = context$source_hash, stage = list(stage_plan_digest = record$stage_plan_digest))
  .dsvert_dp_lmm_cross_public(binding, policy, "published", c(list(
    coordinate_count = context$artifact$coordinate_count, stage_receipt = record$stage_receipt),
    released[c("artifact_key", "execution_id", "final_vector_root", "result_set_sha256")]))
}

.dsvert_dp_lmm_cross_inject <- function(con, secret, manifest, contract, chunk, share, policy) {
  artifacts <- .dsvert_dp_lmm_cross_artifacts(manifest)
  if (!length(artifacts)) return(share)
  if (length(artifacts) != 1L || !is.raw(share) || length(share) != chunk$count * 16L) {
    .dsvert_dp_grouped_cross_fail()
  }
  artifact <- artifacts[[1L]]
  owner <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec$grouping$owner_peer
  .dsvert_dp_staged_cross_inject_artifact(con, secret, manifest, contract,
    chunk, share, policy, artifact, owner)
}

.dsvert_dp_staged_cross_inject_artifact <- function(con, secret, manifest, contract,
    chunk, share, policy, artifact, owner) {
  if (!is.raw(share) || length(share) != chunk$count * 16L) .dsvert_dp_grouped_cross_fail()
  record <- .dsvert_dp_lmm_cross_record(con, secret, manifest, artifact, contract)
  if (is.null(record)) .dsvert_dp_grouped_cross_fail()
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  block <- layout$blocks[[paste("gaussian_models", artifact$analysis_id, sep = "::")]]
  # The admitted owner is the garbler. Non-candidate coordinates receive the public
  # true XOR sharing; candidate bits are copied without opening or combining.
  bits <- rep(as.raw(as.integer(identical(policy$peer_name, owner))), 8L * ceiling(chunk$count / 8))
  if (chunk$count %% 8L) bits[seq.int(chunk$count + 1L, length(bits))] <- as.raw(0)
  first <- max(block$start, chunk$offset + 1L)
  last <- min(block$end, chunk$offset + chunk$count)
  if (first <= last) {
    indices <- seq.int(first - block$start + 1L, last - block$start + 1L)
    target <- seq.int((first - chunk$offset - 1L) * 16L + 1L, length.out = length(indices) * 16L)
    source <- seq.int((first - block$start) * 16L + 1L, length.out = length(target))
    result <- .exact_gc_standard_b64_raw(record$share, 16 * block$length, "staged LMM injection")
    share[target] <- .dsvert_dp_capsule_source_add_ring128(share[target], result[source])
    validity <- rawToBits(.exact_gc_validate_packed_bits(record$validity_share,
      block$length, "staged LMM injection validity"))
    bits[seq.int(first - chunk$offset, last - chunk$offset)] <- validity[indices]
  }
  attr(share, "dsvert_staged_source") <- list(
    validity_share = gsub("[\r\n]", "", jsonlite::base64_enc(packBits(bits, "raw"))),
    stage_receipt = record$stage_receipt, stage_plan_digest = record$stage_plan_digest)
  share
}
