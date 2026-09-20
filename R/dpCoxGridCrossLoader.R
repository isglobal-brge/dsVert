# Private reader for an already authenticated source transport. This does not
# admit a Cox workload or register a remote source/release endpoint.
.dsvert_dp_cox_cross_transport_layout <- function(manifest, artifact) {
  release <- .dsvert_dp_capsule_coordinate_layout(manifest)
  artifacts <- manifest$workload$families$gaussian_models$artifacts
  if (length(artifacts) != 1L || !identical(names(artifacts), artifact$analysis_id) ||
      release$coordinate_count != artifact$coordinate_count + 1L) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  start <- ceiling(release$coordinate_count / 8192) * 8192 + 1
  projection <- .dsvert_dp_cox_cross_source_blocks(artifact, start)
  # Same transport-layout hash domain as the existing source protocol. Cox
  # registration remains closed; this explicit single-Cox projection is local.
  shape <- list(version = .DSVERT_DP_GAUSSIAN_CROSS_LAYOUT_VERSION,
    capsule_id = manifest$capsule_identity$capsule_id,
    release_coordinate_count = as.integer(release$coordinate_count),
    release_coordinate_order_sha256 = release$sha256,
    private_start = as.integer(start),
    padding_coordinates = as.integer(start - release$coordinate_count - 1),
    transport_coordinate_count = as.integer(projection$cursor - 1),
    blocks = projection$blocks, source_peers = artifact$participating_peers,
    computation_peers = artifact$computation_peers,
    padding_rule = "zero_to_next_source_chunk_boundary_v1",
    payload_rule = "manifest_order_capacity_padded_ring128_value_then_validity_no_exact_release_v1")
  shape$transport_coordinate_order_sha256 <- .dsvert_joint_dp_hash(shape)
  shape
}

.dsvert_dp_cox_cross_source_context <- function(policy, manifest,
    source_contract, schema_manifest, analysis_id) {
  source_contract <- .dsvert_dp_capsule_source_contract_validate(source_contract)
  source_hash <- .dsvert_joint_dp_hash(source_contract)
  artifact <- manifest$workload$families$gaussian_models$artifacts[[analysis_id]]
  contract <- .dsvert_dp_cox_grid_cross_contract_validate(
    .dsvert_dp_glm_grid_cross_embedded_contract(artifact),
    policy, schema_manifest)
  spec <- contract$spec
  .dsvert_dp_glm_grid_cross_equal(artifact,
    .dsvert_dp_cox_cross_workload_artifact(contract))
  layout <- .dsvert_dp_cox_cross_transport_layout(manifest, artifact)
  .dsvert_dp_glm_grid_cross_equal(manifest$logical_snapshot, spec$logical_snapshot)
  if (!identical(analysis_id, spec$analysis_id) ||
      !identical(.dsvert_dp_capsule_source_manifest_capsule_id(source_contract),
                 manifest$capsule_identity$capsule_id)) .dsvert_dp_cox_grid_cross_fail()
  expected <- list(version = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_VERSION,
    logical_snapshot_sha256 = .dsvert_joint_dp_hash(spec$logical_snapshot),
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    source_context_hash = manifest$workload$capsule_mechanism$source_context_hash,
    peer_pinset_sha256 = spec$peer_pinset_sha256,
    source_peers = spec$participating_peers,
    designated_noise_peers = spec$computation_peers,
    coordinate_count = layout$transport_coordinate_count,
    coordinate_order_sha256 = layout$transport_coordinate_order_sha256,
    release_coordinate_count = layout$release_coordinate_count,
    release_coordinate_order_sha256 = layout$release_coordinate_order_sha256,
    private_layout_sha256 = layout$transport_coordinate_order_sha256,
    cross_input_peers = spec$participating_peers)
  .dsvert_dp_glm_grid_cross_equal(source_contract[names(expected)], expected)
  list(contract = contract, artifact = artifact, spec = spec, layout = layout,
       source_contract = source_contract, source_hash = source_hash)
}

.dsvert_dp_cox_cross_source_alignment <- function(spec, policy, ss, capsule_id,
                                                source_contract_sha256) {
  peers <- unlist(spec$computation_peers, use.names = FALSE)
  parties <- .exact_gc_vecmul_party_context(ss)
  if (!policy$peer_name %in% peers ||
      !identical(spec$time$owner_peer, peers[[1L]]) ||
      !identical(parties$self_name, policy$peer_name) ||
      !setequal(c(parties$self_name, parties$peer_name), peers)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  # Reuse the staged LMM identity check: names alone do not bind this live
  # transport to the signed source authorities.
  ids <- vapply(peers, function(peer)
    .dsvert_relay_peer_id(unname(policy$peer_pinset[[peer]])), character(1L))
  names(ids) <- peers
  # Only the actual garbler can supply the native private risk-set routing.
  # Provision its identity at the time owner before signing the contract.
  if (anyDuplicated(ids) ||
      !identical(spec$time$owner_peer,
                 peers[[order(ids, method = "radix")[[1L]]]]) ||
      !identical(.dsvert_relay_peer_id(.key_get("identity_pk", ss)),
                 unname(ids[[parties$self_name]])) ||
      !identical(.dsvert_relay_peer_id(ss$.exact_gc_peer_identity_pks[[parties$peer_name]]),
                 unname(ids[[parties$peer_name]]))) .dsvert_dp_cox_grid_cross_fail()
  alignment <- .dsvert_dp_alignment_mask_complete_batch(
    ss, capsule_id, source_contract_sha256)
  if (!identical(alignment$peer_binding_digest, ss$.exact_gc_peer_binding_digest) ||
      !is.character(alignment$terminal_peer_blob_digest) ||
      length(alignment$terminal_peer_blob_digest) != 1L ||
      is.na(alignment$terminal_peer_blob_digest) ||
      !grepl("^[0-9a-f]{64}$", alignment$terminal_peer_blob_digest)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  validity <- tryCatch(.exact_gc_standard_b64_raw(alignment$first_validity_share,
    1L, "private Cox source alignment validity"), error = function(error) raw())
  if (length(validity) != 1L || !as.integer(validity) %in% 0:1) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  alignment
}

# Read authenticated words only; no native handoff until private row composition.
.dsvert_dp_cox_cross_load_inputs <- function(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  contract <- context$contract
  spec <- context$spec
  layout <- context$layout
  source_contract <- context$source_contract
  source_hash <- context$source_hash
  alignment <- .dsvert_dp_cox_cross_source_alignment(spec, policy, ss,
    source_contract$capsule_id, source_hash)
  projection <- switch(alignment$projection_version,
    "fused-grid-digest-v3" = list(source_offset = layout$private_start - 1,
      total = 1, alignment_contract = "all-k-private-xor-digest-equality-fused-grid-v3"),
    "private-suffix-v2" = list(source_offset = layout$private_start - 1,
      total = layout$transport_coordinate_count - layout$private_start + 1,
      alignment_contract = .DSVERT_DP_ALIGNMENT_MASK_PRIVATE_CONTRACT),
    "full-v1" = list(source_offset = 0, total = layout$transport_coordinate_count,
      alignment_contract = .DSVERT_DP_ALIGNMENT_MASK_FULL_CONTRACT),
    .dsvert_dp_cox_grid_cross_fail())
  .dsvert_dp_glm_grid_cross_equal(
    as.list.environment(alignment)[names(projection)], projection)
  variables <- c(unlist(spec$predictor_order, use.names = FALSE),
    spec$event$reference, spec$time$reference)
  loaded <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    .dsvert_dp_capsule_source_transaction(con, {
      state <- .dsvert_dp_capsule_source_incoming_load(
        con, source_contract$capsule_id, secret)
      if (is.null(state) || !isTRUE(state$complete) ||
          !identical(state$capsule_id, source_contract$capsule_id) ||
          !identical(state$contract_hash, source_hash) ||
          !identical(state$recipient_name, policy$peer_name) ||
          state$next_source_index != length(spec$participating_peers) + 1L ||
          state$next_chunk_index != 0) .dsvert_dp_cox_grid_cross_fail()
      .dsvert_dp_alignment_mask_digest_records(state,
        unlist(spec$participating_peers, use.names = FALSE))
      chunks <- seq.int(floor((layout$private_start - 1) / source_contract$chunk_coordinates),
                        source_contract$chunk_count - 1)
      for (index in chunks) {
        record <- .dsvert_dp_capsule_source_aggregate_load(
          con, source_contract$capsule_id, index, secret)
        if (is.null(record) || !identical(record$capsule_id, source_contract$capsule_id) ||
            !identical(record$contract_hash, source_hash) ||
            !identical(record$recipient_name, policy$peer_name) ||
            !identical(as.numeric(record$chunk_index), as.numeric(index))) {
          .dsvert_dp_cox_grid_cross_fail()
        }
      }
      validities <- setNames(vector("list", length(variables)), variables)
      values <- validities[setdiff(variables, spec$time$reference)]
      for (variable in variables) for (kind in
          if (identical(variable, spec$time$reference)) "validity" else c("value", "validity")) {
        block <- layout$blocks[[paste(analysis_id, variable, kind, sep = "::")]]
        raw <- .dsvert_dp_capsule_source_aggregate_range_in_store(con,
          source_contract, source_contract$capsule_id, block$start, block$length, secret)
        if (kind == "value") values[[variable]] <- raw else validities[[variable]] <- raw
      }
      list(values = values, validities = validities)
    })
  })
  # These remain additive row-validity words. They are NOT XOR stage validity
  # or ready-made live/event lanes; the private complete-case stage consumes them.
  list(context = context, values = loaded$values, validities = loaded$validities)
}
