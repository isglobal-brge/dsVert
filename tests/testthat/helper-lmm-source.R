.lmm_transport_fixture <- function(f) {
  artifact <- .dsvert_dp_grouped_cross_workload_artifact(f$contract)
  families <- setNames(rep(list(list(artifacts = list())), 10L), c(
    "admitted_count", "numeric_moments", "numeric_pair_moments", "gaussian_models",
    "fixed_numeric_histograms", "categorical_marginals", "categorical_pairs",
    "correlation_artifacts", "describe_artifacts", "survival_artifacts"))
  families$admitted_count <- list(owner_peer = "peer_a", dataset = "cohort")
  families$survival_artifacts <- list()
  families$gaussian_models$artifacts <- list(grouped = artifact)
  manifest <- list(logical_snapshot = f$contract$spec$logical_snapshot,
    capsule_identity = list(capsule_id = strrep("6", 64)),
    workload = list(coordinate_count = artifact$coordinate_count + 1L,
      families = families, capsule_mechanism = list(source_context_hash = strrep("a", 64))))
  layout <- .dsvert_dp_lmm_cross_transport_layout(manifest, artifact)
  transport <- list(version = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_VERSION,
    purpose = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_PURPOSE,
    capsule_id = manifest$capsule_identity$capsule_id,
    logical_snapshot_sha256 = .dsvert_joint_dp_hash(manifest$logical_snapshot),
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    source_context_hash = manifest$workload$capsule_mechanism$source_context_hash,
    peer_pinset_sha256 = f$policy$peer_pinset_sha256,
    source_peers = artifact$participating_peers,
    designated_noise_peers = artifact$computation_peers,
    coordinate_count = layout$transport_coordinate_count,
    coordinate_order_sha256 = layout$transport_coordinate_order_sha256,
    ring_bits = 128, record_bytes = 16,
    record_encoding = "little_endian_unsigned_fixed_16_bytes",
    chunk_coordinates = 8192, chunk_count = ceiling(layout$transport_coordinate_count / 8192),
    chunk_shape = "fixed_release_prefix_and_capacity_padded_private_slices",
    history_gate = FALSE, ready_for_sampling = FALSE,
    release_coordinate_count = layout$release_coordinate_count,
    release_coordinate_order_sha256 = layout$release_coordinate_order_sha256,
    private_layout_sha256 = layout$transport_coordinate_order_sha256,
    cross_input_peers = artifact$participating_peers,
    private_alignment_consensus = .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING)
  list(artifact = artifact, manifest = manifest, transport = transport, layout = layout)
}

.lmm_handoff_fixture <- function(owners = 2L, family = "lmm", staged_gee = FALSE) {
  f <- .grouped_contract_fixture(family, owners = owners)
  if (family %in% c("binomial_glmm", "poisson_glmm")) {
    f$raw$beta_grid <- f$raw$beta_grid[1:2]
    f$raw$parameters <- list(variance_grid = list(0, .25), quadrature = "gh5_fixed_v1")
    spec <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
    artifact <- .dsvert_dp_grouped_cross_artifact(spec)
    f$contract <- f$sign(list(version = .DSVERT_DP_GROUPED_CROSS_VERSION,
      spec = spec, artifact = artifact,
      source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact)))
  }
  if (staged_gee) {
    f$raw$parameters$composition <- "staged_fixed_rho_v1"
    spec <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
    artifact <- .dsvert_dp_grouped_cross_artifact(spec)
    f$contract <- f$sign(list(version = .DSVERT_DP_GROUPED_CROSS_VERSION,
      spec = spec, artifact = artifact,
      source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact)))
  }
  f$policy$peer_name <- "peer_a"
  f$secret <- as.raw(seq_len(32L))
  f$ss <- new.env(parent = emptyenv())
  f$ss$.exact_gc_peer_binding_digest <- strrep("8", 64)
  f$ss$.exact_gc_transport_initialized <- TRUE
  f$ss$.exact_gc_self_name <- "peer_a"
  f$ss$peer_transport_pks <- list(peer_b = "private-test-transport")
  f$ss$.exact_gc_peer_identity_pks <- list(peer_b = "pinned-test-peer")
  batches <- .dsvert_dp_alignment_mask_batches(f$ss)
  batch <- new.env(parent = emptyenv())
  batch$status <- "complete"
  batch$peer_binding_digest <- f$ss$.exact_gc_peer_binding_digest
  batch$terminal_peer_blob_digest <- strrep("9", 64)
  batch$first_validity_share <- jsonlite::base64_enc(as.raw(1))
  batches$fixture <- batch
  f$contract <- .dsvert_dp_grouped_cross_contract_validate(
    f$contract, f$policy, f$schema)
  context <- .lmm_transport_fixture(f)
  f[names(context)] <- context
  f$source_hash <- .dsvert_joint_dp_hash(f$transport)
  batch$capsule_id <- f$transport$capsule_id
  batch$contract_hash <- f$source_hash
  layout <- f$layout
  route <- layout$blocks[["grouped::peer_a$cluster::value"]]
  presence <- layout$blocks[["grouped::peer_a$cluster::validity"]]
  payload <- numeric(layout$transport_coordinate_count)
  payload[route$start + 0:7] <- c(1, 0, 1, 0, 0, 0, 0, 0)
  payload[presence$start + 0:7] <- c(1, 1, 1, 0, 1, 0, 0, 0)
  f$producer <- structure(list(
    version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
    purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
    capsule_id = f$transport$capsule_id, peer_name = "peer_a",
    logical_snapshot = f$contract$spec$logical_snapshot,
    source_context_hash = strrep("a", 64), coordinate_count = length(payload),
    coordinate_order_sha256 = layout$transport_coordinate_order_sha256, snapshot_binding_sha256 = strrep("c", 64),
    producer_version = .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION,
    state = "internal_incremental_secret_share_input_never_release",
    value_commitment_sha256 = strrep("d", 64), authenticatable_sha256 = strrep("e", 64),
    private_alignment_consensus_hash = strrep("f", 64),
    read_range = function(start, count) payload[seq.int(start, length.out = count)],
    generation_chunks = function(...) list(), reset = function() invisible(NULL)),
    class = c("dsvert_capsule_source_producer", "list"))
  f
}
