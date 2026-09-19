# Internal source handoff for the durable LMM executor. A trusted source loader
# must supply values/validities already verified against its stored source MACs.
# This repacker checks the signed contract, pair and alignment provenance; it
# does not authenticate arbitrary raw block contents or register a source read.
.dsvert_dp_lmm_cross_source_contract <- function(contract, policy, schema_manifest,
                                               source_contract_sha256) {
  contract <- .dsvert_dp_grouped_cross_contract_validate(
    contract, policy, schema_manifest)
  spec <- contract$spec
  if (!identical(spec$family, "lmm") ||
      !is.character(source_contract_sha256) ||
      length(source_contract_sha256) != 1L || is.na(source_contract_sha256) ||
      !grepl("^[0-9a-f]{64}$", source_contract_sha256) ||
      identical(source_contract_sha256, strrep("0", 64))) {
    .dsvert_dp_grouped_cross_fail()
  }
  contract
}

.dsvert_dp_lmm_cross_source_plan <- function(contract, source_contract_sha256) {
  spec <- contract$spec
  caps <- unlist(spec$sensitivity$per_cluster_caps, use.names = FALSE)
  residual <- max(vapply(spec$sensitivity$candidate_bounds, function(bound) {
    max(abs(bound$eta_upper), abs(1 - bound$eta_lower))
  }, numeric(1L)))
  ml <- identical(spec$parameters$objective, "ml")
  variance <- if (ml) spec$parameters$variance_grid[[1L]] else spec$parameters
  plan <- list(version = "dsvert-lmm-staged-source-handoff-v1",
    spec_sha256 = .dsvert_joint_dp_hash(spec),
    source_contract_sha256 = source_contract_sha256,
    profile_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    schema_sha256 = spec$schema_sha256,
    Clusters = spec$grouping$cluster_capacity,
    Slots = spec$grouping$max_patients_per_cluster,
    Predictors = length(spec$predictor_order),
    Numeric = list(Slots = spec$grouping$max_patients_per_cluster,
      GridBits = spec$numeric_grid_bits, ResidualCap = max(1, ceiling(residual)),
      # Signed variances are dyadic q16 values. Binary scaling is exact even
      # above 2^53; decimal strings preserve every integer bit in the Go ABI.
      Sigma2Q64 = sprintf("%.0f", variance$residual_variance * 2^64),
      Tau2Q64 = sprintf("%.0f", variance$random_intercept_variance * 2^64),
      OutputCap = sprintf("%.0f", max(caps))),
    Beta = spec$beta_encoded, Caps = as.list(sprintf("%.0f", caps)))
  if (ml) {
    plan$Objective <- "ml"
    plan$VarianceGrid <- lapply(spec$parameters$variance_grid, function(pair) {
      list(Sigma2Q64 = sprintf("%.0f", pair$residual_variance * 2^64),
        Tau2Q64 = sprintf("%.0f", pair$random_intercept_variance * 2^64))
    })
  }
  plan
}

.dsvert_dp_lmm_cross_source_alignment <- function(spec, policy, ss, capsule_id,
                                                source_contract_sha256) {
  peers <- unlist(spec$computation_peers, use.names = FALSE)
  parties <- .exact_gc_vecmul_party_context(ss)
  if (!policy$peer_name %in% peers ||
      !identical(spec$grouping$owner_peer, peers[[1L]]) ||
      !identical(parties$self_name, policy$peer_name) ||
      !setequal(c(parties$self_name, parties$peer_name), peers)) {
    .dsvert_dp_grouped_cross_fail()
  }
  alignment <- .dsvert_dp_alignment_mask_complete_batch(
    ss, capsule_id, source_contract_sha256)
  if (!identical(alignment$peer_binding_digest, ss$.exact_gc_peer_binding_digest) ||
      !is.character(alignment$terminal_peer_blob_digest) ||
      length(alignment$terminal_peer_blob_digest) != 1L ||
      is.na(alignment$terminal_peer_blob_digest) ||
      !grepl("^[0-9a-f]{64}$", alignment$terminal_peer_blob_digest)) {
    .dsvert_dp_grouped_cross_fail()
  }
  validity <- tryCatch(.exact_gc_standard_b64_raw(alignment$first_validity_share,
    1L, "private LMM source alignment validity"), error = function(error) raw())
  if (length(validity) != 1L || !as.integer(validity) %in% 0:1) {
    .dsvert_dp_grouped_cross_fail()
  }
  alignment
}

.dsvert_dp_lmm_cross_source_handoff <- function(contract, policy, schema_manifest,
    source_contract_sha256, values, validities, ss, capsule_id) {
  contract <- .dsvert_dp_lmm_cross_source_contract(
    contract, policy, schema_manifest, source_contract_sha256)
  spec <- contract$spec
  .dsvert_dp_lmm_cross_source_alignment(
    spec, policy, ss, capsule_id, source_contract_sha256)
  # The authenticated terminal alignment protocol has already opened its
  # global admission bit; status complete means TRUE. Reshare that public
  # admission canonically, so fresh GC output masks cannot change the durable
  # native source binding, including after a unilateral first-bind crash.
  # Private row presence, candidate validity and conversion bits are untouched.
  peers <- unlist(spec$computation_peers, use.names = FALSE)
  ids <- vapply(peers, function(peer)
    .dsvert_relay_peer_id(unname(policy$peer_pinset[[peer]])), character(1L))
  if (anyDuplicated(ids)) .dsvert_dp_grouped_cross_fail()
  garbler <- peers[[order(ids, method = "radix")[[1L]]]]
  validity <- as.raw(as.integer(identical(policy$peer_name, garbler)))
  numeric <- c(unlist(spec$predictor_order, use.names = FALSE), spec$outcome$reference)
  variables <- c(numeric, spec$grouping$reference)
  rows <- spec$grouping$padded_slots
  for (blocks in list(values, validities)) {
    if (!is.list(blocks) || !identical(names(blocks), variables) ||
        !all(vapply(blocks, function(value) is.raw(value) &&
          length(value) == 16 * rows, logical(1L)))) {
      .dsvert_dp_grouped_cross_fail()
    }
  }
  pack <- function(blocks) {
    # Reorder opaque little-endian words only. Local validity shares are never
    # interpreted as presence bits, and no Ring128 share is locally extended.
    words <- vapply(blocks, identity, raw(16 * rows))
    index <- unlist(lapply(seq_len(rows), function(row) {
      unlist(lapply(seq_along(blocks), function(column) {
        (column - 1L) * 16 * rows + (row - 1L) * 16 + seq_len(16L)
      }), use.names = FALSE)
    }), use.names = FALSE)
    bytes <- as.raw(words)[index]
    encode <- function(value) gsub("[\r\n]", "", jsonlite::base64_enc(value))
    # Only the already-public successful alignment admission is reshared.
    list(Share = encode(bytes), Validity = encode(rep(validity, rows * length(blocks))))
  }
  list(plan = .dsvert_dp_lmm_cross_source_plan(contract, source_contract_sha256),
    numeric = pack(values[numeric]),
    metadata = pack(c(validities[numeric],
      values[spec$grouping$reference], validities[spec$grouping$reference])))
}

.dsvert_dp_lmm_cross_route_source_binding <- function(
    context, policy, producer, secret) {
  spec <- context$spec
  owner <- spec$grouping$owner_peer
  layout <- context$layout
  if (!identical(owner, unlist(spec$computation_peers, use.names = FALSE)[[1L]]) ||
      !identical(policy$peer_name, owner) || !identical(producer$peer_name, owner) ||
      !identical(producer$capsule_id,
                 .dsvert_dp_capsule_source_manifest_capsule_id(context$source_contract)) ||
      !identical(producer$logical_snapshot, spec$logical_snapshot) ||
      !identical(producer$source_context_hash, context$source_contract$source_context_hash) ||
      !identical(producer$coordinate_order_sha256, layout$transport_coordinate_order_sha256) ||
      !identical(as.numeric(producer$coordinate_count),
                 as.numeric(layout$transport_coordinate_count))) {
    .dsvert_dp_grouped_cross_fail()
  }
  private <- .dsvert_dp_capsule_source_producer_private(
    secret, producer, context$source_hash, require_commitment = TRUE)
  if (identical(private$alignment_consensus_hash, "not_applicable")) {
    .dsvert_dp_grouped_cross_fail()
  }
  list(spec_sha256 = .dsvert_joint_dp_hash(spec),
    source_contract_sha256 = context$source_hash,
    source_context_sha256 = producer$source_context_hash,
    source_coordinate_order_sha256 = producer$coordinate_order_sha256,
    source_layout_sha256 = .dsvert_joint_dp_hash(layout),
    source_snapshot_mac = private$snapshot_mac,
    source_value_mac = private$value_mac,
    private_alignment_mac = .dsvert_dp_capsule_source_mac(secret,
      "grouped-route-private-alignment-v1", private$alignment_consensus_hash))
}

.dsvert_dp_lmm_cross_route_sidecar <- function(policy, secret, manifest,
    source_contract, schema_manifest, analysis_id, producer) {
  context <- .dsvert_dp_lmm_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  binding <- .dsvert_dp_lmm_cross_route_source_binding(
    context, policy, producer, secret)
  key <- paste(analysis_id, context$spec$grouping$reference, sep = "::")
  routing <- context$layout$blocks[[paste0(key, "::value")]]
  validity <- context$layout$blocks[[paste0(key, "::validity")]]
  # Read the same categorical value/presence blocks used by encrypted source
  # transport. Never recompute a new order from complete-case numeric records.
  labels <- producer$read_range(routing$start, routing$length)
  present <- producer$read_range(validity$start, validity$length)
  if (!is.numeric(labels) || length(labels) != routing$length || anyNA(labels) ||
      any(!is.finite(labels)) || any(labels != floor(labels)) ||
      any(labels < 0 | labels > routing$maximum) ||
      !is.numeric(present) || length(present) != routing$length || anyNA(present) ||
      any(!present %in% c(0, 1))) .dsvert_dp_grouped_cross_fail()
  value <- list(version = "dsvert-lmm-owner-route-source-v1", binding = binding,
    labels = as.list(as.integer(labels)), present = as.list(as.logical(present)))
  value$mac <- .dsvert_dp_capsule_source_mac(secret, "grouped-route-owner-source-v1",
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value)))
  value
}

.dsvert_dp_lmm_cross_route_handoff <- function(sidecar, policy, secret, manifest,
    source_contract, schema_manifest, analysis_id, producer) {
  context <- .dsvert_dp_lmm_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  .dsvert_dp_glm_grid_cross_fields(sidecar,
    c("version", "binding", "labels", "present", "mac"))
  unsigned <- sidecar[setdiff(names(sidecar), "mac")]
  expected_mac <- .dsvert_dp_capsule_source_mac(secret, "grouped-route-owner-source-v1",
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned)))
  if (!identical(sidecar$version, "dsvert-lmm-owner-route-source-v1") ||
      !isTRUE(.dsvert_joint_dp_dsi_hex_equal(sidecar$mac, expected_mac))) {
    .dsvert_dp_grouped_cross_fail()
  }
  .dsvert_dp_glm_grid_cross_equal(sidecar$binding,
    .dsvert_dp_lmm_cross_route_source_binding(
      context, policy, producer, secret))
  # Only the trusted owner-local Go constructor consumes these fields. It
  # computes stable cluster slots, controls, and a private capacity validity.
  # No public receipt contains labels, controls, counts, or a raw label digest.
  sidecar[c("labels", "present")]
}
