# Purpose-bound cross-owner categorical inputs and exact joint-cell shares.
#
# The source custodians contribute only fixed-capacity one-hot/validity arrays
# as encrypted Ring128 shares. Exactly two signed computation peers execute one
# fixed concatenated multiplication, reduce its public segments locally, and
# inject only the resulting table shares into the global vector immediately
# before the sticky joint-DP opening.

.DSVERT_DP_CATEGORICAL_CROSS_ARTIFACT_VERSION <-
  "fixed-domain-categorical-cross-contingency-v1"
.DSVERT_DP_CATEGORICAL_CROSS_PRODUCER <- "dp.categorical-cross.v1"
.DSVERT_DP_CATEGORICAL_CROSS_BIND_VERSION <-
  "dsvert-cross-categorical-exact-binding-v1"
.DSVERT_DP_CATEGORICAL_CROSS_STAGE_VERSION <-
  "dsvert-cross-categorical-exact-stage-v1"
.DSVERT_DP_CATEGORICAL_CROSS_RESULT_VERSION <-
  "dsvert-cross-categorical-result-share-v1"
.DSVERT_DP_CATEGORICAL_CROSS_RECEIPT_VERSION <-
  "dsvert-cross-categorical-result-receipt-v1"

.dsvert_dp_categorical_cross_artifacts <- function(manifest) {
  artifacts <- tryCatch(
    manifest$workload$families$categorical_pairs$cross_artifacts,
    error = function(error) NULL)
  if (!is.list(artifacts)) return(list())
  result <- artifacts[vapply(artifacts, function(artifact) {
    is.list(artifact) && identical(
      artifact$version, .DSVERT_DP_CATEGORICAL_CROSS_ARTIFACT_VERSION)
  }, logical(1L))]
  if (!length(result)) return(list())
  if (is.null(names(result)) || anyNA(names(result)) ||
      any(!nzchar(names(result))) || anyDuplicated(names(result))) {
    stop("The signed cross-owner categorical artifact set is invalid.",
         call. = FALSE)
  }
  result[order(names(result), method = "radix")]
}

.dsvert_dp_categorical_cross_alignment_error <- function() {
  stop(structure(list(
    message = paste(
      "The cross-owner categorical inputs do not have one privately",
      "authenticated ordered PSI alignment manifest."),
    call = NULL,
    reason = "non_prealigned_cross_categorical_cohort"),
    class = c("dsvert_non_prealigned_cohort", "error", "condition")))
}

.dsvert_dp_categorical_cross_result_load <- function(
    connection, capsule_id, analysis_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json, row_mac FROM source_cross_categorical_results",
    "WHERE capsule_id = ? AND analysis_id = ?"),
    params = list(capsule_id, analysis_id))
  if (!nrow(row)) return(NULL)
  .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_cross_categorical_results",
    "cross-owner categorical result")
}

.dsvert_dp_categorical_cross_result_validate <- function(
    record, policy, contract, artifact, block, verifier = NULL) {
  required <- c(
    "version", "status", "capsule_id", "analysis_id", "peer_name",
    "artifact_sha256", "source_contract_hash", "private_layout_sha256",
    "transcript_sha256", "numeric_certificate_sha256",
    "exact_transcript_sha256", "coordinate_count", "release_start",
    "release_end", "release_coordinate_order_sha256", "result_share_b64",
    "result_share_sha256", "receipt_json", "receipt_sha256")
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), required) &&
    identical(record$version, .DSVERT_DP_CATEGORICAL_CROSS_RESULT_VERSION) &&
    identical(record$status, "complete") &&
    identical(record$capsule_id, contract$capsule_id) &&
    identical(record$analysis_id, artifact$analysis_id) &&
    identical(record$peer_name, policy$peer_name) &&
    identical(record$artifact_sha256, .dsvert_joint_dp_hash(artifact)) &&
    identical(record$source_contract_hash, .dsvert_joint_dp_hash(contract)) &&
    identical(record$private_layout_sha256,
              contract$private_layout_sha256) &&
    identical(record$transcript_sha256,
              .dsvert_joint_dp_hash(artifact$transcript)) &&
    identical(record$numeric_certificate_sha256,
              .dsvert_joint_dp_hash(artifact$numeric_certificate)) &&
    grepl("^[0-9a-f]{64}$", record$exact_transcript_sha256) &&
    identical(as.numeric(record$coordinate_count),
              as.numeric(block$length)) &&
    identical(as.numeric(record$release_start), as.numeric(block$start)) &&
    identical(as.numeric(record$release_end), as.numeric(block$end)) &&
    identical(record$release_coordinate_order_sha256,
              contract$release_coordinate_order_sha256) &&
    grepl("^[0-9a-f]{64}$", record$result_share_sha256) &&
    grepl("^[0-9a-f]{64}$", record$receipt_sha256)
  if (!isTRUE(valid)) {
    stop("The persisted cross-owner categorical result contract is invalid.",
         call. = FALSE)
  }
  share <- .dsvert_dp_capsule_source_b64_raw(
    record$result_share_b64, "cross-owner categorical result share",
    block$length * 16L)
  if (!identical(
        digest::digest(share, algo = "sha256", serialize = FALSE),
        record$result_share_sha256) ||
      !identical(digest::digest(
        record$receipt_json, algo = "sha256", serialize = FALSE),
        record$receipt_sha256)) {
    stop("The persisted cross-owner categorical result payload is invalid.",
         call. = FALSE)
  }
  receipt <- .dsvert_dp_capsule_source_decode_json(
    record$receipt_json, "cross-owner categorical result receipt",
    128L * 1024L)
  receipt_required <- c(
    "version", "phase", "capsule_id", "analysis_id", "peer_name",
    "peer_identity_pk", "artifact_sha256", "source_contract_hash",
    "private_layout_sha256", "transcript_sha256",
    "numeric_certificate_sha256", "exact_transcript_sha256",
    "coordinate_count", "release_start", "release_end",
    "release_coordinate_order_sha256", "ring_bits", "frac_bits", "state",
    "fixed_transcript", "result_share_exposed",
    "exact_intermediates_exposed", "alignment_hash_exposed",
    "alignment_hash_exposed_to_relay",
    "alignment_hash_exposed_to_computation_peers", "signature")
  receipt_valid <- is.list(receipt) && !is.null(names(receipt)) &&
    !anyNA(names(receipt)) && !anyDuplicated(names(receipt)) &&
    setequal(names(receipt), receipt_required) &&
    identical(receipt$version,
              .DSVERT_DP_CATEGORICAL_CROSS_RECEIPT_VERSION) &&
    identical(receipt$phase,
              "cross_categorical_result_share_persisted") &&
    identical(receipt$capsule_id, record$capsule_id) &&
    identical(receipt$analysis_id, record$analysis_id) &&
    identical(receipt$peer_name, record$peer_name) &&
    identical(receipt$peer_identity_pk,
              unname(policy$peer_pinset[[policy$peer_name]])) &&
    identical(receipt$artifact_sha256, record$artifact_sha256) &&
    identical(receipt$source_contract_hash, record$source_contract_hash) &&
    identical(receipt$private_layout_sha256,
              record$private_layout_sha256) &&
    identical(receipt$transcript_sha256, record$transcript_sha256) &&
    identical(receipt$numeric_certificate_sha256,
              record$numeric_certificate_sha256) &&
    identical(receipt$exact_transcript_sha256,
              record$exact_transcript_sha256) &&
    identical(as.numeric(receipt$coordinate_count),
              as.numeric(record$coordinate_count)) &&
    identical(as.numeric(receipt$release_start),
              as.numeric(record$release_start)) &&
    identical(as.numeric(receipt$release_end),
              as.numeric(record$release_end)) &&
    identical(receipt$release_coordinate_order_sha256,
              record$release_coordinate_order_sha256) &&
    identical(as.numeric(receipt$ring_bits), 128) &&
    identical(as.numeric(receipt$frac_bits),
              as.numeric(artifact$numeric_certificate$frac_bits)) &&
    identical(receipt$state, "complete") &&
    identical(receipt$fixed_transcript, TRUE) &&
    identical(receipt$result_share_exposed, FALSE) &&
    identical(receipt$exact_intermediates_exposed, FALSE) &&
    identical(receipt$alignment_hash_exposed, FALSE) &&
    identical(receipt$alignment_hash_exposed_to_relay, FALSE) &&
    identical(receipt$alignment_hash_exposed_to_computation_peers, FALSE) &&
    .dsvert_dp_capsule_source_verify(
      receipt, policy, "cross-categorical-result", policy$peer_name,
      verifier)
  if (!isTRUE(receipt_valid)) {
    stop("The persisted cross-owner categorical result receipt is invalid.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_categorical_cross_inject_release_share_internal <- function(
    connection, secret, manifest, contract, chunk, share, policy = NULL,
    verifier = NULL) {
  if (is.null(policy)) policy <- .dsvert_dp_policy()
  if (!is.raw(share) || length(share) != chunk$count * 16L) {
    stop("The cross-owner categorical release injection has the wrong shape.",
         call. = FALSE)
  }
  artifacts <- .dsvert_dp_categorical_cross_artifacts(manifest)
  if (!length(artifacts)) return(share)
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  for (analysis_id in names(artifacts)) {
    block <- layout$blocks[[paste(
      "categorical_pairs", "cross", analysis_id, sep = "::")]]
    record <- .dsvert_dp_categorical_cross_result_load(
      connection, contract$capsule_id, analysis_id, secret)
    if (!is.list(block) || is.null(record)) {
      stop("The cross-owner categorical exact result is incomplete.",
           call. = FALSE)
    }
    record <- .dsvert_dp_categorical_cross_result_validate(
      record, policy, contract, artifacts[[analysis_id]], block, verifier)
    result <- .dsvert_dp_capsule_source_b64_raw(
      record$result_share_b64, "cross-owner categorical result share",
      block$length * 16L)
    global_first <- max(block$start, chunk$offset + 1L)
    global_last <- min(block$end, chunk$offset + chunk$count)
    if (global_first > global_last) next
    count <- global_last - global_first + 1L
    chunk_first <- global_first - chunk$offset
    result_first <- global_first - block$start + 1L
    chunk_bytes <- seq.int(
      (chunk_first - 1L) * 16L + 1L, length.out = count * 16L)
    result_bytes <- seq.int(
      (result_first - 1L) * 16L + 1L, length.out = count * 16L)
    share[chunk_bytes] <- .dsvert_dp_capsule_source_add_ring128(
      share[chunk_bytes], result[result_bytes])
  }
  share
}

.dsvert_dp_categorical_cross_tag <- function(capsule_id, analysis_id) {
  substr(.dsvert_joint_dp_hash(list(
    protocol = "dsvert-cross-categorical-slot-namespace-v1",
    capsule_id = capsule_id, analysis_id = analysis_id)), 1L, 20L)
}

.dsvert_dp_categorical_cross_slot <- function(binding, kind) {
  .exact_gc_vecmul_validate_slot(
    paste0("dp_cat_", binding$tag, "_", kind),
    "cross-owner categorical private slot")
}

.dsvert_dp_categorical_cross_load_inputs <- function(
    policy, secret, manifest, artifact, analysis_id, ss) {
  manifest_json <- .dsvert_dp_canonical_json(manifest)
  parsed <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  if (!identical(
        contract$version,
        .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION) ||
      !policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("The cross-owner categorical computation peer is not authorized.",
         call. = FALSE)
  }
  private_layout <- .dsvert_dp_gaussian_cross_layout(manifest)
  inputs <- list()
  .dsvert_dp_alignment_mask_complete_batch(
    ss, contract$capsule_id, parsed$contract_hash)
  for (side in c("left", "right")) {
    side_inputs <- list()
    for (kind in c("one_hot", "validity")) {
      key <- paste("categorical", analysis_id, side, kind, sep = "::")
      block <- private_layout$blocks[[key]]
      expected <- if (identical(kind, "one_hot")) {
        artifact$transcript$padded_units * length(artifact[[side]]$levels)
      } else {
        artifact$transcript$padded_units
      }
      if (!is.list(block) ||
          !identical(as.numeric(block$length), as.numeric(expected))) {
        stop("The cross-owner categorical private input shape changed.",
             call. = FALSE)
      }
      raw <- .dsvert_dp_alignment_mask_range(
        ss, contract$capsule_id, parsed$contract_hash,
        block$start, block$length)
      encoded <- .dsvert_dp_gaussian_cross_standard_b64(
        raw, "cross-owner categorical masked aggregate share")
      .exact_gc_validate_residue_records(
        encoded, 128L, block$length,
        "cross-owner categorical masked aggregate share")
      side_inputs[[kind]] <- encoded
    }
    inputs[[side]] <- side_inputs
  }
  list(
    contract = contract, contract_hash = parsed$contract_hash,
    private_layout = private_layout, inputs = inputs)
}

.dsvert_dp_categorical_cross_binding_public <- function(
    binding, policy, signer = NULL) {
  unsigned <- list(
    version = .DSVERT_DP_CATEGORICAL_CROSS_BIND_VERSION,
    phase = "cross_categorical_private_inputs_bound",
    capsule_id = binding$capsule_id, analysis_id = binding$analysis_id,
    artifact_sha256 = binding$artifact_sha256,
    source_contract_hash = binding$source_contract_hash,
    private_layout_sha256 = binding$private_layout_sha256,
    transcript_sha256 = binding$transcript_sha256,
    numeric_certificate_sha256 = binding$numeric_certificate_sha256,
    peer_name = policy$peer_name,
    peer_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    padded_units = binding$capacity,
    row_level_count = binding$row_levels,
    column_level_count = binding$column_levels,
    ring_bits = 128L, frac_bits = binding$grid_bits,
    state = if (identical(binding$state, "finalized")) "complete" else "bound",
    source_values_exposed = FALSE, alignment_hash_exposed = FALSE,
    alignment_hash_exposed_to_relay = FALSE,
    alignment_hash_exposed_to_computation_peers = FALSE,
    exact_intermediates_exposed = FALSE, fixed_transcript = TRUE)
  .dsvert_dp_capsule_source_sign(
    unsigned, policy, "cross-categorical-bind", signer)
}

.dsvert_dp_categorical_cross_bind_impl <- function(
    manifest_json, analysis_id, session_id,
    first_opening_json, second_opening_json,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .allocation_observer =
      .dsvert_joint_dp_vector_allocation_observer_require) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner categorical analysis id")
  session_id <- .dsvert_relay_validate_session_id(session_id)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(.policy, manifest)
  artifact <- .dsvert_dp_categorical_cross_artifacts(manifest)[[analysis_id]]
  if (is.null(artifact)) {
    stop("The signed capsule has no cross-owner categorical artifact.",
         call. = FALSE)
  }
  computation <- .dsvert_dp_gaussian_cross_names(
    artifact$computation_peers, "categorical computation-peer list")
  ss <- .S(session_id)
  parties <- .exact_gc_vecmul_party_context(ss)
  if (!setequal(computation, c(parties$self_name, parties$peer_name)) ||
      !identical(parties$self_name, .policy$peer_name)) {
    stop("The exact-GC pinned pair does not match the signed computation peers.",
         call. = FALSE)
  }
  if (is.null(ss$.dp_categorical_cross_bindings)) {
    ss$.dp_categorical_cross_bindings <- list()
  }
  previous <- ss$.dp_categorical_cross_bindings[[analysis_id]]
  artifact_hash <- .dsvert_joint_dp_hash(artifact)
  if (!is.null(previous)) {
    if (!identical(previous$capsule_id, validated$identity$capsule_id) ||
        !identical(previous$artifact_sha256, artifact_hash) ||
        !identical(previous$peer_binding_digest,
                   ss$.exact_gc_peer_binding_digest)) {
      stop("Conflicting cross-owner categorical session binding.",
           call. = FALSE)
    }
    return(.dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_categorical_cross_binding_public(
        previous, .policy, .signer)))
  }
  parsed <- .dsvert_dp_capsule_source_contract_json(.policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  release_block <- validated$layout$blocks[[paste(
    "categorical_pairs", "cross", analysis_id, sep = "::")]]
  if (!is.function(.allocation_observer)) {
    stop("Invalid biomedical capsule allocation observer gate.",
         call. = FALSE)
  }
  .allocation_observer(
    policy = .policy, manifest_json = manifest_json,
    first_opening_json = first_opening_json,
    second_opening_json = second_opening_json,
    secret = .secret, verifier = .verifier)
  prior <- .dsvert_dp_capsule_source_with_store(
    .policy, .secret, function(connection) {
      .dsvert_dp_categorical_cross_result_load(
        connection, contract$capsule_id, analysis_id, .secret)
    })
  base <- list(
    version = .DSVERT_DP_CATEGORICAL_CROSS_BIND_VERSION,
    capsule_id = validated$identity$capsule_id,
    analysis_id = analysis_id, artifact = artifact,
    artifact_sha256 = artifact_hash,
    tag = .dsvert_dp_categorical_cross_tag(
      validated$identity$capsule_id, analysis_id),
    source_contract_hash = parsed$contract_hash,
    private_layout_sha256 = contract$private_layout_sha256,
    transcript_sha256 = .dsvert_joint_dp_hash(artifact$transcript),
    numeric_certificate_sha256 =
      .dsvert_joint_dp_hash(artifact$numeric_certificate),
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    capacity = as.integer(artifact$transcript$padded_units),
    row_levels = as.integer(length(artifact$left$levels)),
    column_levels = as.integer(length(artifact$right$levels)),
    grid_bits = as.integer(artifact$numeric_certificate$frac_bits),
    stage = NULL)
  if (!is.null(prior)) {
    prior <- .dsvert_dp_categorical_cross_result_validate(
      prior, .policy, contract, artifact, release_block, .verifier)
    binding <- c(base, list(
      left_key = "", right_key = "", left_validity_key = "",
      right_validity_key = "", state = "finalized",
      result_exact_transcript_sha256 = prior$exact_transcript_sha256))
    ss$.dp_categorical_cross_bindings[[analysis_id]] <- binding
    return(.dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_categorical_cross_binding_public(
        binding, .policy, .signer)))
  }
  loaded <- .dsvert_dp_categorical_cross_load_inputs(
    .policy, .secret, manifest, artifact, analysis_id, ss)
  binding <- c(base, list(
    left_key = "", right_key = "", left_validity_key = "",
    right_validity_key = "", state = "bound"))
  installed <- character()
  committed <- FALSE
  on.exit(if (!committed) for (key in installed) ss[[key]] <- NULL, add = TRUE)
  for (side in c("left", "right")) {
    one_hot_key <- .dsvert_dp_categorical_cross_slot(
      binding, paste0(side, "_onehot"))
    validity_key <- .dsvert_dp_categorical_cross_slot(
      binding, paste0(side, "_valid"))
    if (!is.null(ss[[one_hot_key]]) || !is.null(ss[[validity_key]])) {
      stop("A cross-owner categorical private input slot is already in use.",
           call. = FALSE)
    }
    ss[[one_hot_key]] <- loaded$inputs[[side]]$one_hot
    ss[[validity_key]] <- loaded$inputs[[side]]$validity
    binding[[paste0(side, "_key")]] <- one_hot_key
    binding[[paste0(side, "_validity_key")]] <- validity_key
    installed <- c(installed, one_hot_key, validity_key)
  }
  binding$state <- "installed"
  ss$.dp_categorical_cross_bindings[[analysis_id]] <- binding
  committed <- TRUE
  .dsvert_dp_capsule_source_encode_json(
    .dsvert_dp_categorical_cross_binding_public(
      binding, .policy, .signer))
}

#' Bind one signed cross-owner categorical private input set (AGGREGATE)
#' @param manifest_json Canonical signed biomedical-capsule manifest.
#' @param analysis_id Signed cross-owner categorical analysis identifier.
#' @param session_id Pinned two-peer exact-computation session identifier.
#' @param first_opening_json,second_opening_json Cross-signed allocation
#'   openings verified before any private aggregate share is loaded.
#' @return A signed, redacted binding receipt.
#' @export
dsvertDPCategoricalCrossBindDS <- function(
    manifest_json, analysis_id, session_id,
    first_opening_json, second_opening_json) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_opening_json <- .dsvert_dsi_text_decode(
      first_opening_json, "first biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_opening_json <- .dsvert_dsi_text_decode(
      second_opening_json, "second biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(policy, manifest_json, secret)
    .dsvert_dp_categorical_cross_bind_impl(
      manifest_json, analysis_id, session_id,
      first_opening_json, second_opening_json,
      .policy = policy, .secret = secret)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_categorical_cross_binding <- function(ss, analysis_id) {
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner categorical analysis id")
  binding <- ss$.dp_categorical_cross_bindings[[analysis_id]]
  if (!is.list(binding) ||
      !binding$state %in% c("installed", "finalized") ||
      !identical(binding$peer_binding_digest,
                 ss$.exact_gc_peer_binding_digest)) {
    stop("The cross-owner categorical private input is not bound.",
         call. = FALSE)
  }
  binding
}

.dsvert_dp_categorical_cross_segment <- function(
    value, level_index, capacity, level_count, what) {
  raw <- .exact_gc_validate_residue_records(
    value, 128L, capacity * level_count, what)
  level_index <- as.integer(.exact_gc_integer(
    level_index, what, 1, level_count))
  first <- (level_index - 1L) * capacity * 16L + 1L
  raw[seq.int(first, length.out = capacity * 16L)]
}

.dsvert_dp_categorical_cross_stage_public <- function(
    binding, record, minted, state) {
  c(minted, list(
    version = .DSVERT_DP_CATEGORICAL_CROSS_STAGE_VERSION,
    state = state, producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
    purpose = record$purpose, capsule_id = binding$capsule_id,
    analysis_id = binding$analysis_id, stage = "cell-products",
    stage_index = 1L, artifact_sha256 = binding$artifact_sha256,
    source_contract_hash = binding$source_contract_hash,
    transcript_sha256 = binding$transcript_sha256,
    numeric_certificate_sha256 = binding$numeric_certificate_sha256,
    exact_intermediates_exposed = FALSE, source_values_exposed = FALSE))
}

.dsvert_dp_categorical_cross_prepare_impl <- function(
    analysis_id, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  binding <- .dsvert_dp_categorical_cross_binding(ss, analysis_id)
  previous <- binding$stage
  if (!is.null(previous)) {
    manifest <- ss$.exact_gc_vecmul_manifests[[previous$manifest_handle]]
    if (!is.list(manifest)) {
      stop("The cross-owner categorical exact-stage manifest disappeared.",
           call. = FALSE)
    }
    .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
    state <- if (.dsvert_dp_gaussian_cross_stage_complete(ss, previous)) {
      "complete"
    } else if (identical(manifest$state, "fresh")) {
      "prepared"
    } else {
      stop("The cross-owner categorical exact stage has an incomplete retry.",
           call. = FALSE)
    }
    return(.dsvert_dp_categorical_cross_stage_public(
      binding, previous, previous$minted, state))
  }
  left <- right <- list()
  cell <- 1L
  for (right_index in seq_len(binding$column_levels)) {
    for (left_index in seq_len(binding$row_levels)) {
      left[[cell]] <- .dsvert_dp_categorical_cross_segment(
        ss[[binding$left_key]], left_index, binding$capacity,
        binding$row_levels, "categorical left one-hot share")
      right[[cell]] <- .dsvert_dp_categorical_cross_segment(
        ss[[binding$right_key]], right_index, binding$capacity,
        binding$column_levels, "categorical right one-hot share")
      cell <- cell + 1L
    }
  }
  x_key <- .dsvert_dp_categorical_cross_slot(binding, "product_x")
  y_key <- .dsvert_dp_categorical_cross_slot(binding, "product_y")
  output_key <- .dsvert_dp_categorical_cross_slot(binding, "products")
  installed <- character()
  installed <- .dsvert_dp_gaussian_cross_install_derived(
    ss, x_key, do.call(c, left),
    binding$capacity * binding$row_levels * binding$column_levels,
    installed)
  installed <- .dsvert_dp_gaussian_cross_install_derived(
    ss, y_key, do.call(c, right),
    binding$capacity * binding$row_levels * binding$column_levels,
    installed)
  if (!is.null(ss[[output_key]])) {
    for (key in installed) ss[[key]] <- NULL
    stop("The cross-owner categorical exact destination is already in use.",
         call. = FALSE)
  }
  total_n <- as.double(binding$capacity) * binding$row_levels *
    binding$column_levels
  if (!is.finite(total_n) || total_n != floor(total_n) ||
      total_n < 1L || total_n > 2^31 - 1) {
    for (key in installed) ss[[key]] <- NULL
    stop(structure(list(
      message = "The cross-owner categorical exact stage is not representable.",
      call = NULL,
      reason = "cross_categorical_exact_stage_shape_unrepresentable"),
      class = c("dsvert_resource_shape_unrepresentable", "error",
                "condition")))
  }
  purpose <- paste0(
    "dp.categorical-cross.", binding$tag, ".cell-products")
  record <- list(
    status = "preparing", producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
    purpose = purpose, x_key = x_key, y_key = y_key,
    output_key = output_key, total_n = as.integer(total_n),
    ring_bits = 128L, frac_bits = binding$grid_bits,
    operand_bound = format(
      2^binding$grid_bits, scientific = FALSE, trim = TRUE),
    installed = installed)
  ss$.dp_categorical_cross_stage <- record
  minted <- tryCatch(.exact_gc_vecmul_mint_manifest(
    ss = ss, session_id = session_id,
    producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
    purpose = purpose, total_n = as.integer(total_n)),
    error = function(error) {
      for (key in installed) ss[[key]] <- NULL
      ss$.dp_categorical_cross_stage <- NULL
      stop(error)
    })
  record$status <- "prepared"
  record$manifest_handle <- minted$manifest_handle
  record$minted <- minted
  binding$stage <- record
  ss$.dp_categorical_cross_stage <- record
  ss$.dp_categorical_cross_bindings[[binding$analysis_id]] <- binding
  .dsvert_dp_categorical_cross_stage_public(
    binding, record, minted, "prepared")
}

#' Prepare the fixed cross-owner categorical multiplication (AGGREGATE)
#' @export
dsvertDPCategoricalCrossPrepareDS <- function(analysis_id, session_id) {
  tryCatch(
    .dsvert_dp_categorical_cross_prepare_impl(analysis_id, session_id),
    error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_categorical_cross_transcript <- function(ss, binding) {
  record <- binding$stage
  if (!.dsvert_dp_gaussian_cross_stage_complete(ss, record)) {
    stop("The fixed cross-owner categorical exact transcript is incomplete.",
         call. = FALSE)
  }
  manifest <- ss$.exact_gc_vecmul_manifests[[record$manifest_handle]]
  .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
  input_stage <- ss$.exact_gc_vecmul_input_stages[[manifest$claimed_batch]]
  list(
    version = "dsvert-cross-categorical-completed-transcript-v1",
    capsule_id = binding$capsule_id, analysis_id = binding$analysis_id,
    peer_binding_digest = binding$peer_binding_digest,
    artifact_sha256 = binding$artifact_sha256,
    stages = list(list(
      stage = "cell-products", stage_index = 1L,
      purpose = record$purpose,
      manifest_context_hash = manifest$context_hash,
      claimed_batch = manifest$claimed_batch,
      claim_context_hash = input_stage$context_hash,
      plan_id = manifest$plan$plan_id, total_n = manifest$total_n,
      ring_bits = manifest$plan$ring_bits,
      frac_bits = manifest$plan$frac_bits,
      backend = manifest$plan$backend)))
}

.dsvert_dp_categorical_cross_finalize_impl <- function(
    manifest_json, analysis_id, session_id,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .reducer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner categorical analysis id")
  session_id <- .dsvert_relay_validate_session_id(session_id)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(.policy, manifest)
  artifact <- .dsvert_dp_categorical_cross_artifacts(manifest)[[analysis_id]]
  parsed <- .dsvert_dp_capsule_source_contract_json(.policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  block <- validated$layout$blocks[[paste(
    "categorical_pairs", "cross", analysis_id, sep = "::")]]
  if (is.null(artifact) || !is.list(block) ||
      !identical(as.numeric(block$length),
                 as.numeric(artifact$coordinate_count)) ||
      !identical(contract$version,
                 .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION) ||
      !.policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("The cross-owner categorical release contract is invalid.",
         call. = FALSE)
  }
  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    prior <- .dsvert_dp_categorical_cross_result_load(
      connection, contract$capsule_id, analysis_id, .secret)
    if (!is.null(prior)) {
      prior <- .dsvert_dp_categorical_cross_result_validate(
        prior, .policy, contract, artifact, block, .verifier)
      return(prior$receipt_json)
    }
    ss <- .S(session_id)
    binding <- .dsvert_dp_categorical_cross_binding(ss, analysis_id)
    certificate <- artifact$numeric_certificate
    if (!identical(binding$capsule_id, contract$capsule_id) ||
        !identical(binding$source_contract_hash, parsed$contract_hash) ||
        !identical(binding$artifact_sha256,
                   .dsvert_joint_dp_hash(artifact)) ||
        !identical(binding$private_layout_sha256,
                   contract$private_layout_sha256) ||
        !isTRUE(certificate$modular_wrap_proved_absent) ||
        !identical(as.numeric(certificate$ring_bits), 128) ||
        !identical(as.numeric(certificate$frac_bits),
                   as.numeric(binding$grid_bits)) ||
        !identical(certificate$overflow_behavior,
                   "typed_abort_before_commit")) {
      stop("The cross-owner categorical numeric binding is invalid.",
           call. = FALSE)
    }
    transcript <- .dsvert_dp_categorical_cross_transcript(ss, binding)
    exact_transcript_hash <- .dsvert_joint_dp_hash(transcript)
    result_share <- .dsvert_dp_gaussian_cross_reduce(
      ss[[binding$stage$output_key]], binding$capacity,
      binding$row_levels * binding$column_levels, .reducer)
    if (length(result_share) != block$length * 16L) {
      stop("The cross-owner categorical result share has the wrong shape.",
           call. = FALSE)
    }
    receipt_unsigned <- list(
      version = .DSVERT_DP_CATEGORICAL_CROSS_RECEIPT_VERSION,
      phase = "cross_categorical_result_share_persisted",
      capsule_id = contract$capsule_id, analysis_id = analysis_id,
      peer_name = .policy$peer_name,
      peer_identity_pk = unname(.policy$peer_pinset[[.policy$peer_name]]),
      artifact_sha256 = binding$artifact_sha256,
      source_contract_hash = parsed$contract_hash,
      private_layout_sha256 = binding$private_layout_sha256,
      transcript_sha256 = binding$transcript_sha256,
      numeric_certificate_sha256 = binding$numeric_certificate_sha256,
      exact_transcript_sha256 = exact_transcript_hash,
      coordinate_count = block$length,
      release_start = block$start, release_end = block$end,
      release_coordinate_order_sha256 =
        contract$release_coordinate_order_sha256,
      ring_bits = 128L, frac_bits = binding$grid_bits,
      state = "complete", fixed_transcript = TRUE,
      result_share_exposed = FALSE, exact_intermediates_exposed = FALSE,
      alignment_hash_exposed = FALSE,
      alignment_hash_exposed_to_relay = FALSE,
      alignment_hash_exposed_to_computation_peers = FALSE)
    receipt_json <- .dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_capsule_source_sign(
        receipt_unsigned, .policy, "cross-categorical-result", .signer))
    record <- list(
      version = .DSVERT_DP_CATEGORICAL_CROSS_RESULT_VERSION,
      status = "complete", capsule_id = contract$capsule_id,
      analysis_id = analysis_id, peer_name = .policy$peer_name,
      artifact_sha256 = binding$artifact_sha256,
      source_contract_hash = parsed$contract_hash,
      private_layout_sha256 = binding$private_layout_sha256,
      transcript_sha256 = binding$transcript_sha256,
      numeric_certificate_sha256 = binding$numeric_certificate_sha256,
      exact_transcript_sha256 = exact_transcript_hash,
      coordinate_count = block$length,
      release_start = block$start, release_end = block$end,
      release_coordinate_order_sha256 =
        contract$release_coordinate_order_sha256,
      result_share_b64 = .dsvert_dp_capsule_source_raw_b64(result_share),
      result_share_sha256 = digest::digest(
        result_share, algo = "sha256", serialize = FALSE),
      receipt_json = receipt_json,
      receipt_sha256 = digest::digest(
        receipt_json, algo = "sha256", serialize = FALSE))
    .dsvert_dp_capsule_source_transaction(connection, {
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_cross_categorical_results",
        c("capsule_id", "analysis_id"),
        list(contract$capsule_id, analysis_id), record, .secret)
    })
    .dsvert_dp_categorical_cross_result_validate(
      record, .policy, contract, artifact, block, .verifier)
    private_keys <- unique(c(
      binding$left_key, binding$right_key,
      binding$left_validity_key, binding$right_validity_key,
      binding$stage$installed, binding$stage$output_key))
    for (key in private_keys[nzchar(private_keys)]) ss[[key]] <- NULL
    binding$state <- "finalized"
    binding$result_exact_transcript_sha256 <- exact_transcript_hash
    ss$.dp_categorical_cross_bindings[[analysis_id]] <- binding
    receipt_json
  })
}

#' Finalize one fixed cross-owner categorical transcript (AGGREGATE)
#' @export
dsvertDPCategoricalCrossFinalizeDS <- function(
    manifest_json, analysis_id, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(policy, manifest_json, secret)
    .dsvert_dp_categorical_cross_finalize_impl(
      manifest_json, analysis_id, session_id,
      .policy = policy, .secret = secret)
  }, error = .dsvert_dp_transcript_stop)
}
