# Exact private-alignment gate for cross-owner capsule inputs.
#
# The two designated computation peers hold additive Ring128 value shares and
# one recipient-specific XOR share of every source custodian's SHA-256
# alignment digest. Each fixed-shape circuit reconstructs the digests only
# inside GC, compares all K values, and re-shares either the complete value
# chunk or zero. No digest, mismatch location, gate share, or masked value is
# returned through DSI. After every public chunk has completed, the peers open
# exactly one aggregate terminal outcome: valid, or alignment_contract_invalid.

.DSVERT_DP_ALIGNMENT_MASK_OPERATION <- "alignment-mask-ring128"
.DSVERT_DP_ALIGNMENT_MASK_PRODUCER <- "dp.alignment-mask.source.v1"
.DSVERT_DP_ALIGNMENT_MASK_VERSION <- "dsvert-alignment-mask-batch-v1"
.DSVERT_DP_ALIGNMENT_MASK_TERMINAL_VERSION <-
  "dsvert-alignment-mask-terminal-v1"
.DSVERT_DP_ALIGNMENT_MASK_CONTRACT <-
  "all-k-private-xor-digest-equality-value-or-zero-fixed-shape-v1"

.dsvert_dp_alignment_mask_chunk_size <- function(source_count) {
  source_count <- .exact_gc_alignment_source_count(source_count)
  size <- floor((
    .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS / 128L -
      4L * source_count - 1L) / 3L)
  if (!is.finite(size) || size < 1L) {
    stop("The alignment-mask circuit shape is not representable.",
         call. = FALSE)
  }
  as.integer(min(size, 4096L))
}

.dsvert_dp_alignment_mask_operation_id <- function(
    batch_operation_id, contract_hash, chunk_index, chunk_count) {
  batch_operation_id <- .dsvert_relay_validate_operation_id(
    batch_operation_id)
  contract_hash <- .dsvert_dp_capsule_source_scalar(
    contract_hash, "alignment-mask contract hash", "^[0-9a-f]{64}$", 64L)
  chunk_index <- as.integer(.exact_gc_integer(
    chunk_index, "alignment-mask chunk index", 1, 2^31 - 1))
  chunk_count <- as.integer(.exact_gc_integer(
    chunk_count, "alignment-mask chunk count", 1, 2^31 - 1))
  digest <- digest::digest(charToRaw(paste0(
    "dsVert/alignment-mask/ring128/chunk/v1|", batch_operation_id, "|",
    contract_hash, "|", chunk_index, "|", chunk_count)),
    algo = "sha256", serialize = FALSE)
  paste0("op_", substr(digest, 1L, 32L))
}

.dsvert_dp_alignment_mask_keys <- function(operation_id) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  suffix <- sub("^op_", "", operation_id)
  list(source = paste0("exact_gc_in_", suffix),
       output = paste0("exact_gc_out_", suffix))
}

.dsvert_dp_alignment_mask_batches <- function(ss) {
  if (!is.environment(ss$.dp_alignment_mask_batches)) {
    ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
  }
  ss$.dp_alignment_mask_batches
}

.dsvert_dp_alignment_mask_contract <- function(
    policy, manifest_json, source_contract = NULL) {
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  parsed <- .dsvert_dp_capsule_source_contract_json(
    policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  if (!.dsvert_dp_capsule_source_cross_contract(contract) ||
      !identical(as.numeric(contract$ring_bits), 128) ||
      !policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("The private alignment-mask contract is unavailable.",
         call. = FALSE)
  }
  sources <- .dsvert_dp_capsule_source_names(
    contract$cross_input_peers, "cross-input peer list")
  list(manifest = manifest, contract = contract,
       contract_hash = parsed$contract_hash, sources = sources)
}

.dsvert_dp_alignment_mask_geometry <- function(
    parsed, batch_operation_id, operation_id, chunk_index, chunk_count) {
  k <- length(parsed$sources)
  chunk_size <- .dsvert_dp_alignment_mask_chunk_size(k)
  total <- as.numeric(parsed$contract$coordinate_count)
  expected_count <- ceiling(total / chunk_size)
  chunk_count <- as.integer(.exact_gc_integer(
    chunk_count, "alignment-mask chunk count", 1, 2^31 - 1))
  chunk_index <- as.integer(.exact_gc_integer(
    chunk_index, "alignment-mask chunk index", 1, chunk_count))
  expected_operation <- .dsvert_dp_alignment_mask_operation_id(
    batch_operation_id, parsed$contract_hash, chunk_index, chunk_count)
  if (chunk_count != expected_count ||
      !identical(operation_id, expected_operation)) {
    stop("Invalid private alignment-mask chunk contract.", call. = FALSE)
  }
  offset <- (chunk_index - 1) * chunk_size
  n <- as.integer(min(chunk_size, total - offset))
  list(
    batch_operation_id = batch_operation_id,
    operation_id = operation_id, chunk_index = chunk_index,
    chunk_count = chunk_count, chunk_size = chunk_size,
    offset = as.numeric(offset), n = n, total = total, source_count = k,
    purpose = paste0(
      "dp.alignment-mask.", substr(parsed$contract_hash, 1L, 20L),
      ".c-", chunk_index, "-", chunk_count))
}

.dsvert_dp_alignment_mask_file <- function(ss, batch_operation_id,
                                           create = FALSE) {
  batch_operation_id <- .dsvert_relay_validate_operation_id(
    batch_operation_id)
  root <- file.path(.ensure_session_dir(ss), "alignment_mask")
  path <- file.path(root, paste0(batch_operation_id, ".ring128"))
  if (isTRUE(create)) {
    dir.create(root, recursive = TRUE, showWarnings = FALSE, mode = "0700")
    Sys.chmod(root, mode = "0700")
    if (!file.exists(path)) .exact_gc_private_file(path)
  }
  normalized_root <- normalizePath(root, mustWork = FALSE)
  normalized_path <- normalizePath(path, mustWork = FALSE)
  if (!identical(dirname(normalized_path), normalized_root) ||
      nzchar(Sys.readlink(path))) {
    stop("Unsafe private alignment-mask path.", call. = FALSE)
  }
  if (file.exists(path)) {
    info <- file.info(path)
    if (!isTRUE(info$isdir == FALSE) ||
        bitwAnd(as.integer(info$mode), 63L) != 0L) {
      stop("Unsafe private alignment-mask file.", call. = FALSE)
    }
  }
  path
}

.dsvert_dp_alignment_mask_batch <- function(
    ss, parsed, geometry, session_id, create = FALSE) {
  batches <- .dsvert_dp_alignment_mask_batches(ss)
  batch <- batches[[geometry$batch_operation_id]]
  expected <- list(
    version = .DSVERT_DP_ALIGNMENT_MASK_VERSION,
    session_id = session_id,
    batch_operation_id = geometry$batch_operation_id,
    capsule_id = parsed$contract$capsule_id,
    contract_hash = parsed$contract_hash,
    source_count = geometry$source_count,
    total = geometry$total, chunk_count = geometry$chunk_count,
    chunk_size = geometry$chunk_size,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest)
  if (is.null(batch) && isTRUE(create)) {
    existing_ids <- ls(batches, all.names = TRUE)
    conflicting <- vapply(existing_ids, function(batch_id) {
      candidate <- batches[[batch_id]]
      is.environment(candidate) &&
        identical(candidate$capsule_id, parsed$contract$capsule_id) &&
        identical(candidate$contract_hash, parsed$contract_hash)
    }, logical(1L))
    if (any(conflicting)) {
      stop("A private alignment-mask batch already exists for this contract.",
           call. = FALSE)
    }
    retained <- geometry$total * 16
    if (!is.finite(retained) || retained < 16 || retained > 2^53) {
      stop("The private alignment-mask output is not representable.",
           call. = FALSE)
    }
    .dsvert_resource_admit(ss, retained)
    path <- .dsvert_dp_alignment_mask_file(
      ss, geometry$batch_operation_id, create = TRUE)
    batch <- new.env(parent = emptyenv())
    for (name in names(expected)) batch[[name]] <- expected[[name]]
    batch$path <- path
    batch$status <- "running"
    batch$next_chunk_index <- 1L
    batch$chunk_digests <- character(geometry$chunk_count)
    batch$context_hashes <- character(geometry$chunk_count)
    batch$operation_ids <- character(geometry$chunk_count)
    batch$first_validity_share <- NULL
    batch$terminal_peer_blob_digest <- NULL
    batch$resource_reservation_bytes <- retained
    batches[[geometry$batch_operation_id]] <- batch
  }
  if (!is.environment(batch) || !all(vapply(names(expected), function(name) {
        identical(batch[[name]], expected[[name]])
      }, logical(1L)))) {
    stop("Conflicting private alignment-mask batch retry.", call. = FALSE)
  }
  batch
}

.dsvert_dp_alignment_mask_digest_records <- function(state, sources) {
  shares <- state$private_alignment_consensus_shares
  if (!is.list(shares) || is.null(names(shares)) ||
      !identical(sort(names(shares), method = "radix"),
                 sort(sources, method = "radix"))) {
    stop("The private alignment-share set is incomplete.", call. = FALSE)
  }
  do.call(c, lapply(sources, function(source) {
    value <- tryCatch(.dsvert_relay_b64url_decode(
      shares[[source]], "private alignment consensus share"),
      error = function(error) raw())
    if (!is.raw(value) || length(value) != 32L) {
      stop("The private alignment-share set is invalid.", call. = FALSE)
    }
    # Two fixed 128-bit records. XOR is bytewise, so retaining the raw byte
    # order preserves exact equality under the worker's little-endian decode.
    value
  }))
}

.dsvert_dp_alignment_mask_start_impl <- function(
    manifest_json, batch_operation_id, operation_id,
    chunk_index, chunk_count, session_id,
    .policy = NULL, .secret = NULL, binary = .findMpcBinary(),
    source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  session_id <- .dsvert_relay_validate_session_id(session_id)
  batch_operation_id <- .dsvert_relay_validate_operation_id(
    batch_operation_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  parsed <- .dsvert_dp_alignment_mask_contract(
    .policy, manifest_json, source_contract)
  geometry <- .dsvert_dp_alignment_mask_geometry(
    parsed, batch_operation_id, operation_id, chunk_index, chunk_count)
  ss <- .S(session_id)
  parties <- .exact_gc_vecmul_party_context(ss)
  designated <- .dsvert_dp_capsule_source_names(
    parsed$contract$designated_noise_peers, "noise-peer list")
  if (!setequal(designated, c(parties$self_name, parties$peer_name)) ||
      !identical(parties$self_name, .policy$peer_name)) {
    stop("The alignment-mask exact pair is not the designated pinned pair.",
         call. = FALSE)
  }
  batch <- .dsvert_dp_alignment_mask_batch(
    ss, parsed, geometry, session_id, create = TRUE)
  if (batch$status %in% c("complete", "alignment_contract_invalid")) {
    stop("The private alignment-mask batch is already terminal.",
         call. = FALSE)
  }
  existing <- .exact_gc_operation_state(ss, operation_id, required = FALSE)
  index <- geometry$chunk_index
  if (nzchar(batch$operation_ids[[index]])) {
    if (!identical(batch$operation_ids[[index]], operation_id)) {
      stop("Conflicting private alignment-mask chunk retry.", call. = FALSE)
    }
  } else if (!identical(batch$next_chunk_index, index)) {
    stop("Private alignment-mask chunks must start in canonical order.",
         call. = FALSE)
  }
  keys <- .dsvert_dp_alignment_mask_keys(operation_id)
  if (is.null(existing)) {
    material <- .dsvert_dp_capsule_source_with_store(
      .policy, .secret, function(connection) {
        state <- .dsvert_dp_capsule_source_incoming_load(
          connection, parsed$contract$capsule_id, .secret)
        if (is.null(state) || !isTRUE(state$complete) ||
            !identical(state$contract_hash, parsed$contract_hash) ||
            !identical(state$recipient_name, .policy$peer_name)) {
          stop("The private capsule source is incomplete.", call. = FALSE)
        }
        values <- .dsvert_dp_capsule_source_aggregate_range_in_store(
          connection, parsed$contract, parsed$contract$capsule_id,
          geometry$offset + 1, geometry$n, .secret)
        c(values, .dsvert_dp_alignment_mask_digest_records(
          state, parsed$sources))
      })
    share <- gsub("[\r\n]", "", jsonlite::base64_enc(material))
    .exact_gc_stage_share(
      ss, keys$source, share, 128L, geometry$n,
      .DSVERT_DP_ALIGNMENT_MASK_PRODUCER,
      .DSVERT_DP_ALIGNMENT_MASK_OPERATION, geometry$purpose, 0L,
      "alignment-masked-ring128-share-v1",
      alignment_source_count = geometry$source_count)
  }
  .exact_gc_init_impl(
    ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    keys$source, keys$output, .DSVERT_DP_ALIGNMENT_MASK_OPERATION,
    128L, 0L, geometry$n, geometry$purpose,
    threshold = as.character(geometry$source_count), binary = binary)
}

#' Start one fixed-shape private alignment-mask chunk (AGGREGATE)
#' @param manifest_json Canonical JSON for the built capsule manifest.
#' @param batch_operation_id Identifier shared by all chunks in this alignment
#'   batch.
#' @param operation_id Exact-GC operation identifier derived for this chunk.
#' @param chunk_index One-based public chunk index.
#' @param chunk_count Public total number of chunks in the batch.
#' @param session_id Active exact-GC session identifier.
#' @export
dsvertDPAlignmentMaskStartDS <- function(
    manifest_json, batch_operation_id, operation_id,
    chunk_index, chunk_count, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(policy, manifest_json, secret)
    .dsvert_dp_alignment_mask_start_impl(
      manifest_json, batch_operation_id, operation_id,
      chunk_index, chunk_count, session_id,
      .policy = policy, .secret = secret)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_alignment_mask_cleanup_operation <- function(state) {
  if (is.environment(state) && !is.null(state$spool) &&
      dir.exists(state$spool)) {
    unlink(state$spool, recursive = TRUE)
  }
  if (is.environment(state)) {
    state$spool <- NULL
    state$process <- NULL
    state$worker_heartbeat_key <- raw()
    state$resource_reservation_bytes <- 0
  }
  invisible(NULL)
}

.dsvert_dp_alignment_mask_abort_operation <- function(ss, operation_id) {
  if (!is.environment(ss) ||
      !is.environment(ss$.dp_alignment_mask_batches)) {
    return(invisible(FALSE))
  }
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  changed <- FALSE
  for (batch_id in ls(ss$.dp_alignment_mask_batches, all.names = TRUE)) {
    batch <- ss$.dp_alignment_mask_batches[[batch_id]]
    expected_operations <- if (is.environment(batch) &&
        is.numeric(batch$chunk_count) && length(batch$chunk_count) == 1L &&
        batch$chunk_count >= 1L) {
      vapply(seq_len(batch$chunk_count), function(index) {
        .dsvert_dp_alignment_mask_operation_id(
          batch$batch_operation_id, batch$contract_hash,
          index, batch$chunk_count)
      }, character(1L))
    } else {
      character()
    }
    if (!is.environment(batch) ||
        !operation_id %in% expected_operations ||
        !identical(batch$status, "running")) {
      next
    }
    if (is.character(batch$path) && length(batch$path) == 1L &&
        file.exists(batch$path)) {
      unlink(batch$path)
    }
    batch$status <- "aborted"
    batch$resource_reservation_bytes <- 0
    batch$terminal_outbound <- NULL
    batch$first_validity_share <- NULL
    changed <- TRUE
  }
  invisible(changed)
}

.dsvert_dp_alignment_mask_write <- function(batch, geometry, raw) {
  if (!is.raw(raw) || length(raw) != geometry$n * 16L) {
    stop("The private alignment-mask result has the wrong shape.",
         call. = FALSE)
  }
  expected_offset <- geometry$offset * 16
  info <- file.info(batch$path)
  if (nrow(info) != 1L || is.na(info$size) ||
      as.numeric(info$size) != expected_offset || nzchar(Sys.readlink(batch$path))) {
    stop("The private alignment-mask output file changed.", call. = FALSE)
  }
  connection <- file(batch$path, open = "ab")
  on.exit(close(connection), add = TRUE)
  writeBin(raw, connection)
  flush(connection)
  Sys.chmod(batch$path, mode = "0600")
  invisible(TRUE)
}

.dsvert_dp_alignment_mask_store_impl <- function(
    manifest_json, batch_operation_id, operation_id,
    chunk_index, chunk_count, session_id,
    .policy = NULL, source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  session_id <- .dsvert_relay_validate_session_id(session_id)
  parsed <- .dsvert_dp_alignment_mask_contract(
    .policy, manifest_json, source_contract)
  geometry <- .dsvert_dp_alignment_mask_geometry(
    parsed, batch_operation_id, operation_id, chunk_index, chunk_count)
  ss <- .S(session_id)
  batch <- .dsvert_dp_alignment_mask_batch(
    ss, parsed, geometry, session_id, create = FALSE)
  index <- geometry$chunk_index
  if (nzchar(batch$chunk_digests[[index]])) {
    if (!identical(batch$operation_ids[[index]], operation_id)) {
      stop("Conflicting private alignment-mask chunk retry.", call. = FALSE)
    }
    return(list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
                state = "stored", stored = TRUE,
                chunk_index = index, chunk_count = geometry$chunk_count))
  }
  if (!identical(batch$status, "running") ||
      !identical(batch$next_chunk_index, index)) {
    stop("Private alignment-mask chunks must commit in canonical order.",
         call. = FALSE)
  }
  keys <- .dsvert_dp_alignment_mask_keys(operation_id)
  value <- .exact_gc_consume_output(
    ss, keys$output, operation_id,
    "alignment-masked-ring128-share-v1",
    .DSVERT_DP_ALIGNMENT_MASK_OPERATION, geometry$purpose,
    128L, 0L, geometry$n, .DSVERT_DP_ALIGNMENT_MASK_PRODUCER)
  raw <- .exact_gc_validate_residue_records(
    value$share, 128L, geometry$n, "private alignment-mask result")
  validity <- .exact_gc_standard_b64_raw(
    value$validity_share, 1L, "private alignment-mask validity share")
  if (!as.integer(validity[[1L]]) %in% 0:1) {
    stop("The private alignment-mask validity share is invalid.",
         call. = FALSE)
  }
  .dsvert_dp_alignment_mask_write(batch, geometry, raw)
  batch$chunk_digests[[index]] <- digest::digest(
    raw, algo = "sha256", serialize = FALSE)
  batch$context_hashes[[index]] <- value$context_hash
  batch$operation_ids[[index]] <- operation_id
  if (index == 1L) batch$first_validity_share <- value$validity_share
  batch$next_chunk_index <- as.integer(index + 1L)
  state <- .exact_gc_operation_state(ss, operation_id)
  .dsvert_dp_alignment_mask_cleanup_operation(state)
  .session_progress(ss)
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "stored", stored = TRUE,
       chunk_index = index, chunk_count = geometry$chunk_count)
}

#' Persist one private alignment-mask share chunk (AGGREGATE)
#' @inheritParams dsvertDPAlignmentMaskStartDS
#' @export
dsvertDPAlignmentMaskStoreDS <- function(
    manifest_json, batch_operation_id, operation_id,
    chunk_index, chunk_count, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    .dsvert_dp_alignment_mask_store_impl(
      manifest_json, batch_operation_id, operation_id,
      chunk_index, chunk_count, session_id)
  },
    error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_alignment_mask_terminal_context <- function(
    ss, batch, outbound) {
  parties <- .exact_gc_vecmul_party_context(ss)
  sender <- if (isTRUE(outbound)) parties$self_name else parties$peer_name
  recipient <- if (isTRUE(outbound)) parties$peer_name else parties$self_name
  transcript <- .dsvert_joint_dp_hash(list(
    version = .DSVERT_DP_ALIGNMENT_MASK_VERSION,
    batch_operation_id = batch$batch_operation_id,
    contract_hash = batch$contract_hash,
    operation_ids = as.list(batch$operation_ids),
    context_hashes = as.list(batch$context_hashes)))
  list(
    version = .DSVERT_DP_ALIGNMENT_MASK_TERMINAL_VERSION,
    contract = .DSVERT_DP_ALIGNMENT_MASK_CONTRACT,
    session_id = batch$session_id,
    batch_operation_id = batch$batch_operation_id,
    capsule_id = batch$capsule_id,
    contract_hash = batch$contract_hash,
    peer_binding_digest = batch$peer_binding_digest,
    source_count = batch$source_count,
    coordinate_count = batch$total,
    chunk_count = batch$chunk_count,
    transcript_sha256 = transcript,
    sender_name = sender, recipient_name = recipient,
    terminal_outcome_only = TRUE,
    mismatch_source_exposed = FALSE,
    alignment_digest_exposed = FALSE)
}

.dsvert_dp_alignment_mask_seal_impl <- function(
    manifest_json, batch_operation_id, session_id, .policy = NULL,
    source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  session_id <- .dsvert_relay_validate_session_id(session_id)
  parsed <- .dsvert_dp_alignment_mask_contract(
    .policy, manifest_json, source_contract)
  k <- length(parsed$sources)
  geometry <- list(
    batch_operation_id = .dsvert_relay_validate_operation_id(
      batch_operation_id), source_count = k,
    total = as.numeric(parsed$contract$coordinate_count),
    chunk_size = .dsvert_dp_alignment_mask_chunk_size(k))
  geometry$chunk_count <- as.integer(ceiling(
    geometry$total / geometry$chunk_size))
  ss <- .S(session_id)
  batch <- .dsvert_dp_alignment_mask_batch(
    ss, parsed, geometry, session_id, create = FALSE)
  complete_chunks <- all(nzchar(batch$chunk_digests)) &&
    all(nzchar(batch$context_hashes)) && all(nzchar(batch$operation_ids))
  info <- file.info(batch$path)
  if (!identical(batch$status, "running") || !isTRUE(complete_chunks) ||
      is.null(batch$first_validity_share) || nrow(info) != 1L ||
      is.na(info$size) || as.numeric(info$size) != batch$total * 16) {
    stop("The private alignment-mask transcript is incomplete.",
         call. = FALSE)
  }
  context <- .dsvert_dp_alignment_mask_terminal_context(
    ss, batch, outbound = TRUE)
  binding <- .dsvert_joint_dp_hash(c(
    context, list(validity_share = batch$first_validity_share)))
  if (!is.null(batch$terminal_outbound)) {
    if (!identical(batch$terminal_outbound_binding, binding)) {
      stop("Conflicting private alignment-mask terminal retry.",
           call. = FALSE)
    }
    return(list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
                state = "sealed", peer_blob = batch$terminal_outbound))
  }
  blob <- .exact_gc_checked_mul_seal(
    ss, c(context, list(validity_share = batch$first_validity_share)))
  batch$terminal_outbound <- blob
  batch$terminal_outbound_binding <- binding
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "sealed", peer_blob = blob)
}

#' Seal the one terminal alignment outcome share (AGGREGATE)
#' @inheritParams dsvertDPAlignmentMaskStartDS
#' @export
dsvertDPAlignmentMaskSealDS <- function(
    manifest_json, batch_operation_id, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    .dsvert_dp_alignment_mask_seal_impl(
      manifest_json, batch_operation_id, session_id)
  },
    error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_alignment_mask_terminal_public <- function(batch) {
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    version = .DSVERT_DP_ALIGNMENT_MASK_TERMINAL_VERSION,
    state = batch$status,
    terminal_outcome = batch$status,
    fixed_transcript = TRUE,
    source_count = batch$source_count,
    coordinate_count = batch$total,
    chunk_count = batch$chunk_count,
    alignment_digest_exposed = FALSE,
    mismatch_source_exposed = FALSE,
    gate_share_exposed = FALSE)
}

.dsvert_dp_alignment_mask_receive_impl <- function(
    peer_blob, manifest_json, batch_operation_id, session_id,
    .policy = NULL, source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  session_id <- .dsvert_relay_validate_session_id(session_id)
  parsed <- .dsvert_dp_alignment_mask_contract(
    .policy, manifest_json, source_contract)
  k <- length(parsed$sources)
  geometry <- list(
    batch_operation_id = .dsvert_relay_validate_operation_id(
      batch_operation_id), source_count = k,
    total = as.numeric(parsed$contract$coordinate_count),
    chunk_size = .dsvert_dp_alignment_mask_chunk_size(k))
  geometry$chunk_count <- as.integer(ceiling(
    geometry$total / geometry$chunk_size))
  ss <- .S(session_id)
  batch <- .dsvert_dp_alignment_mask_batch(
    ss, parsed, geometry, session_id, create = FALSE)
  payload_digest <- digest::digest(
    peer_blob, algo = "sha256", serialize = FALSE)
  if (batch$status %in% c("complete", "alignment_contract_invalid")) {
    if (!identical(batch$terminal_peer_blob_digest, payload_digest)) {
      stop("Conflicting private alignment-mask terminal replay.",
           call. = FALSE)
    }
    return(.dsvert_dp_alignment_mask_terminal_public(batch))
  }
  if (!identical(batch$status, "running") ||
      is.null(batch$terminal_outbound)) {
    stop("The private alignment-mask terminal transcript is unavailable.",
         call. = FALSE)
  }
  opened <- .exact_gc_checked_mul_open_peer(ss, peer_blob)
  expected <- .dsvert_dp_alignment_mask_terminal_context(
    ss, batch, outbound = FALSE)
  body <- opened$body
  required <- c(names(expected), "validity_share")
  if (!is.list(body) || !identical(sort(names(body)), sort(required)) ||
      !identical(
        .exact_gc_checked_mul_context_digest(body[names(expected)]),
        .exact_gc_checked_mul_context_digest(expected))) {
    stop("Invalid private alignment-mask terminal context.",
         call. = FALSE)
  }
  peer_identity <- ss$.exact_gc_peer_identity_pks[[expected$sender_name]]
  if (is.null(peer_identity) || !.verify_peer_identity(
      .base64url_to_base64(opened$body_token), peer_identity,
      .base64url_to_base64(opened$signature))) {
    stop("Invalid private alignment-mask terminal signature.",
         call. = FALSE)
  }
  peer_validity <- .exact_gc_standard_b64_raw(
    body$validity_share, 1L, "private peer alignment validity share")
  local_validity <- .exact_gc_standard_b64_raw(
    batch$first_validity_share, 1L,
    "private local alignment validity share")
  if (!as.integer(peer_validity[[1L]]) %in% 0:1 ||
      !as.integer(local_validity[[1L]]) %in% 0:1) {
    stop("Invalid private alignment-mask terminal share.", call. = FALSE)
  }
  valid <- bitwXor(as.integer(peer_validity[[1L]]),
                   as.integer(local_validity[[1L]])) == 1L
  batch$terminal_peer_blob_digest <- payload_digest
  batch$status <- if (isTRUE(valid)) {
    "complete"
  } else {
    "alignment_contract_invalid"
  }
  if (!isTRUE(valid)) {
    if (file.exists(batch$path)) unlink(batch$path)
    batch$resource_reservation_bytes <- 0
  }
  .session_progress(ss)
  .dsvert_dp_alignment_mask_terminal_public(batch)
}

#' Open the one uniform terminal alignment outcome (AGGREGATE)
#' @param peer_blob Opaque authenticated terminal validity share from the peer.
#' @inheritParams dsvertDPAlignmentMaskStartDS
#' @export
dsvertDPAlignmentMaskReceiveDS <- function(
    peer_blob, manifest_json, batch_operation_id, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    .dsvert_dp_alignment_mask_receive_impl(
      peer_blob, manifest_json, batch_operation_id, session_id)
  },
    error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_alignment_mask_complete_batch <- function(
    ss, capsule_id, contract_hash) {
  batches <- .dsvert_dp_alignment_mask_batches(ss)
  candidates <- Filter(function(batch) {
    is.environment(batch) && identical(batch$status, "complete") &&
      identical(batch$capsule_id, capsule_id) &&
      identical(batch$contract_hash, contract_hash)
  }, as.list.environment(batches, all.names = TRUE))
  if (length(candidates) != 1L) {
    stop("The exact private alignment gate is not complete.",
         call. = FALSE)
  }
  candidates[[1L]]
}

.dsvert_dp_alignment_mask_range <- function(
    ss, capsule_id, contract_hash, start, count) {
  batch <- .dsvert_dp_alignment_mask_complete_batch(
    ss, capsule_id, contract_hash)
  start <- .dsvert_dp_capsule_source_index(
    start, "masked aggregate range start", 1, batch$total)
  count <- .dsvert_dp_capsule_source_index(
    count, "masked aggregate range length", 1, batch$total - start + 1)
  connection <- file(batch$path, open = "rb")
  on.exit(close(connection), add = TRUE)
  seek(connection, where = (start - 1) * 16, origin = "start")
  result <- readBin(connection, what = "raw", n = count * 16L)
  if (!is.raw(result) || length(result) != count * 16L) {
    stop("The exact private alignment-mask output is incomplete.",
         call. = FALSE)
  }
  result
}
