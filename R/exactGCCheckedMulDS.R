# Purpose-specific checked multiplication and exact floor truncation.
# The DSI relay sees only public operation metadata and sealed peer envelopes.

.exact_gc_checked_mul_policy_id <- function(value) {
  value <- .exact_gc_scalar(value, "exact-gc numeric policy id")
  if (!grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid exact-gc numeric policy id.", call. = FALSE)
  }
  value
}

.exact_gc_checked_mul_chunk_operation <- function(
    batch_operation_id, chunk_index, chunk_count, policy_id, plan_id) {
  batch_operation_id <- .dsvert_relay_validate_operation_id(batch_operation_id)
  policy_id <- .exact_gc_checked_mul_policy_id(policy_id)
  plan_id <- .exact_gc_checked_mul_policy_id(plan_id)
  chunk_index <- as.integer(.exact_gc_integer(
    chunk_index, "exact-gc multiplication chunk index", 1,
    .Machine$integer.max))
  chunk_count <- as.integer(.exact_gc_integer(
    chunk_count, "exact-gc multiplication chunk count", 1,
    .Machine$integer.max))
  value <- paste0(
    "dsVert/exact-gc/checked-mul-chunk/v3|", batch_operation_id, "|",
    policy_id, "|", plan_id, "|", chunk_index, "|", chunk_count)
  hash <- digest::digest(
    charToRaw(value), algo = "sha256", serialize = FALSE)
  paste0("op_", substr(hash, 1L, 32L))
}

.exact_gc_checked_mul_keys <- function(operation_id) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  suffix <- sub("^op_", "", operation_id)
  list(
    source = paste0("exact_gc_in_", suffix),
    output = paste0("exact_gc_out_", suffix),
    destination = paste0("k2_exact_vecmul_z_", suffix),
    x = paste0("k2_exact_vecmul_x_", suffix),
    y = paste0("k2_exact_vecmul_y_", suffix))
}

.exact_gc_checked_mul_contract <- function(
    ss, batch_operation_id, operation_id, n, total_n, chunk_index,
    chunk_count, policy_id, plan_id) {
  batch_operation_id <- .dsvert_relay_validate_operation_id(batch_operation_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  policy_id <- .exact_gc_checked_mul_policy_id(policy_id)
  plan_id <- .exact_gc_checked_mul_policy_id(plan_id)
  total_n <- as.integer(.exact_gc_integer(
    total_n, "exact-gc multiplication total length", 1, 2^31 - 1))
  input_stage <- ss$.exact_gc_vecmul_input_stages[[batch_operation_id]]
  .exact_gc_vecmul_require_promoted_stage(input_stage)
  if (is.null(input_stage) || !is.list(input_stage$plan) ||
      !identical(input_stage$plan$plan_id, plan_id) ||
      !identical(input_stage$total_n, total_n) ||
      !identical(input_stage$policy_id, policy_id)) {
    stop("Exact-gc multiplication ticket is unavailable.", call. = FALSE)
  }
  chunk_size <- as.integer(.exact_gc_integer(
    input_stage$plan$max_chunk, "exact-gc planned chunk size", 1, 256))
  expected_count <- as.integer(ceiling(total_n / chunk_size))
  chunk_count <- as.integer(.exact_gc_integer(
    chunk_count, "exact-gc multiplication chunk count", 1, expected_count))
  if (chunk_count != expected_count) {
    stop("Invalid exact-gc multiplication chunk contract.", call. = FALSE)
  }
  chunk_index <- as.integer(.exact_gc_integer(
    chunk_index, "exact-gc multiplication chunk index", 1, chunk_count))
  offset <- as.integer(
    (chunk_index - 1L) * chunk_size)
  expected_n <- as.integer(min(
    chunk_size, total_n - offset))
  n <- as.integer(.exact_gc_integer(
    n, "exact-gc multiplication chunk length", 1,
    chunk_size))
  expected_operation <- .exact_gc_checked_mul_chunk_operation(
    batch_operation_id, chunk_index, chunk_count, policy_id, plan_id)
  if (n != expected_n || !identical(operation_id, expected_operation)) {
    stop("Invalid exact-gc multiplication chunk contract.", call. = FALSE)
  }
  purpose <- paste0(
    .DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE, ".p-", policy_id,
    ".m-", substr(plan_id, 1L, 16L),
    ".c-", chunk_index, "-", chunk_count)
  .exact_gc_validate_purpose(purpose)
  list(
    batch_operation_id = batch_operation_id, operation_id = operation_id,
    n = n, total_n = total_n, chunk_index = chunk_index,
    chunk_count = chunk_count, offset = offset, purpose = purpose,
    policy_id = policy_id, plan_id = plan_id, plan = input_stage$plan,
    chunk_size = chunk_size,
    ring_bits = as.integer(input_stage$plan$ring_bits),
    frac_bits = as.integer(input_stage$plan$frac_bits))
}

.exact_gc_checked_mul_input_stage <- function(ss, contract) {
  stage <- ss$.exact_gc_vecmul_input_stages[[contract$batch_operation_id]]
  if (is.null(stage) ||
      !stage$state %in% c("staged", "inputs-consumed", "complete") ||
      !identical(stage$total_n, contract$total_n) ||
      !identical(stage$policy_id, contract$policy_id) ||
      !identical(stage$plan$plan_id, contract$plan_id) ||
      !is.character(stage$context_hash) ||
      !grepl("^[0-9a-f]{64}$", stage$context_hash)) {
    stop("Exact-gc multiplication ticket is unavailable.", call. = FALSE)
  }
  stage
}

.exact_gc_checked_mul_slice <- function(value, ring_bits, total_n, offset, n,
                                        what) {
  records <- .exact_gc_validate_residue_records(
    value, ring_bits, total_n, what)
  record_bytes <- .exact_gc_record_bytes(ring_bits)
  first <- record_bytes * offset + 1L
  records[seq.int(first, length.out = record_bytes * n)]
}

.exact_gc_checked_mul_start_impl <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id, binary = .findMpcBinary()) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  contract <- .exact_gc_checked_mul_contract(
    ss, batch_operation_id, operation_id, n, total_n, chunk_index,
    chunk_count, policy_id, plan_id)
  input_stage <- .exact_gc_checked_mul_input_stage(ss, contract)
  batch_keys <- .exact_gc_checked_mul_keys(batch_operation_id)
  keys <- .exact_gc_checked_mul_keys(operation_id)
  x_share <- ss[[batch_keys$x]]
  y_share <- ss[[batch_keys$y]]
  if (is.null(x_share) || is.null(y_share)) {
    stop("Exact-gc multiplication inputs are unavailable.", call. = FALSE)
  }
  x_chunk <- .exact_gc_checked_mul_slice(
    x_share, contract$ring_bits, contract$total_n, contract$offset, contract$n,
    "exact-gc multiplication x share")
  y_chunk <- .exact_gc_checked_mul_slice(
    y_share, contract$ring_bits, contract$total_n, contract$offset, contract$n,
    "exact-gc multiplication y share")
  source_share <- gsub("[\r\n]", "", jsonlite::base64_enc(c(x_chunk, y_chunk)))
  .exact_gc_stage_share(
    ss, keys$source, source_share, contract$ring_bits, contract$n,
    .DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER, "mul-truncate-checked",
    contract$purpose, contract$frac_bits, "checked-ring-share")
  if (is.null(ss$.exact_gc_checked_mul_stages)) {
    ss$.exact_gc_checked_mul_stages <- list()
  }
  stage_binding <- list(
    contract = contract, input_context_hash = input_stage$context_hash,
    source_digest = digest::digest(
      source_share, algo = "sha256", serialize = FALSE))
  previous <- ss$.exact_gc_checked_mul_stages[[operation_id]]
  if (!is.null(previous) && !identical(previous, stage_binding)) {
    stop("Conflicting exact-gc multiplication retry.", call. = FALSE)
  }
  ss$.exact_gc_checked_mul_stages[[operation_id]] <- stage_binding
  result <- .exact_gc_init_impl(
    ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    keys$source, keys$output, "mul-truncate-checked",
    contract$ring_bits, contract$frac_bits,
    contract$n, contract$purpose, mul_plan = contract$plan, binary = binary)
  result
}

#' Start a purpose-specific checked Ring127 multiplication (AGGREGATE)
#'
#' @param n Number of vector elements in this chunk.
#' @param total_n Total number of elements in the multiplication batch.
#' @param chunk_index One-based public chunk index.
#' @param chunk_count Public total number of chunks in the batch.
#' @param batch_operation_id Identifier for the complete multiplication batch.
#' @param session_id Active exact-GC session identifier.
#' @param operation_id Exact-GC operation identifier derived for this chunk.
#' @param policy_id SHA-256 identifier of the active numeric policy.
#' @param plan_id SHA-256 identifier of the server-derived multiplication plan.
#' @export
exactGCVecmulStartDS <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id) {
  tryCatch(
    .exact_gc_checked_mul_start_impl(
      n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
      operation_id, policy_id, plan_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}

.exact_gc_checked_mul_peer_context <- function(
    ss, session_id, contract, result_context_hash, outbound) {
  parties <- .exact_gc_vecmul_party_context(ss)
  self_peer_id <- .dsvert_relay_peer_id(.key_get("identity_pk", ss))
  peer_peer_id <- .dsvert_relay_peer_id(
    ss$.exact_gc_peer_identity_pks[[parties$peer_name]])
  input_stage <- .exact_gc_checked_mul_input_stage(ss, contract)
  list(
    version = "dsvert-exact-gc-checked-mul-validity-v3",
    session_id = .dsvert_relay_validate_session_id(session_id),
    batch_operation_id = contract$batch_operation_id,
    operation_id = contract$operation_id, purpose = contract$purpose,
    producer = .DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER,
    numeric_policy_id = contract$policy_id, plan_id = contract$plan_id,
    mul_backend = contract$plan$backend,
    bound_x = contract$plan$bound_x, bound_y = contract$plan$bound_y,
    ring_bits = contract$ring_bits, frac_bits = contract$frac_bits,
    vector_len = contract$n,
    total_n = contract$total_n, chunk_index = contract$chunk_index,
    chunk_count = contract$chunk_count, offset = contract$offset,
    input_context_hash = input_stage$context_hash,
    result_context_hash = result_context_hash,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    sender_name = if (isTRUE(outbound)) parties$self_name else parties$peer_name,
    recipient_name = if (isTRUE(outbound)) parties$peer_name else parties$self_name,
    sender_peer_id = if (isTRUE(outbound)) self_peer_id else peer_peer_id,
    recipient_peer_id = if (isTRUE(outbound)) peer_peer_id else self_peer_id)
}

.exact_gc_checked_mul_context_digest <- function(value) {
  encoded <- charToRaw(as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", digits = NA)))
  digest::digest(encoded, algo = "sha256", serialize = FALSE)
}

.exact_gc_checked_mul_seal <- function(ss, body) {
  body_raw <- charToRaw(as.character(jsonlite::toJSON(
    body, auto_unbox = TRUE, null = "null", digits = NA)))
  body_b64url <- .exact_gc_b64url_encode(body_raw)
  identity <- .get_identity_keypair()
  if (!identical(identity$identity_pk, .key_get("identity_pk", ss))) {
    stop("Exact-gc identity changed during multiplication.", call. = FALSE)
  }
  signature <- .sign_transport_pk(
    .base64url_to_base64(body_b64url), identity$identity_sk)
  envelope <- charToRaw(as.character(jsonlite::toJSON(list(
    body = body_b64url, signature = base64_to_base64url(signature)),
    auto_unbox = TRUE)))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = gsub("[\r\n]", "", jsonlite::base64_enc(envelope)),
    recipient_pk = unname(ss$peer_transport_pks[[1L]])))
  base64_to_base64url(sealed$sealed)
}

.exact_gc_checked_mul_validity_impl <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  contract <- .exact_gc_checked_mul_contract(
    ss, batch_operation_id, operation_id, n, total_n, chunk_index,
    chunk_count, policy_id, plan_id)
  keys <- .exact_gc_checked_mul_keys(operation_id)
  state <- .exact_gc_operation_state(ss, operation_id)
  .exact_gc_refresh(ss, state)
  output <- ss$.exact_gc_outputs[[keys$output]]
  if (is.null(output) || !identical(state$status, "complete") ||
      !identical(output$kind, "checked-ring-share") ||
      !identical(output$operation, "mul-truncate-checked") ||
      !identical(output$purpose, contract$purpose) ||
      !identical(output$vector_len, contract$n) ||
      !is.character(output$validity_share)) {
    stop("Exact-gc multiplication result is unavailable.", call. = FALSE)
  }
  context <- .exact_gc_checked_mul_peer_context(
    ss, session_id, contract, output$context_hash, outbound = TRUE)
  if (is.null(ss$.exact_gc_checked_mul_validity_out)) {
    ss$.exact_gc_checked_mul_validity_out <- list()
  }
  binding <- list(
    context_digest = .exact_gc_checked_mul_context_digest(context),
    validity_digest = digest::digest(
      output$validity_share, algo = "sha256", serialize = FALSE))
  previous <- ss$.exact_gc_checked_mul_validity_out[[operation_id]]
  if (!is.null(previous)) {
    if (!identical(previous$binding, binding)) {
      stop("Conflicting exact-gc validity retry.", call. = FALSE)
    }
    return(list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
                state = "sealed", peer_blob = previous$peer_blob))
  }
  peer_blob <- .exact_gc_checked_mul_seal(
    ss, c(context, list(validity_share = output$validity_share)))
  ss$.exact_gc_checked_mul_validity_out[[operation_id]] <- list(
    binding = binding, peer_blob = peer_blob)
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "sealed", peer_blob = peer_blob)
}

#' Seal this peer's checked-multiplication validity share (AGGREGATE)
#'
#' @inheritParams exactGCVecmulStartDS
#' @export
exactGCVecmulValidityDS <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id) {
  tryCatch(
    .exact_gc_checked_mul_validity_impl(
      n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
      operation_id, policy_id, plan_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}

.exact_gc_checked_mul_open_peer <- function(ss, peer_blob) {
  raw_blob <- .exact_gc_b64url_decode(
    peer_blob, "exact-gc multiplication validity envelope", 1024^2)
  decrypted <- .callMpcTool("transport-decrypt", list(
    sealed = gsub("[\r\n]", "", jsonlite::base64_enc(raw_blob)),
    recipient_sk = .key_get("transport_sk", ss)))
  envelope <- tryCatch(jsonlite::fromJSON(
    rawToChar(jsonlite::base64_dec(decrypted$data)), simplifyVector = FALSE),
    error = function(e) NULL)
  if (!is.list(envelope) ||
      !identical(sort(names(envelope)), c("body", "signature"))) {
    stop("Invalid exact-gc multiplication validity envelope.", call. = FALSE)
  }
  body_raw <- .exact_gc_b64url_decode(
    envelope$body, "exact-gc multiplication validity body", 512 * 1024)
  body <- tryCatch(jsonlite::fromJSON(
    rawToChar(body_raw), simplifyVector = FALSE), error = function(e) NULL)
  list(body = body, body_token = envelope$body,
       signature = envelope$signature)
}

.exact_gc_checked_mul_validity_receive_impl <- function(
    peer_blob, n, total_n, chunk_index, chunk_count, batch_operation_id,
    session_id, operation_id, policy_id, plan_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  contract <- .exact_gc_checked_mul_contract(
    ss, batch_operation_id, operation_id, n, total_n, chunk_index,
    chunk_count, policy_id, plan_id)
  keys <- .exact_gc_checked_mul_keys(operation_id)
  output <- ss$.exact_gc_outputs[[keys$output]]
  outbound <- ss$.exact_gc_checked_mul_validity_out[[operation_id]]
  if (is.null(output) || is.null(outbound) ||
      !identical(output$kind, "checked-ring-share")) {
    stop("Exact-gc multiplication validity context is unavailable.",
         call. = FALSE)
  }
  expected <- .exact_gc_checked_mul_peer_context(
    ss, session_id, contract, output$context_hash, outbound = FALSE)
  opened <- .exact_gc_checked_mul_open_peer(ss, peer_blob)
  body <- opened$body
  required <- c(names(expected), "validity_share")
  if (!is.list(body) || !identical(sort(names(body)), sort(required))) {
    stop("Invalid exact-gc multiplication validity context.", call. = FALSE)
  }
  peer_context <- body[names(expected)]
  if (!identical(.exact_gc_checked_mul_context_digest(peer_context),
                 .exact_gc_checked_mul_context_digest(expected))) {
    stop("Invalid exact-gc multiplication validity context.", call. = FALSE)
  }
  peer_identity <- ss$.exact_gc_peer_identity_pks[[expected$sender_name]]
  if (is.null(peer_identity) || !.verify_peer_identity(
      .base64url_to_base64(opened$body_token), peer_identity,
      .base64url_to_base64(opened$signature))) {
    stop("Invalid exact-gc multiplication validity signature.", call. = FALSE)
  }
  peer_validity <- .exact_gc_standard_b64_raw(
    body$validity_share, 1L, "exact-gc peer validity share")
  local_validity <- .exact_gc_standard_b64_raw(
    output$validity_share, 1L, "exact-gc local validity share")
  if (!as.integer(peer_validity[[1L]]) %in% 0:1 ||
      !as.integer(local_validity[[1L]]) %in% 0:1) {
    stop("Invalid exact-gc multiplication validity share.", call. = FALSE)
  }
  valid <- bitwXor(as.integer(peer_validity[[1L]]),
                   as.integer(local_validity[[1L]])) == 1L
  payload_digest <- digest::digest(
    peer_blob, algo = "sha256", serialize = FALSE)
  if (is.null(ss$.exact_gc_checked_mul_validity)) {
    ss$.exact_gc_checked_mul_validity <- list()
  }
  previous <- ss$.exact_gc_checked_mul_validity[[operation_id]]
  binding <- list(
    payload_digest = payload_digest,
    context_digest = .exact_gc_checked_mul_context_digest(expected),
    valid = valid,
    failure_code = if (valid) "" else "bound_exceeded")
  if (!is.null(previous) && !identical(previous, binding)) {
    stop("Conflicting exact-gc multiplication validity retry.",
         call. = FALSE)
  }
  ss$.exact_gc_checked_mul_validity[[operation_id]] <- binding
  if (!isTRUE(valid)) {
    ss$.exact_gc_outputs[[keys$output]] <- NULL
  }
  # Deliberately identical for valid and invalid arithmetic. The relay learns
  # only whether the authenticated protocol itself completed.
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "checked", stored = TRUE)
}

#' Receive the peer-only validity share for checked multiplication (AGGREGATE)
#'
#' @param peer_blob Opaque authenticated validity share from the peer.
#' @inheritParams exactGCVecmulStartDS
#' @export
exactGCVecmulValidityReceiveDS <- function(
    peer_blob, n, total_n, chunk_index, chunk_count, batch_operation_id,
    session_id, operation_id, policy_id, plan_id) {
  tryCatch(
    .exact_gc_checked_mul_validity_receive_impl(
      peer_blob, n, total_n, chunk_index, chunk_count, batch_operation_id,
      session_id, operation_id, policy_id, plan_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}

.exact_gc_checked_mul_cleanup_spool <- function(state) {
  if (!is.null(state$spool) && dir.exists(state$spool)) {
    unlink(state$spool, recursive = TRUE)
  }
  state$spool <- NULL
  state$process <- NULL
  invisible(NULL)
}

.exact_gc_checked_mul_abort_batch <- function(ss, operation_id, state = NULL) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  stage_binding <- if (is.null(ss$.exact_gc_checked_mul_stages)) NULL else
    ss$.exact_gc_checked_mul_stages[[operation_id]]
  batch_operation_id <- if (!is.null(stage_binding)) {
    stage_binding$contract$batch_operation_id
  } else if (!is.null(ss$.exact_gc_vecmul_input_stages[[operation_id]])) {
    operation_id
  } else {
    NULL
  }
  if (is.null(batch_operation_id)) {
    if (!is.null(state)) {
      .exact_gc_abort_state(
        ss, state, release_source = FALSE, abort_complete = TRUE)
      if (!is.null(ss$.exact_gc_inputs)) {
        ss$.exact_gc_inputs[[state$source_key]] <- NULL
      }
    }
    return(invisible(TRUE))
  }

  input_stage <- ss$.exact_gc_vecmul_input_stages[[batch_operation_id]]
  if (is.null(input_stage)) return(invisible(TRUE))
  if (identical(input_stage$state, "complete")) {
    current_digest <- .exact_gc_vecmul_value_digest(
      ss[[input_stage$output_key]])
    if (!identical(input_stage$output_previous_digest, "absent") ||
        !is.character(input_stage$output_digest) ||
        length(input_stage$output_digest) != 1L ||
        !identical(current_digest, input_stage$output_digest)) {
      stop("Exact-gc completed destination changed before rollback.",
           call. = FALSE)
    }
    ss[[input_stage$output_key]] <- NULL
  }

  operation_ids <- character(0)
  if (!is.null(ss$.exact_gc_checked_mul_stages)) {
    operation_ids <- names(Filter(function(value) {
      is.list(value) && is.list(value$contract) &&
        identical(value$contract$batch_operation_id, batch_operation_id)
    }, ss$.exact_gc_checked_mul_stages))
  }
  for (id in operation_ids) {
    operation_state <- .exact_gc_operation_state(ss, id, required = FALSE)
    if (!is.null(operation_state)) {
      .exact_gc_abort_state(
        ss, operation_state, release_source = FALSE, abort_complete = TRUE)
      if (!is.null(ss$.exact_gc_inputs)) {
        ss$.exact_gc_inputs[[operation_state$source_key]] <- NULL
      }
    }
    if (!is.null(ss$.exact_gc_checked_mul_stages)) {
      ss$.exact_gc_checked_mul_stages[[id]] <- NULL
    }
    if (!is.null(ss$.exact_gc_checked_mul_validity_out)) {
      ss$.exact_gc_checked_mul_validity_out[[id]] <- NULL
    }
    if (!is.null(ss$.exact_gc_checked_mul_validity)) {
      ss$.exact_gc_checked_mul_validity[[id]] <- NULL
    }
    if (!is.null(ss$.exact_gc_checked_mul_commits)) {
      ss$.exact_gc_checked_mul_commits[[id]] <- NULL
    }
  }
  if (!is.null(ss$.exact_gc_checked_mul_chunks)) {
    ss$.exact_gc_checked_mul_chunks[[batch_operation_id]] <- NULL
  }
  batch_keys <- .exact_gc_checked_mul_keys(batch_operation_id)
  ss[[batch_keys$x]] <- NULL
  ss[[batch_keys$y]] <- NULL
  if (!is.null(input_stage$manifest_handle) &&
      !is.null(ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]])) {
    manifest <- ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]]
    .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
    if (identical(manifest$state, "claimed") &&
        identical(manifest$claimed_batch, batch_operation_id)) {
      manifest$state <- "aborted"
      manifest$mac <- .exact_gc_vecmul_manifest_mac(ss, manifest)
      ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]] <- manifest
    }
  }
  ss$.exact_gc_vecmul_input_stages[[batch_operation_id]] <- list(
    state = "aborted", session_id = input_stage$session_id,
    batch_operation_id = batch_operation_id,
    purpose = input_stage$purpose, policy_id = input_stage$policy_id,
    producer = input_stage$producer,
    manifest_handle = input_stage$manifest_handle,
    plan = input_stage$plan,
    output_key = input_stage$output_key, total_n = input_stage$total_n,
    context_hash = input_stage$context_hash,
    output_previous_digest = input_stage$output_previous_digest)
  invisible(TRUE)
}

.exact_gc_checked_mul_commit_impl <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  contract <- .exact_gc_checked_mul_contract(
    ss, batch_operation_id, operation_id, n, total_n, chunk_index,
    chunk_count, policy_id, plan_id)
  keys <- .exact_gc_checked_mul_keys(operation_id)
  input_stage <- .exact_gc_checked_mul_input_stage(ss, contract)
  validation <- ss$.exact_gc_checked_mul_validity[[operation_id]]
  if (is.null(validation) || !isTRUE(validation$valid)) {
    state <- .exact_gc_operation_state(ss, operation_id, required = FALSE)
    if (!is.null(state)) .exact_gc_checked_mul_cleanup_spool(state)
    stop("Checked multiplication was not bilaterally validated.",
         call. = FALSE)
  }
  if (is.null(ss$.exact_gc_checked_mul_commits)) {
    ss$.exact_gc_checked_mul_commits <- list()
  }
  previous <- ss$.exact_gc_checked_mul_commits[[operation_id]]
  if (!is.null(previous)) {
    complete <- identical(input_stage$state, "complete") &&
      identical(.exact_gc_vecmul_value_digest(
        ss[[input_stage$output_key]]), input_stage$output_digest)
    return(list(
      capability_id = .DSVERT_EXACT_GC_CAPABILITY, stored = TRUE,
      state = if (isTRUE(complete)) "committed" else "partial"))
  }
  if (contract$chunk_index == contract$chunk_count &&
      !identical(.exact_gc_vecmul_value_digest(
        ss[[input_stage$output_key]]), input_stage$output_previous_digest)) {
    stop("Exact-gc multiplication destination changed.", call. = FALSE)
  }
  value <- .exact_gc_consume_output(
    ss, keys$output, operation_id, "checked-ring-share",
    "mul-truncate-checked", contract$purpose,
    contract$ring_bits, contract$frac_bits, contract$n,
    .DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER)
  .exact_gc_validate_residue_records(
    value$share, contract$ring_bits, contract$n,
    "exact-gc multiplication result share")
  chunk_digest <- digest::digest(
    value$share, algo = "sha256", serialize = FALSE)
  if (is.null(ss$.exact_gc_checked_mul_chunks)) {
    ss$.exact_gc_checked_mul_chunks <- list()
  }
  chunks <- ss$.exact_gc_checked_mul_chunks[[contract$batch_operation_id]]
  if (is.null(chunks)) chunks <- list()
  index <- as.character(contract$chunk_index)
  if (!is.null(chunks[[index]])) {
    stop("Exact-gc multiplication chunk was already committed.",
         call. = FALSE)
  }
  chunks[[index]] <- list(
    share = value$share, digest = chunk_digest, contract = contract)
  ss$.exact_gc_checked_mul_chunks[[contract$batch_operation_id]] <- chunks
  ss$.exact_gc_checked_mul_commits[[operation_id]] <- list(
    digest = chunk_digest, contract = contract)
  .exact_gc_checked_mul_cleanup_spool(
    .exact_gc_operation_state(ss, operation_id))

  state <- "partial"
  if (length(chunks) == contract$chunk_count) {
    ordered <- lapply(seq_len(contract$chunk_count), function(i) {
      chunk <- chunks[[as.character(i)]]
      if (is.null(chunk) || !identical(chunk$contract$chunk_index,
                                        as.integer(i)) ||
          !identical(chunk$contract$batch_operation_id,
                     contract$batch_operation_id) ||
          !identical(chunk$contract$policy_id, contract$policy_id) ||
          !identical(chunk$contract$plan_id, contract$plan_id)) {
        stop("Exact-gc multiplication batch is incomplete.", call. = FALSE)
      }
      .exact_gc_validate_residue_records(
        chunk$share, contract$ring_bits, chunk$contract$n,
        "exact-gc multiplication chunk share")
    })
    combined_raw <- do.call(c, ordered)
    if (length(combined_raw) !=
        .exact_gc_record_bytes(contract$ring_bits) * contract$total_n) {
      stop("Exact-gc multiplication batch has the wrong shape.",
           call. = FALSE)
    }
    if (!identical(.exact_gc_vecmul_value_digest(
        ss[[input_stage$output_key]]), input_stage$output_previous_digest)) {
      stop("Exact-gc multiplication destination changed.", call. = FALSE)
    }
    combined <- gsub(
      "[\r\n]", "", jsonlite::base64_enc(combined_raw))
    manifest <- NULL
    if (!is.null(input_stage$manifest_handle)) {
      manifest <- ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]]
      if (is.null(manifest)) {
        stop("Exact-gc vecmul manifest disappeared before commit.",
             call. = FALSE)
      }
      .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
      if (!identical(manifest$state, "claimed") ||
          !identical(manifest$claimed_batch,
                     contract$batch_operation_id)) {
        stop("Exact-gc vecmul manifest changed before commit.", call. = FALSE)
      }
      manifest$state <- "consumed"
      manifest$mac <- .exact_gc_vecmul_manifest_mac(ss, manifest)
    }
    previous_stage <- ss$.exact_gc_vecmul_input_stages[[
      contract$batch_operation_id]]
    previous_manifest <- if (is.null(input_stage$manifest_handle)) NULL else
      ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]]
    installed <- FALSE
    on.exit(if (!installed) {
      ss[[input_stage$output_key]] <- NULL
      ss$.exact_gc_vecmul_input_stages[[contract$batch_operation_id]] <-
        previous_stage
      if (!is.null(input_stage$manifest_handle)) {
        ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]] <-
          previous_manifest
      }
    }, add = TRUE)
    ss[[input_stage$output_key]] <- combined
    input_stage$output_digest <- .exact_gc_vecmul_value_digest(combined)
    input_stage$state <- "complete"
    if (!is.null(manifest)) {
      ss$.exact_gc_vecmul_manifests[[input_stage$manifest_handle]] <- manifest
    }
    ss$.exact_gc_vecmul_input_stages[[contract$batch_operation_id]] <-
      input_stage
    ss$.exact_gc_checked_mul_chunks[[contract$batch_operation_id]] <- NULL
    batch_keys <- .exact_gc_checked_mul_keys(contract$batch_operation_id)
    ss[[batch_keys$x]] <- NULL
    ss[[batch_keys$y]] <- NULL
    installed <- TRUE
    state <- "committed"
  }
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       stored = TRUE, state = state)
}

#' Commit a bilaterally validated checked multiplication (AGGREGATE)
#'
#' @inheritParams exactGCVecmulStartDS
#' @export
exactGCVecmulCommitDS <- function(
    n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
    operation_id, policy_id, plan_id) {
  tryCatch(
    .exact_gc_checked_mul_commit_impl(
      n, total_n, chunk_index, chunk_count, batch_operation_id, session_id,
      operation_id, policy_id, plan_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}
