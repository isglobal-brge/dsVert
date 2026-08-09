# Fixed-geometry DSI framing adapter for padded PSI. This is transport
# chunking only: it does not split a statistical query and never changes the
# result, privacy budget, or request semantics.

.DSVERT_PSI_PADDED_RELAY_CAPABILITY <- "psi.padded.v4"
.DSVERT_PSI_PADDED_RELAY_DESCRIPTOR <- "dsvert-psi-padded-relay-v4"

.psi_padded_inline_max_bytes <- function() {
  value <- getOption("dsvert.psi.padded.inline_max_bytes", 448L * 1024L)
  .psi_padded_integer(
    value, "inline byte limit", 16L * 1024L, 64L * 1024L^2)
}

.psi_padded_sealed_scalar <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") >
        .dsvert_relay_max_envelope_bytes() ||
      !grepl("^[A-Za-z0-9_-]+$", value)) {
    stop("Invalid padded PSI sealed envelope.", call. = FALSE)
  }
  value
}

.psi_padded_relay_ensure <- function(ss) {
  state <- .psi_padded_and_state(ss)
  if (is.environment(ss$.dsvert_dsi_relay)) {
    relay <- .dsvert_relay_state(ss)
    if (!identical(relay$session_id, state$contract$session_id) ||
        !identical(relay$self_peer_id, state$self_peer_id) ||
        !.DSVERT_PSI_PADDED_RELAY_CAPABILITY %in%
          relay$allowed_capabilities) {
      stop("Padded PSI relay has a conflicting session manifest.",
           call. = FALSE)
    }
    return(invisible(relay))
  }
  peers <- state$identity_pks
  if (!is.list(peers) || is.null(names(peers)) ||
      !setequal(names(peers), state$contract$peer_names)) {
    stop("Padded PSI relay peer manifest is unavailable.", call. = FALSE)
  }
  .dsvert_relay_init(
    ss, state$contract$session_id, state$identity_pk,
    trusted_identity_pks = unname(unlist(
      peers[setdiff(names(peers), state$self_peer)], use.names = FALSE)),
    allowed_capabilities = .DSVERT_PSI_PADDED_RELAY_CAPABILITY)
  relay <- .dsvert_relay_state(ss)
  if (!identical(relay$self_peer_id, state$self_peer_id)) {
    .dsvert_relay_close(ss)
    stop("Padded PSI relay identity does not match its signed contract.",
         call. = FALSE)
  }
  invisible(relay)
}

.psi_padded_relay_operation <- function(context) {
  context <- .psi_padded_validate_envelope_context(context)
  paste0("op_", substr(digest::digest(charToRaw(paste0(
    "dsVert/padded-psi/relay-operation/v4|",
    .psi_padded_canonical_json(context))),
    algo = "sha256", serialize = FALSE), 1L, 32L))
}

.psi_padded_relay_descriptor <- function(state, context, payload,
                                         operation_id) {
  recipient_index <- match(context$recipient, state$contract$peer_names)
  sender_index <- match(context$sender, state$contract$peer_names)
  if (is.na(recipient_index) || is.na(sender_index)) {
    stop("Padded PSI relay route is outside the signed contract.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_PSI_PADDED_RELAY_DESCRIPTOR,
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = state$contract$contract_hash,
    operation_id = operation_id,
    capability_id = .DSVERT_PSI_PADDED_RELAY_CAPABILITY,
    sender = context$sender, recipient = context$recipient,
    sender_peer_id = state$contract$peer_ids[[sender_index]],
    recipient_peer_id = state$contract$peer_ids[[recipient_index]],
    total_bytes = as.numeric(length(payload)),
    payload_hash = digest::digest(
      payload, algo = "sha256", serialize = FALSE),
    frame_bytes = as.numeric(state$contract$relay_frame_bytes))
}

.psi_padded_validate_relay_descriptor <- function(value, state,
                                                   expected_context) {
  required <- c(
    "version", "protocol", "contract_hash", "operation_id",
    "capability_id", "sender", "recipient", "sender_peer_id",
    "recipient_peer_id", "total_bytes", "payload_hash", "frame_bytes")
  fail <- function() stop("Invalid padded PSI relay descriptor.",
                          call. = FALSE)
  if (!is.list(value) || !identical(names(value), required) ||
      !identical(value$version, .DSVERT_PSI_PADDED_RELAY_DESCRIPTOR) ||
      !identical(value$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !identical(value$contract_hash, state$contract$contract_hash) ||
      !identical(value$capability_id,
                 .DSVERT_PSI_PADDED_RELAY_CAPABILITY) ||
      !identical(value$sender, expected_context$sender) ||
      !identical(value$recipient, expected_context$recipient) ||
      !identical(value$operation_id,
                 .psi_padded_relay_operation(expected_context)) ||
      !is.character(value$payload_hash) ||
      !grepl("^[0-9a-f]{64}$", value$payload_hash)) fail()
  sender_index <- match(value$sender, state$contract$peer_names)
  recipient_index <- match(value$recipient, state$contract$peer_names)
  value$frame_bytes <- tryCatch(
    .dsvert_relay_uint(value$frame_bytes, "padded PSI relay frame length"),
    error = function(error) fail())
  if (is.na(sender_index) || is.na(recipient_index) ||
      !identical(value$sender_peer_id,
                 state$contract$peer_ids[[sender_index]]) ||
      !identical(value$recipient_peer_id,
                 state$contract$peer_ids[[recipient_index]]) ||
      !identical(as.numeric(value$frame_bytes),
                 as.numeric(state$contract$relay_frame_bytes))) fail()
  value$total_bytes <- .dsvert_relay_uint(
    value$total_bytes, "padded PSI relay total length")
  if (value$total_bytes < 1 ||
      value$total_bytes > .dsvert_relay_max_envelope_bytes()) fail()
  value
}

.psi_padded_publish_envelope <- function(ss, envelope, context,
                                         force_relay = FALSE) {
  state <- .psi_padded_and_state(ss)
  context <- .psi_padded_validate_envelope_context(context)
  if (!identical(context$sender, state$self_peer)) {
    stop("Padded PSI cannot publish another peer's envelope.",
         call. = FALSE)
  }
  if (!is.logical(force_relay) || length(force_relay) != 1L ||
      is.na(force_relay)) {
    stop("Invalid padded PSI relay selector.", call. = FALSE)
  }
  envelope <- .psi_padded_sealed_scalar(envelope)
  bytes <- charToRaw(envelope)
  operation_id <- .psi_padded_relay_operation(context)
  descriptor <- .psi_padded_relay_descriptor(
    state, context, bytes, operation_id)
  if (identical(context$sender, context$recipient)) {
    local <- state$local_envelopes %||% list()
    previous <- local[[operation_id]]
    record <- list(payload_hash = descriptor$payload_hash,
                   envelope = envelope)
    if (!is.null(previous) && !identical(previous, record)) {
      stop("Conflicting padded PSI local-envelope retry.", call. = FALSE)
    }
    local[[operation_id]] <- record
    state$local_envelopes <- local
    ss$.psi_padded_state <- state
    .psi_padded_state_commit(ss)
    return(list(transport = "local", envelope = NULL,
                relay = descriptor))
  }
  inline_limit <- min(
    as.numeric(state$contract$inline_max_bytes),
    as.numeric(.psi_padded_inline_max_bytes()))
  if (!isTRUE(force_relay) && length(bytes) <= inline_limit) {
    return(list(transport = "inline", envelope = envelope,
                relay = NULL))
  }
  .psi_padded_relay_ensure(ss)
  opened <- .dsvert_relay_queue_begin(
    ss, operation_id, descriptor$recipient_peer_id,
    descriptor$capability_id, descriptor$total_bytes,
    payload_hash = descriptor$payload_hash,
    frame_bytes = descriptor$frame_bytes)
  if (identical(opened$status, "building")) {
    offsets <- seq.int(
      0, descriptor$total_bytes - 1,
      by = descriptor$frame_bytes)
    for (offset in offsets) {
      count <- min(descriptor$frame_bytes,
                   descriptor$total_bytes - offset)
      .dsvert_relay_queue_append(
        ss, operation_id, descriptor$recipient_peer_id,
        descriptor$capability_id, offset,
        bytes[seq.int(offset + 1, length.out = count)])
    }
    .dsvert_relay_queue_seal(
      ss, operation_id, descriptor$recipient_peer_id,
      descriptor$capability_id, descriptor$payload_hash)
  }
  list(transport = "relay", envelope = NULL, relay = descriptor)
}

.psi_padded_resolve_envelope <- function(ss, envelope, relay_descriptor,
                                         expected_context) {
  state <- .psi_padded_and_state(ss)
  expected_context <- .psi_padded_validate_envelope_context(expected_context)
  inline <- is.character(envelope) && length(envelope) == 1L &&
    !is.na(envelope) && nzchar(envelope)
  relayed <- is.list(relay_descriptor)
  if (identical(inline, relayed)) {
    stop("Padded PSI requires exactly one envelope transport.",
         call. = FALSE)
  }
  if (inline) return(envelope)
  descriptor <- .psi_padded_validate_relay_descriptor(
    relay_descriptor, state, expected_context)
  if (!identical(descriptor$recipient, state$self_peer)) {
    stop("Padded PSI relay descriptor has the wrong recipient.",
         call. = FALSE)
  }
  if (identical(descriptor$sender, descriptor$recipient)) {
    record <- state$local_envelopes[[descriptor$operation_id]]
    if (!is.list(record) ||
        !identical(record$payload_hash, descriptor$payload_hash) ||
        !is.character(record$envelope) || length(record$envelope) != 1L) {
      stop("Padded PSI local envelope is unavailable.", call. = FALSE)
    }
    return(.psi_padded_sealed_scalar(record$envelope))
  }
  .psi_padded_relay_ensure(ss)
  payload <- .dsvert_relay_payload(
    ss, descriptor$sender_peer_id, descriptor$operation_id,
    descriptor$capability_id)
  if (!is.raw(payload) || length(payload) != descriptor$total_bytes ||
      !identical(digest::digest(
        payload, algo = "sha256", serialize = FALSE),
        descriptor$payload_hash)) {
    stop("Padded PSI relayed envelope is incomplete or hash-mismatched.",
         call. = FALSE)
  }
  value <- tryCatch(rawToChar(payload), error = function(e) "")
  value <- .psi_padded_sealed_scalar(value)
  .dsvert_relay_mark_payload_consumed(
    ss, descriptor$sender_peer_id, descriptor$operation_id,
    descriptor$capability_id)
  value
}

.psi_padded_decode_relay_descriptor <- function(value) {
  if (is.null(value) || (is.character(value) && length(value) == 1L &&
                         !is.na(value) && !nzchar(value))) return(NULL)
  .psi_padded_parse_json_b64url(
    value, "relay descriptor", 64L * 1024L)
}

.psi_padded_parse_relay_request <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) ||
      nchar(value, type = "bytes") > 2L *
        .dsvert_relay_exchange_max_bytes() + 256L * 1024L) {
    stop("Invalid padded PSI relay exchange request.", call. = FALSE)
  }
  parsed <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(e) NULL)
  if (!is.list(parsed) || is.null(names(parsed)) ||
      anyNA(names(parsed)) || anyDuplicated(names(parsed))) {
    stop("Invalid padded PSI relay exchange request.", call. = FALSE)
  }
  parsed
}

.psi_padded_decode_relay_receipt <- function(value) {
  if (is.null(value) || (is.character(value) && length(value) == 1L &&
                         !is.na(value) && !nzchar(value))) return(NULL)
  .psi_padded_parse_json_b64url(value, "terminal relay receipt", 64L * 1024L)
}

# Purpose-specific exchange. It cannot choose a capability or read a payload;
# it only advances signed PSI frames at absolute offsets.
#' @export
#' @noRd
psiPaddedRelayExchangeDS <- function(
    request_json, session_id, outbound_operation_id = "",
    terminal_receipt_b64url = "") {
  tryCatch({
    request_json <- .dsvert_dsi_text_decode(
      request_json, "padded PSI relay request",
      2L * .dsvert_relay_exchange_max_bytes() + 256L * 1024L)
    ss <- .S(session_id)
    .psi_padded_relay_ensure(ss)
    operation_id <- if (is.character(outbound_operation_id) &&
                            length(outbound_operation_id) == 1L &&
                            !is.na(outbound_operation_id) &&
                            nzchar(outbound_operation_id)) {
      .dsvert_relay_validate_operation_id(outbound_operation_id)
    } else if (identical(outbound_operation_id, "")) NULL else {
      stop("Invalid padded PSI relay operation selector.", call. = FALSE)
    }
    receipt <- .psi_padded_decode_relay_receipt(terminal_receipt_b64url)
    if (!is.null(receipt)) {
      if (is.null(operation_id) ||
          !identical(receipt$operation_id, operation_id)) {
        stop("Padded PSI terminal receipt has the wrong operation.",
             call. = FALSE)
      }
      .dsvert_relay_verify_receipt(ss, receipt)
      .dsvert_relay_record_verified_receipt(ss, receipt)
    }
    .dsvert_relay_exchange(
      ss, .psi_padded_parse_relay_request(request_json),
      outbound_operation_id = operation_id)
  }, error = function(e) {
    if (inherits(e, "dsvert_resource_backpressure") ||
        inherits(e, "dsvert_resource_oversize")) stop(e)
    stop("Padded PSI relay exchange failed.", call. = FALSE)
  })
}
