# Internal, unregistered DSI fan-out relay substrate.  It moves only opaque,
# peer-authenticated envelopes; no DataSHIELD *DS entrypoint is exposed yet.

.DSVERT_RELAY_VERSION <- "dsvert-relay-v1"
.DSVERT_RELAY_DOMAIN <- "dsVert/dsi-relay/envelope/v1|"
.DSVERT_RELAY_PEER_RE <- "^dsv1_[0-9a-f]{64}$"
.DSVERT_RELAY_OPERATION_RE <- "^op_[0-9a-f]{32}$"
.DSVERT_RELAY_SESSION_RE <-
  "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
.DSVERT_RELAY_CAPABILITY_RE <- "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"
.DSVERT_RELAY_RECEIPT_VERSION <- "dsvert-relay-receipt-v1"
.DSVERT_RELAY_RECEIPT_DOMAIN <- "dsVert/dsi-relay/receipt/v1|"
.DSVERT_RELAY_FRAME_METADATA_BYTES <- 1024

#' @keywords internal
.dsvert_relay_scalar_string <- function(x, what) {
  if (!is.character(x) || length(x) != 1L || is.na(x) || !nzchar(x))
    stop("Invalid ", what, ".", call. = FALSE)
  enc2utf8(x)
}

#' @keywords internal
.dsvert_relay_uint <- function(x, what) {
  if (!is.numeric(x) || length(x) != 1L || is.na(x) || !is.finite(x) ||
      x < 0 || x != floor(x) || x > 2^53)
    stop("Invalid ", what, ".", call. = FALSE)
  as.numeric(x)
}

#' @keywords internal
.dsvert_relay_b64url_encode <- function(x) {
  if (!is.raw(x)) stop("Relay payload must be raw bytes.", call. = FALSE)
  base64_to_base64url(gsub("[\r\n]", "", jsonlite::base64_enc(x)))
}

#' @keywords internal
.dsvert_relay_b64url_decode <- function(x, what = "base64url payload") {
  x <- .dsvert_relay_scalar_string(x, what)
  if (!grepl("^[A-Za-z0-9_-]+$", x) || nchar(x) %% 4L == 1L)
    stop("Invalid ", what, ".", call. = FALSE)
  value <- tryCatch(jsonlite::base64_dec(.base64url_to_base64(x)),
                    error = function(e) NULL)
  if (is.null(value) || !identical(.dsvert_relay_b64url_encode(value), x))
    stop("Invalid or non-canonical ", what, ".", call. = FALSE)
  value
}

#' @keywords internal
.dsvert_relay_decode_payload <- function(x) {
  .dsvert_relay_b64url_decode(x, "relay payload")
}

#' @keywords internal
.dsvert_relay_normalize_identity_pk <- function(identity_pk) {
  identity_pk <- .dsvert_relay_scalar_string(identity_pk,
                                               "identity public key")
  identity_pk <- base64_to_base64url(gsub("[\r\n[:space:]]", "", identity_pk))
  raw_pk <- .dsvert_relay_b64url_decode(identity_pk, "identity public key")
  if (length(raw_pk) != 32L)
    stop("Invalid identity public key length.", call. = FALSE)
  .dsvert_relay_b64url_encode(raw_pk)
}

#' Stable, non-secret peer routing ID derived from a pinned Ed25519 key.
#' @keywords internal
.dsvert_relay_peer_id <- function(identity_pk) {
  pk <- .dsvert_relay_b64url_decode(
    .dsvert_relay_normalize_identity_pk(identity_pk), "identity public key")
  paste0("dsv1_", digest::digest(
    c(charToRaw("dsVert/peer-capability/v1|"), pk),
    algo = "sha256", serialize = FALSE))
}

#' @keywords internal
.dsvert_relay_validate_peer_id <- function(peer_id) {
  peer_id <- .dsvert_relay_scalar_string(peer_id, "peer capability")
  if (!grepl(.DSVERT_RELAY_PEER_RE, peer_id))
    stop("Invalid peer capability ID.", call. = FALSE)
  peer_id
}

#' @keywords internal
.dsvert_relay_validate_session_id <- function(session_id) {
  session_id <- .dsvert_relay_scalar_string(session_id, "relay session ID")
  if (!grepl(.DSVERT_RELAY_SESSION_RE, session_id))
    stop("Invalid relay session ID; a canonical lower-case UUID is required.",
         call. = FALSE)
  session_id
}

#' @keywords internal
.dsvert_relay_validate_operation_id <- function(operation_id) {
  operation_id <- .dsvert_relay_scalar_string(operation_id,
                                                "relay operation ID")
  if (!grepl(.DSVERT_RELAY_OPERATION_RE, operation_id))
    stop("Invalid relay operation ID.", call. = FALSE)
  operation_id
}

#' @keywords internal
.dsvert_relay_validate_capability_id <- function(capability_id) {
  capability_id <- .dsvert_relay_scalar_string(capability_id,
                                                "relay capability ID")
  if (nchar(capability_id, type = "bytes") > 64L ||
      !grepl(.DSVERT_RELAY_CAPABILITY_RE, capability_id, perl = TRUE))
    stop("Invalid relay capability ID.", call. = FALSE)
  capability_id
}

#' Initialise state from server-owned identity and capability manifests.
#' @keywords internal
.dsvert_relay_init <- function(ss, session_id, own_identity_pk,
                               trusted_identity_pks, allowed_capabilities) {
  if (!is.environment(ss)) stop("ss must be an environment.", call. = FALSE)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (is.null(ss$.session_id)) {
    ss$.session_id <- session_id
  } else if (!identical(ss$.session_id, session_id)) {
    stop("DSI relay session ID does not match the private session.",
         call. = FALSE)
  }
  own_pk <- .dsvert_relay_normalize_identity_pk(own_identity_pk)
  if (!is.character(trusted_identity_pks) || !length(trusted_identity_pks))
    stop("Pinned peer identities are required for the DSI relay.", call. = FALSE)
  peer_pks <- unique(c(own_pk, vapply(
    trusted_identity_pks, .dsvert_relay_normalize_identity_pk, character(1L))))
  peer_ids <- vapply(peer_pks, .dsvert_relay_peer_id, character(1L))
  if (anyDuplicated(peer_ids)) stop("Duplicate pinned peer capabilities.", call. = FALSE)
  if (!is.character(allowed_capabilities) || !length(allowed_capabilities))
    stop("At least one relay capability is required.", call. = FALSE)
  allowed_capabilities <- unique(vapply(
    allowed_capabilities, .dsvert_relay_validate_capability_id, character(1L)))

  if (is.environment(ss$.dsvert_dsi_relay)) .dsvert_relay_close(ss)
  session_dir <- .ensure_session_dir(ss)
  relay_root <- file.path(session_dir, "relay")
  if (!dir.exists(relay_root) && !dir.create(
      relay_root, recursive = FALSE, showWarnings = FALSE, mode = "0700")) {
    stop("Could not create the private relay spool directory.", call. = FALSE)
  }
  Sys.chmod(relay_root, mode = "0700")
  .dsvert_session_private_directory(
    relay_root, "private relay spool directory")
  spool_tag <- substr(digest::digest(
    paste(session_id, .dsvert_relay_peer_id(own_pk), sep = "|"),
    algo = "sha256", serialize = FALSE), 1L, 16L)
  spool <- tempfile(pattern = paste0("relay-", spool_tag, "-"),
                    tmpdir = relay_root)
  if (!dir.create(spool, mode = "0700", showWarnings = FALSE))
    stop("Could not create the private relay spool.", call. = FALSE)
  Sys.chmod(spool, mode = "0700")
  .dsvert_session_private_directory(spool, "private relay spool")

  state <- new.env(parent = emptyenv())
  state$session_id <- session_id
  state$self_peer_id <- .dsvert_relay_peer_id(own_pk)
  state$identity_pks <- stats::setNames(as.list(peer_pks), peer_ids)
  state$allowed_capabilities <- allowed_capabilities
  state$inbox <- list()
  state$inbox_latest_consumed <- list()
  state$outbox <- list()
  state$outbox_base <- 0
  state$outgoing <- list()
  state$outgoing_latest_receipt <- list()
  state$spool <- spool
  state$spool_root <- relay_root
  state$retained_bytes <- 0
  state$spool_max_bytes <- .dsvert_relay_spool_max_bytes()
  state$metadata_max_bytes <- .dsvert_relay_metadata_max_bytes()
  state$exchange_max_bytes <- .dsvert_relay_exchange_max_bytes()
  state$ttl_seconds <- .dsvert_relay_ttl_seconds()
  state$last_activity <- .dsvert_relay_now()
  ss$.dsvert_dsi_relay <- state
  .session_progress(ss, state$last_activity)
  reg.finalizer(state, function(value) {
    path <- value$spool
    root <- value$spool_root
    if (is.character(path) && length(path) == 1L && dir.exists(path) &&
        is.character(root) && length(root) == 1L &&
        identical(normalizePath(dirname(path), mustWork = FALSE),
                  normalizePath(root, mustWork = FALSE)) &&
        grepl("^relay-[0-9a-f]{16}-[A-Za-z0-9]+$", basename(path))) {
      unlink(path, recursive = TRUE)
    }
  }, onexit = TRUE)
  invisible(state$self_peer_id)
}

#' @keywords internal
.dsvert_relay_state <- function(ss) {
  if (!is.environment(ss) || !is.environment(ss$.dsvert_dsi_relay))
    stop("DSI relay state has not been initialised.", call. = FALSE)
  ss$.dsvert_dsi_relay
}

#' Canonical, length-delimited envelope header.
#' @keywords internal
.dsvert_relay_auth_message <- function(version, session_id, operation_id,
                                        sender_peer_id, recipient_peer_id,
                                        capability_id, total_bytes,
                                        payload_hash) {
  values <- c(version, session_id, operation_id, sender_peer_id,
              recipient_peer_id, capability_id,
              format(total_bytes, scientific = FALSE, trim = TRUE), payload_hash)
  fields <- vapply(values, function(value)
    paste0(nchar(value, type = "bytes"), ":", value), character(1L))
  charToRaw(paste0(.DSVERT_RELAY_DOMAIN, paste0(fields, collapse = "")))
}

#' Domain-separated Ed25519 authentication using the existing MPC kernel.
#' @keywords internal
.dsvert_relay_sign_message <- function(message, identity_sk) {
  if (!is.raw(message)) stop("Relay signature message must be raw.", call. = FALSE)
  message_b64 <- gsub("[\r\n]", "", jsonlite::base64_enc(message))
  signature <- base64_to_base64url(.sign_transport_pk(message_b64, identity_sk))
  if (length(.dsvert_relay_b64url_decode(signature, "relay signature")) != 64L)
    stop("Invalid relay signature length.", call. = FALSE)
  signature
}

#' @keywords internal
.dsvert_relay_verify_message <- function(message, identity_pk, signature) {
  if (!is.raw(message)) return(FALSE)
  identity_pk <- tryCatch(.dsvert_relay_normalize_identity_pk(identity_pk),
                          error = function(e) NULL)
  sig_raw <- tryCatch(.dsvert_relay_b64url_decode(signature, "relay signature"),
                      error = function(e) NULL)
  if (is.null(identity_pk) || is.null(sig_raw) || length(sig_raw) != 64L)
    return(FALSE)
  .verify_peer_identity(
    gsub("[\r\n]", "", jsonlite::base64_enc(message)),
    .base64url_to_base64(identity_pk),
    gsub("[\r\n]", "", jsonlite::base64_enc(sig_raw)))
}

#' @keywords internal
.dsvert_relay_max_envelope_bytes <- function() {
  .dsvert_relay_uint(
    getOption("dsvert.relay.max_envelope_bytes", 64L * 1024L * 1024L),
    "maximum envelope size")
}

#' @keywords internal
.dsvert_relay_option_uint <- function(name, default, minimum, maximum) {
  value <- getOption(paste0("dsvert.relay.", name), default)
  value <- .dsvert_relay_uint(value, paste0("relay ", name, " policy"))
  if (value < minimum || value > maximum)
    stop("Invalid relay ", name, " policy.", call. = FALSE)
  value
}

#' Total retained opaque bytes, not a request-count or privacy-budget quota.
#' @keywords internal
.dsvert_relay_spool_max_bytes <- function() {
  .dsvert_relay_option_uint(
    "spool_max_bytes", 1024^3, 1024^2, 64 * 1024^3)
}

#' Bound R control-plane descriptors independently of disk spool capacity.
#'
#' Operators may legitimately provision a large disk spool.  That must not let
#' a tiny advertised frame create millions of in-memory offsets/descriptors
#' before backpressure is evaluated.
#' @keywords internal
.dsvert_relay_metadata_max_bytes <- function() {
  .dsvert_relay_option_uint(
    "metadata_max_bytes", 64 * 1024^2, 64 * 1024, 4 * 1024^3)
}

#' Maximum raw payload moved in either direction by one DSI fan-out cycle.
#' @keywords internal
.dsvert_relay_exchange_max_bytes <- function() {
  .dsvert_relay_option_uint(
    "exchange_max_bytes", 480 * 1024, 16 * 1024, 64 * 1024^2)
}

#' @keywords internal
.dsvert_relay_ttl_seconds <- function() {
  # Long MPC kernels can legitimately run for many minutes without a relay
  # call.  Six hours keeps abandoned state time-bounded while avoiding a
  # five-minute lease that would invalidate otherwise healthy large jobs.
  .dsvert_relay_option_uint("ttl_seconds", 6 * 60 * 60, 10, 86400)
}

#' @keywords internal
.dsvert_relay_now <- function() floor(as.numeric(Sys.time()))

#' @keywords internal
.dsvert_relay_spool_path <- function(state, stream_key, direction) {
  if (!direction %in% c("in", "out"))
    stop("Invalid relay spool direction.", call. = FALSE)
  token <- digest::digest(
    paste(direction, stream_key, sep = "|"), algo = "sha256",
    serialize = FALSE)
  file.path(state$spool, paste0(direction, "-", token, ".bin"))
}

#' @keywords internal
.dsvert_relay_private_write <- function(path, value) {
  if (!is.raw(value)) stop("Relay spool value must be raw bytes.", call. = FALSE)
  tmp <- tempfile(pattern = ".relay-write-", tmpdir = dirname(path))
  on.exit(unlink(tmp), add = TRUE)
  con <- file(tmp, "wb")
  on.exit(tryCatch(close(con), error = function(e) NULL), add = TRUE)
  if (length(value)) writeBin(value, con)
  flush(con)
  close(con)
  Sys.chmod(tmp, mode = "0600")
  if (!file.rename(tmp, path))
    stop("Could not commit the private relay spool.", call. = FALSE)
  Sys.chmod(path, mode = "0600")
  invisible(path)
}

#' @keywords internal
.dsvert_relay_read_at <- function(path, offset, n) {
  offset <- .dsvert_relay_uint(offset, "relay spool offset")
  n <- .dsvert_relay_uint(n, "relay spool read length")
  size <- if (file.exists(path)) file.size(path) else NA_real_
  if (length(size) != 1L || is.na(size) || !is.finite(size) ||
      offset + n > size)
    stop("Invalid relay spool range.", call. = FALSE)
  if (n == 0) return(raw(0))
  con <- file(path, "rb")
  on.exit(close(con), add = TRUE)
  seek(con, where = offset, origin = "start")
  value <- readBin(con, "raw", n = n)
  if (length(value) != n) stop("Relay spool read was truncated.", call. = FALSE)
  value
}

#' @keywords internal
.dsvert_relay_append <- function(path, value, expected_offset) {
  if (!is.raw(value) || !length(value))
    stop("Relay append must contain raw bytes.", call. = FALSE)
  size <- if (file.exists(path)) file.size(path) else 0
  if (length(size) != 1L || is.na(size) || !is.finite(size) ||
      size != expected_offset)
    stop("Relay spool offset does not match its committed bytes.", call. = FALSE)
  con <- file(path, "ab")
  on.exit(close(con), add = TRUE)
  writeBin(value, con)
  flush(con)
  Sys.chmod(path, mode = "0600")
  invisible(size + length(value))
}

#' @keywords internal
.dsvert_relay_truncate <- function(path, size) {
  size <- .dsvert_relay_uint(size, "relay rollback offset")
  if (!file.exists(path)) return(invisible(FALSE))
  current <- file.size(path)
  if (is.na(current) || current < size)
    stop("Relay spool cannot be rolled back safely.", call. = FALSE)
  if (current == size) return(invisible(TRUE))
  con <- file(path, "r+b")
  on.exit(close(con), add = TRUE)
  seek(con, where = size, origin = "start")
  truncate(con)
  invisible(TRUE)
}

#' Remove only a relay-created private spool directory.
#' @keywords internal
.dsvert_relay_close <- function(ss) {
  state <- if (is.environment(ss)) ss$.dsvert_dsi_relay else NULL
  if (!is.environment(state)) return(invisible(FALSE))
  path <- state$spool
  session_dir <- .assert_session_dir(ss)
  relay_root <- file.path(session_dir, "relay")
  .dsvert_session_private_directory(
    relay_root, "private relay spool directory")
  parent_ok <- is.character(path) && length(path) == 1L &&
    identical(normalizePath(dirname(path), mustWork = FALSE),
              normalizePath(relay_root, mustWork = FALSE))
  name_ok <- is.character(path) && length(path) == 1L &&
    grepl("^relay-[0-9a-f]{16}-[A-Za-z0-9]+$", basename(path))
  if (!parent_ok || !name_ok)
    stop("Refusing to remove an invalid relay spool path.", call. = FALSE)
  if (dir.exists(path)) unlink(path, recursive = TRUE)
  ss$.dsvert_dsi_relay <- NULL
  invisible(TRUE)
}

#' Expire a relay session after a public, fixed period without activity.
#' @keywords internal
.dsvert_relay_gc <- function(ss, now = .dsvert_relay_now()) {
  state <- .dsvert_relay_state(ss)
  now <- .dsvert_relay_uint(now, "relay clock")
  if (now - state$last_activity <= state$ttl_seconds) return(invisible(FALSE))
  .dsvert_relay_close(ss)
  stop("DSI relay session expired; initialise a fresh session.", call. = FALSE)
}

#' @keywords internal
.dsvert_relay_frame_bytes <- function(value = NULL) {
  if (is.null(value)) value <- getOption(
    "dsvert.relay.frame_bytes", 480L * 1024L)
  value <- .dsvert_relay_uint(value, "relay frame size")
  if (value < 1 || value > .dsvert_relay_exchange_max_bytes())
    stop("Relay frame size is outside the exchange bound.", call. = FALSE)
  value
}

#' Reserve a bounded, unpublished outbound ciphertext stream.
#' @keywords internal
.dsvert_relay_queue_begin <- function(
    ss, operation_id, recipient_peer_id, capability_id, total_bytes,
    payload_hash = NULL, frame_bytes = NULL) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  recipient_peer_id <- .dsvert_relay_validate_peer_id(recipient_peer_id)
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  if (is.null(state$identity_pks[[recipient_peer_id]]))
    stop("Relay recipient is not a pinned peer.", call. = FALSE)
  if (identical(recipient_peer_id, state$self_peer_id))
    stop("Relay recipient must be a different pinned peer.", call. = FALSE)
  if (!capability_id %in% state$allowed_capabilities)
    stop("Relay capability is not allowed by the session manifest.", call. = FALSE)
  total_bytes <- .dsvert_relay_uint(total_bytes, "relay total length")
  if (total_bytes < 1)
    stop("Opaque payload must contain at least one byte.", call. = FALSE)
  if (total_bytes > .dsvert_relay_max_envelope_bytes()) {
    .dsvert_resource_oversize(
      total_bytes, .dsvert_relay_max_envelope_bytes(),
      "relay maximum envelope")
  }
  frame_bytes <- .dsvert_relay_frame_bytes(frame_bytes)
  if (!is.null(payload_hash) &&
      (!is.character(payload_hash) || length(payload_hash) != 1L ||
       is.na(payload_hash) || !grepl("^[0-9a-f]{64}$", payload_hash)))
    stop("Invalid relay envelope hash.", call. = FALSE)
  frame_count <- ceiling(total_bytes / frame_bytes)
  metadata_bytes <- frame_count * .DSVERT_RELAY_FRAME_METADATA_BYTES
  reservation <- total_bytes + metadata_bytes
  outgoing_key <- paste(recipient_peer_id, operation_id, capability_id, sep = "|")
  previous <- state$outgoing[[outgoing_key]]
  if (!is.null(previous)) {
    known_hash <- if (!is.null(previous$payload_hash))
      previous$payload_hash else previous$expected_hash
    hash_conflict <- !is.null(payload_hash) &&
      !is.null(known_hash) && !identical(known_hash, payload_hash)
    if (!identical(previous$total_bytes, total_bytes) ||
        !identical(previous$frame_bytes, frame_bytes) || hash_conflict)
      stop("Conflicting retry for an existing outbound operation.", call. = FALSE)
    if (identical(previous$status, "poisoned"))
      stop("Relay outbound operation is poisoned; abort the session.",
           call. = FALSE)
    advanced <- is.null(previous$expected_hash) && !is.null(payload_hash)
    if (advanced)
      previous$expected_hash <- payload_hash
    if (advanced) {
      previous$last_activity <- .dsvert_relay_now()
      state$last_activity <- previous$last_activity
      .session_progress(ss, state$last_activity)
    }
    state$outgoing[[outgoing_key]] <- previous
    committed <- if (is.character(previous$path) &&
                     length(previous$path) == 1L &&
                     file.exists(previous$path)) {
      size <- file.size(previous$path)
      if (length(size) != 1L || is.na(size) || !is.finite(size))
        stop("Invalid outbound relay spool size.", call. = FALSE)
      as.numeric(size)
    } else {
      previous$total_bytes
    }
    return(invisible(list(
      status = previous$status,
      committed_bytes = committed,
      total_bytes = previous$total_bytes,
      frame_bytes = previous$frame_bytes)))
  }

  if (metadata_bytes > state$metadata_max_bytes) {
    .dsvert_resource_oversize(
      metadata_bytes, state$metadata_max_bytes,
      "relay control-plane metadata")
  }
  if (reservation > state$spool_max_bytes) {
    .dsvert_resource_oversize(
      reservation, state$spool_max_bytes, "relay session spool")
  }
  if (state$retained_bytes > state$spool_max_bytes - reservation) {
    .dsvert_resource_backpressure(
      state$retained_bytes, reservation, state$spool_max_bytes,
      "relay session spool")
  }
  .dsvert_resource_admit(ss, reservation)
  offsets <- (seq_len(as.integer(frame_count)) - 1) * frame_bytes
  lengths <- pmin(frame_bytes, total_bytes - offsets)
  path <- .dsvert_relay_spool_path(state, outgoing_key, "out")
  created <- .dsvert_relay_now()
  stream <- list(
    operation_id = operation_id, recipient_peer_id = recipient_peer_id,
    capability_id = capability_id, expected_hash = payload_hash,
    payload_hash = NULL, total_bytes = total_bytes, signature = NULL,
    path = path, frame_bytes = frame_bytes, reservation = reservation,
    frame_offsets = as.numeric(offsets), frame_lengths = as.numeric(lengths),
    status = "building", created_at = created, last_activity = created)
  next_outgoing <- state$outgoing
  next_outgoing[[outgoing_key]] <- stream
  .dsvert_relay_private_write(path, raw(0))
  committed <- FALSE
  on.exit(if (!committed) unlink(path), add = TRUE)
  state$outgoing <- next_outgoing
  state$retained_bytes <- state$retained_bytes + reservation
  state$last_activity <- created
  committed <- TRUE
  .session_progress(ss, state$last_activity)
  invisible(list(status = "building", committed_bytes = 0,
                 total_bytes = total_bytes, frame_bytes = frame_bytes))
}

#' Append one immutable ciphertext frame at its absolute byte offset.
#' @keywords internal
.dsvert_relay_queue_append <- function(
    ss, operation_id, recipient_peer_id, capability_id, offset, payload) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  key <- paste(.dsvert_relay_validate_peer_id(recipient_peer_id),
               .dsvert_relay_validate_operation_id(operation_id),
               .dsvert_relay_validate_capability_id(capability_id), sep = "|")
  stream <- state$outgoing[[key]]
  if (is.null(stream) || !identical(stream$status, "building"))
    stop("Relay outbound stream is not open for appends.", call. = FALSE)
  offset <- .dsvert_relay_uint(offset, "relay append offset")
  if (!is.raw(payload) || !length(payload))
    stop("Relay append must contain raw ciphertext bytes.", call. = FALSE)
  index <- match(offset, stream$frame_offsets)
  if (is.na(index) || length(payload) != stream$frame_lengths[[index]])
    stop("Relay append does not match the immutable frame geometry.",
         call. = FALSE)
  size <- as.numeric(file.size(stream$path))
  if (is.na(size) || offset > size)
    stop("Relay append offset gap detected.", call. = FALSE)
  progressed <- FALSE
  if (offset < size) {
    existing <- .dsvert_relay_read_at(stream$path, offset, length(payload))
    if (!identical(existing, payload))
      stop("Conflicting retry for an outbound relay frame.", call. = FALSE)
  } else {
    .dsvert_relay_append(stream$path, payload, expected_offset = offset)
    size <- offset + length(payload)
    stream$last_activity <- .dsvert_relay_now()
    state$last_activity <- stream$last_activity
    progressed <- TRUE
  }
  state$outgoing[[key]] <- stream
  if (isTRUE(progressed)) {
    .session_progress(ss, state$last_activity)
  }
  invisible(as.numeric(size))
}

#' Abort one unpublished outbound stream and release its reservation.
#'
#' A sealed stream cannot be aborted because a peer may already have observed
#' it.  Callers can safely use this only while building, for example after a
#' local producer fails before publication.
#' @keywords internal
.dsvert_relay_queue_abort <- function(
    ss, operation_id, recipient_peer_id, capability_id) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  key <- paste(.dsvert_relay_validate_peer_id(recipient_peer_id),
               .dsvert_relay_validate_operation_id(operation_id),
               .dsvert_relay_validate_capability_id(capability_id), sep = "|")
  stream <- state$outgoing[[key]]
  if (is.null(stream)) return(invisible(FALSE))
  if (!identical(stream$status, "building"))
    stop("Only an unpublished outbound relay stream can be aborted.",
         call. = FALSE)
  if (is.character(stream$path) && length(stream$path) == 1L &&
      file.exists(stream$path)) unlink(stream$path)
  state$retained_bytes <- max(0, state$retained_bytes - stream$reservation)
  state$outgoing[[key]] <- NULL
  state$last_activity <- .dsvert_relay_now()
  .session_progress(ss, state$last_activity)
  invisible(TRUE)
}

#' Verify, sign, and publish one fully spooled ciphertext stream.
#' @keywords internal
.dsvert_relay_queue_seal <- function(
    ss, operation_id, recipient_peer_id, capability_id, payload_hash,
    signer = NULL) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  recipient_peer_id <- .dsvert_relay_validate_peer_id(recipient_peer_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  key <- paste(recipient_peer_id, operation_id, capability_id, sep = "|")
  stream <- state$outgoing[[key]]
  if (is.null(stream)) stop("Relay outbound stream does not exist.", call. = FALSE)
  if (!is.character(payload_hash) || length(payload_hash) != 1L ||
      is.na(payload_hash) || !grepl("^[0-9a-f]{64}$", payload_hash))
    stop("Invalid relay envelope hash.", call. = FALSE)
  if (identical(stream$status, "acknowledged")) {
    if (!identical(stream$payload_hash, payload_hash))
      stop("Conflicting retry for an acknowledged relay stream.", call. = FALSE)
    return(invisible(list(
      status = "acknowledged", total_bytes = stream$total_bytes,
      payload_hash = stream$payload_hash)))
  }
  if (identical(stream$status, "queued")) {
    if (!identical(stream$payload_hash, payload_hash))
      stop("Conflicting retry for a sealed relay stream.", call. = FALSE)
    return(invisible(list(status = "queued", total_bytes = stream$total_bytes,
                          payload_hash = stream$payload_hash)))
  }
  if (!identical(stream$status, "building"))
    stop("Relay outbound operation is poisoned; abort the session.",
         call. = FALSE)
  if (!is.null(stream$expected_hash) &&
      !identical(stream$expected_hash, payload_hash))
    stop("Relay seal hash conflicts with the reserved envelope.", call. = FALSE)
  size <- as.numeric(file.size(stream$path))
  actual <- if (!is.na(size) && size == stream$total_bytes)
    digest::digest(file = stream$path, algo = "sha256", serialize = FALSE) else ""
  if (!identical(actual, payload_hash)) {
    stream$status <- "poisoned"
    stream$last_activity <- .dsvert_relay_now()
    state$outgoing[[key]] <- stream
    stop("Relay seal rejected an incomplete or hash-mismatched stream.",
         call. = FALSE)
  }
  auth_message <- .dsvert_relay_auth_message(
    .DSVERT_RELAY_VERSION, state$session_id, operation_id, state$self_peer_id,
    recipient_peer_id, capability_id, stream$total_bytes, payload_hash)
  start_cursor <- if (length(state$outbox)) {
    state$outbox[[length(state$outbox)]]$end
  } else {
    state$outbox_base
  }
  descriptors <- vector("list", length(stream$frame_offsets))
  cursor <- start_cursor
  for (i in seq_along(stream$frame_offsets)) {
    descriptors[[i]] <- list(
      cursor = as.numeric(cursor),
      end = as.numeric(cursor + stream$frame_lengths[[i]]),
      stream_key = key, frame_index = as.integer(i),
      chunk_bytes = as.numeric(stream$frame_lengths[[i]]))
    cursor <- descriptors[[i]]$end
  }
  next_outbox <- c(state$outbox, descriptors)

  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    if (!identical(.dsvert_relay_peer_id(identity$identity_pk),
                   state$self_peer_id))
      stop("Runtime identity does not match the pinned relay identity.",
           call. = FALSE)
    signer <- function(message)
      .dsvert_relay_sign_message(message, identity$identity_sk)
  }
  signature <- signer(auth_message)
  if (length(.dsvert_relay_b64url_decode(signature, "relay signature")) != 64L)
    stop("Invalid relay signature length.", call. = FALSE)
  stream$payload_hash <- payload_hash
  stream$signature <- signature
  stream$status <- "queued"
  stream$last_activity <- .dsvert_relay_now()
  # Commit publication only after every descriptor and the signature have been
  # prepared.  A local allocation/signing failure leaves the stream retryable
  # in its unpublished building state.
  state$outgoing[[key]] <- stream
  state$outbox <- next_outbox
  state$last_activity <- stream$last_activity
  .session_progress(ss, state$last_activity)
  invisible(list(status = "queued", total_bytes = stream$total_bytes,
                 payload_hash = payload_hash,
                 frame_count = length(stream$frame_offsets)))
}

#' Queue one signed opaque envelope in a replayable server-owned outbox.
#'
#' Compatibility convenience for small in-memory ciphertext. Large producers
#' must call begin/append/seal so peak memory is bounded by one frame.
#' @keywords internal
.dsvert_relay_queue <- function(ss, operation_id, recipient_peer_id,
                                capability_id, payload, frame_bytes = NULL,
                                signer = NULL) {
  if (!is.raw(payload) || !length(payload))
    stop("Opaque relay payload must contain raw ciphertext bytes.", call. = FALSE)
  frame_bytes <- .dsvert_relay_frame_bytes(frame_bytes)
  if (length(payload) > frame_bytes) {
    stop("Multi-frame relay payloads require begin/append/seal streaming.",
         call. = FALSE)
  }
  payload_hash <- digest::digest(payload, algo = "sha256", serialize = FALSE)
  opened <- .dsvert_relay_queue_begin(
    ss, operation_id, recipient_peer_id, capability_id,
    total_bytes = as.numeric(length(payload)), payload_hash = payload_hash,
    frame_bytes = frame_bytes)
  state <- .dsvert_relay_state(ss)
  key <- paste(.dsvert_relay_validate_peer_id(recipient_peer_id),
               .dsvert_relay_validate_operation_id(operation_id),
               .dsvert_relay_validate_capability_id(capability_id), sep = "|")
  if (identical(opened$status, "acknowledged")) return(list())
  if (identical(opened$status, "building")) {
    stream <- state$outgoing[[key]]
    for (index in seq_along(stream$frame_offsets)) {
      first <- stream$frame_offsets[[index]] + 1
      last <- first + stream$frame_lengths[[index]] - 1
      .dsvert_relay_queue_append(
        ss, operation_id, recipient_peer_id, capability_id,
        stream$frame_offsets[[index]], payload[first:last])
    }
    .dsvert_relay_queue_seal(
      ss, operation_id, recipient_peer_id, capability_id, payload_hash,
      signer = signer)
  }
  state <- .dsvert_relay_state(ss)
  remaining <- state$outbox[vapply(
    state$outbox, function(value) identical(value$stream_key, key),
    logical(1L))]
  lapply(remaining, function(value) .dsvert_relay_materialize_frame(
    state, key, value$frame_index))
}

#' Materialise one bounded Base64 frame from the private raw spool.
#' @keywords internal
.dsvert_relay_materialize_frame <- function(state, stream_key, frame_index) {
  stream <- state$outgoing[[stream_key]]
  if (is.null(stream) || !identical(stream$status, "queued") ||
      !file.exists(stream$path))
    stop("Relay outbound operation is no longer available.", call. = FALSE)
  if (!is.numeric(frame_index) || length(frame_index) != 1L ||
      is.na(frame_index) || frame_index != floor(frame_index) ||
      frame_index < 1L || frame_index > length(stream$frame_offsets))
    stop("Invalid relay frame index.", call. = FALSE)
  offset <- stream$frame_offsets[[frame_index]]
  chunk_bytes <- stream$frame_lengths[[frame_index]]
  chunk <- .dsvert_relay_read_at(stream$path, offset, chunk_bytes)
  list(
    version = .DSVERT_RELAY_VERSION, session_id = state$session_id,
    operation_id = stream$operation_id, sender_peer_id = state$self_peer_id,
    recipient_peer_id = stream$recipient_peer_id,
    capability_id = stream$capability_id,
    sequence = as.numeric(frame_index - 1L), offset = offset,
    chunk_bytes = chunk_bytes, total_bytes = stream$total_bytes,
    final = identical(frame_index, length(stream$frame_offsets)),
    payload_hash = stream$payload_hash,
    chunk_hash = digest::digest(chunk, algo = "sha256", serialize = FALSE),
    payload = .dsvert_relay_b64url_encode(chunk),
    signature = stream$signature)
}

#' @keywords internal
.dsvert_relay_validate_frame <- function(frame, state) {
  required <- c("version", "session_id", "operation_id", "sender_peer_id",
                "recipient_peer_id", "capability_id", "sequence", "offset",
                "chunk_bytes", "total_bytes", "final", "payload_hash",
                "chunk_hash", "payload", "signature")
  if (!is.list(frame) || !identical(sort(names(frame)), sort(required)))
    stop("Relay frame schema is invalid.", call. = FALSE)
  version <- .dsvert_relay_scalar_string(frame$version, "relay version")
  if (!identical(version, .DSVERT_RELAY_VERSION))
    stop("Unsupported relay version.", call. = FALSE)
  session_id <- .dsvert_relay_validate_session_id(frame$session_id)
  if (!identical(session_id, state$session_id))
    stop("Relay frame belongs to a different session.", call. = FALSE)
  operation_id <- .dsvert_relay_validate_operation_id(frame$operation_id)
  sender <- .dsvert_relay_validate_peer_id(frame$sender_peer_id)
  recipient <- .dsvert_relay_validate_peer_id(frame$recipient_peer_id)
  if (!identical(recipient, state$self_peer_id))
    stop("Relay frame has the wrong recipient.", call. = FALSE)
  if (is.null(state$identity_pks[[sender]]) || identical(sender, recipient))
    stop("Relay frame does not have a pinned sender.", call. = FALSE)
  capability_id <- .dsvert_relay_validate_capability_id(frame$capability_id)
  if (!capability_id %in% state$allowed_capabilities)
    stop("Relay capability is not allowed by the session manifest.", call. = FALSE)
  sequence <- .dsvert_relay_uint(frame$sequence, "relay sequence")
  offset <- .dsvert_relay_uint(frame$offset, "relay offset")
  chunk_bytes <- .dsvert_relay_uint(frame$chunk_bytes, "relay chunk length")
  total_bytes <- .dsvert_relay_uint(frame$total_bytes, "relay total length")
  if (chunk_bytes < 1 || total_bytes < 1 || offset + chunk_bytes > total_bytes)
    stop("Invalid relay chunk length or offset.", call. = FALSE)
  if (chunk_bytes > state$exchange_max_bytes) {
    .dsvert_resource_oversize(
      chunk_bytes, state$exchange_max_bytes, "relay exchange chunk")
  }
  if (total_bytes > .dsvert_relay_max_envelope_bytes()) {
    .dsvert_resource_oversize(
      total_bytes, .dsvert_relay_max_envelope_bytes(),
      "relay maximum envelope")
  }
  metadata_bytes <- ceiling(total_bytes / chunk_bytes) *
    .DSVERT_RELAY_FRAME_METADATA_BYTES
  if (metadata_bytes > state$metadata_max_bytes) {
    .dsvert_resource_oversize(
      metadata_bytes, state$metadata_max_bytes,
      "relay control-plane metadata")
  }
  if (!is.logical(frame$final) || length(frame$final) != 1L || is.na(frame$final))
    stop("Invalid final-frame marker.", call. = FALSE)
  final <- isTRUE(frame$final)
  if (!identical(final, offset + chunk_bytes == total_bytes))
    stop("Invalid final frame boundary.", call. = FALSE)
  payload_hash <- .dsvert_relay_scalar_string(frame$payload_hash, "envelope hash")
  chunk_hash <- .dsvert_relay_scalar_string(frame$chunk_hash, "chunk hash")
  if (!grepl("^[0-9a-f]{64}$", payload_hash) ||
      !grepl("^[0-9a-f]{64}$", chunk_hash))
    stop("Invalid relay hash encoding.", call. = FALSE)
  if (!is.character(frame$payload) || length(frame$payload) != 1L ||
      is.na(frame$payload) ||
      nchar(frame$payload, type = "bytes") != ceiling(4 * chunk_bytes / 3))
    stop("Relay payload shape does not match its declared length.", call. = FALSE)
  payload <- .dsvert_relay_b64url_decode(frame$payload, "relay payload")
  if (length(payload) != chunk_bytes)
    stop("Relay chunk length does not match its bytes.", call. = FALSE)
  if (!identical(digest::digest(payload, algo = "sha256", serialize = FALSE),
                 chunk_hash))
    stop("Relay chunk hash mismatch.", call. = FALSE)
  signature <- .dsvert_relay_scalar_string(frame$signature, "relay signature")
  if (nchar(signature, type = "bytes") != 86L)
    stop("Invalid relay signature shape.", call. = FALSE)
  sig_raw <- .dsvert_relay_b64url_decode(signature, "relay signature")
  if (length(sig_raw) != 64L)
    stop("Invalid relay signature length.", call. = FALSE)
  list(frame = list(
    version = version, session_id = session_id, operation_id = operation_id,
    sender_peer_id = sender, recipient_peer_id = recipient,
    capability_id = capability_id, sequence = sequence, offset = offset,
    chunk_bytes = chunk_bytes, total_bytes = total_bytes, final = final,
    payload_hash = payload_hash, chunk_hash = chunk_hash,
    payload = .dsvert_relay_b64url_encode(payload),
    signature = .dsvert_relay_b64url_encode(sig_raw)), payload = payload,
    metadata_bytes = metadata_bytes)
}

#' Accept one frame with exact-retry idempotency.
#' @keywords internal
.dsvert_relay_accept <- function(ss, frame, verifier = NULL) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  checked <- .dsvert_relay_validate_frame(frame, state)
  frame <- checked$frame
  stream_key <- paste(frame$sender_peer_id, frame$operation_id,
                      frame$capability_id, sep = "|")
  stream <- state$inbox[[stream_key]]
  is_new <- is.null(stream)
  if (is_new) stream <- list(
    header = NULL, next_sequence = 0, next_offset = 0,
    fingerprints = list(), complete = FALSE, poisoned = FALSE,
    path = .dsvert_relay_spool_path(state, stream_key, "in"),
    total_bytes = frame$total_bytes, payload_hash = frame$payload_hash,
    frame_bytes = frame$chunk_bytes,
    reserved_bytes = frame$total_bytes + checked$metadata_bytes,
    read_offset = 0,
    created_at = .dsvert_relay_now(),
    last_activity = .dsvert_relay_now())
  if (isTRUE(stream$poisoned))
    stop("Relay envelope is poisoned; abort the protocol session.", call. = FALSE)
  offset_key <- format(frame$offset, scientific = FALSE, trim = TRUE)
  fingerprint <- digest::digest(frame, algo = "sha256")
  old <- stream$fingerprints[[offset_key]]
  if (!is.null(old)) {
    if (!identical(old, fingerprint))
      stop("Relay frame is a conflicting retry at an existing offset.", call. = FALSE)
    return(list(status = "duplicate", operation_id = frame$operation_id,
                offset = frame$offset,
                ack_offset = stream$next_offset,
                terminal = isTRUE(stream$complete), stream_key = stream_key))
  }
  if (isTRUE(stream$complete)) stop("Relay envelope is already complete.", call. = FALSE)
  if (frame$offset < stream$next_offset)
    stop("Relay frame is a conflicting retry inside an accepted range.", call. = FALSE)
  if (frame$offset > stream$next_offset)
    stop("Relay offset gap detected.", call. = FALSE)
  if (!identical(frame$sequence, stream$next_sequence))
    stop("Relay sequence gap detected.", call. = FALSE)
  expected_length <- min(stream$frame_bytes,
                         stream$total_bytes - stream$next_offset)
  if (!identical(frame$chunk_bytes, expected_length))
    stop("Relay frame geometry changed inside an envelope.", call. = FALSE)

  auth_message <- .dsvert_relay_auth_message(
    frame$version, frame$session_id, frame$operation_id, frame$sender_peer_id,
    frame$recipient_peer_id, frame$capability_id, frame$total_bytes,
    frame$payload_hash)
  header <- digest::digest(c(
    auth_message, .dsvert_relay_b64url_decode(frame$signature, "relay signature")),
    algo = "sha256", serialize = FALSE)
  if (is.null(stream$header)) {
    # Authenticate before allocating any inbox state.  This prevents an
    # untrusted relay from filling memory with incomplete envelopes while still
    # paying for only one Ed25519 verification per complete envelope, not one
    # verification per DSI frame.
    if (is.null(verifier)) verifier <- .dsvert_relay_verify_message
    if (!isTRUE(verifier(auth_message,
                         state$identity_pks[[frame$sender_peer_id]],
                         frame$signature)))
      stop("Relay envelope signature verification failed.", call. = FALSE)
    stream$header <- header
  } else if (!identical(stream$header, header))
    stop("Relay chunks carry conflicting authenticated headers.", call. = FALSE)
  if (is_new && stream$reserved_bytes > state$spool_max_bytes) {
    .dsvert_resource_oversize(
      stream$reserved_bytes, state$spool_max_bytes,
      "relay session spool")
  }
  if (is_new && state$retained_bytes >
      state$spool_max_bytes - stream$reserved_bytes) {
    .dsvert_resource_backpressure(
      state$retained_bytes, stream$reserved_bytes, state$spool_max_bytes,
      "relay session spool")
  }
  if (is_new) .dsvert_resource_admit(ss, stream$reserved_bytes)
  if (is_new) .dsvert_relay_private_write(stream$path, raw(0))
  prior_offset <- stream$next_offset
  committed <- FALSE
  on.exit(if (!committed) {
    if (is_new) unlink(stream$path) else
      try(.dsvert_relay_truncate(stream$path, prior_offset), silent = TRUE)
  }, add = TRUE)
  .dsvert_relay_append(stream$path, checked$payload, stream$next_offset)
  stream$fingerprints[[offset_key]] <- fingerprint
  stream$next_sequence <- stream$next_sequence + 1
  stream$next_offset <- stream$next_offset + frame$chunk_bytes
  stream$last_activity <- .dsvert_relay_now()

  status <- "accepted"
  if (frame$final) {
    size <- file.size(stream$path)
    if (length(size) != 1L || is.na(size) || size != frame$total_bytes ||
        !identical(digest::digest(
          file = stream$path, algo = "sha256", serialize = FALSE),
          frame$payload_hash)) {
      stream$poisoned <- TRUE
      next_inbox <- state$inbox
      next_inbox[[stream_key]] <- stream
      state$inbox <- next_inbox
      if (is_new) {
        state$retained_bytes <- state$retained_bytes + stream$reserved_bytes
      }
      committed <- TRUE
      stop("Relay envelope hash mismatch.", call. = FALSE)
    }
    stream$complete <- TRUE
    status <- "complete"
  }
  next_inbox <- state$inbox
  next_inbox[[stream_key]] <- stream
  state$inbox <- next_inbox
  if (is_new) state$retained_bytes <- state$retained_bytes + stream$reserved_bytes
  state$last_activity <- stream$last_activity
  committed <- TRUE
  .session_progress(ss, state$last_activity)
  list(status = status, operation_id = frame$operation_id,
       offset = frame$offset, ack_offset = stream$next_offset,
       terminal = isTRUE(stream$complete), stream_key = stream_key)
}

#' Read one complete opaque envelope from internal protocol code.
#' @keywords internal
.dsvert_relay_payload <- function(ss, sender_peer_id, operation_id,
                                  capability_id) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  sender_peer_id <- .dsvert_relay_validate_peer_id(sender_peer_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  key <- paste(sender_peer_id, operation_id, capability_id, sep = "|")
  stream <- state$inbox[[key]]
  if (is.null(stream) || !isTRUE(stream$complete) || isTRUE(stream$poisoned))
    return(NULL)
  value <- .dsvert_relay_read_at(stream$path, 0, stream$total_bytes)
  if (is.null(stream$read_offset) || stream$read_offset < stream$total_bytes) {
    stream$read_offset <- stream$total_bytes
    stream$last_activity <- .dsvert_relay_now()
    state$inbox[[key]] <- stream
    state$last_activity <- stream$last_activity
    .session_progress(ss, state$last_activity)
  }
  value
}

#' Read a bounded slice of one complete opaque envelope.
#'
#' Large protocol consumers should use this absolute-offset reader instead of
#' materialising the compatibility payload helper above.  Repeating an offset
#' is side-effect-free, and no call can allocate more than the negotiated
#' exchange bound.
#' @keywords internal
.dsvert_relay_payload_read <- function(
    ss, sender_peer_id, operation_id, capability_id, offset = 0,
    max_bytes = NULL) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  sender_peer_id <- .dsvert_relay_validate_peer_id(sender_peer_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  key <- paste(sender_peer_id, operation_id, capability_id, sep = "|")
  stream <- state$inbox[[key]]
  if (is.null(stream) || !isTRUE(stream$complete) || isTRUE(stream$poisoned))
    return(NULL)
  offset <- .dsvert_relay_uint(offset, "relay payload read offset")
  if (offset > stream$total_bytes)
    stop("Relay payload read offset exceeds the completed envelope.",
         call. = FALSE)
  if (is.null(max_bytes)) max_bytes <- state$exchange_max_bytes
  max_bytes <- .dsvert_relay_uint(max_bytes, "relay payload read bound")
  if (max_bytes < 1) {
    stop("Relay payload read bound must be positive.", call. = FALSE)
  }
  if (max_bytes > state$exchange_max_bytes) {
    .dsvert_resource_oversize(
      max_bytes, state$exchange_max_bytes, "relay payload read")
  }
  n <- min(max_bytes, stream$total_bytes - offset)
  value <- .dsvert_relay_read_at(stream$path, offset, n)
  next_offset <- offset + n
  read_offset <- if (is.null(stream$read_offset)) 0 else stream$read_offset
  if (next_offset > read_offset) {
    stream$read_offset <- next_offset
    stream$last_activity <- .dsvert_relay_now()
    state$inbox[[key]] <- stream
    state$last_activity <- stream$last_activity
    .session_progress(ss, state$last_activity)
  }
  list(
    operation_id = operation_id,
    offset = offset, next_offset = next_offset,
    total_bytes = stream$total_bytes,
    final = identical(next_offset, stream$total_bytes),
    payload_hash = stream$payload_hash, payload = value)
}

# Mark a fully read envelope as consumed while retaining only the bounded
# terminal DSI request fingerprints needed for an ambiguous-response replay.
# The encrypted payload itself remains available for replay of the current
# consumer call.  It is reclaimed when the next stream on the same pinned
# sender/capability route proves that the previous response was observed, or at
# session cleanup.  Thus long sessions retain at most one consumed payload per
# route instead of one payload per operation.
.dsvert_relay_mark_payload_consumed <- function(
    ss, sender_peer_id, operation_id, capability_id) {
  state <- .dsvert_relay_state(ss)
  sender_peer_id <- .dsvert_relay_validate_peer_id(sender_peer_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  key <- paste(sender_peer_id, operation_id, capability_id, sep = "|")
  stream <- state$inbox[[key]]
  if (is.null(stream) || !isTRUE(stream$complete) ||
      isTRUE(stream$poisoned) ||
      !identical(as.numeric(stream$read_offset),
                 as.numeric(stream$total_bytes)) ||
      is.null(stream$receipt)) {
    stop("Relay payload cannot be released before complete verified consumption.",
         call. = FALSE)
  }
  if (isTRUE(stream$consumed)) return(invisible(TRUE))
  replay <- stream$terminal_replay_fingerprints
  if (!is.list(replay) || !length(replay)) replay <- stream$fingerprints
  stream$fingerprints <- replay
  stream$terminal_replay_fingerprints <- NULL
  stream$consumed <- TRUE
  stream$consumed_at <- .dsvert_relay_now()
  state$inbox[[key]] <- stream
  route <- paste(sender_peer_id, capability_id, sep = "|")
  previous_key <- state$inbox_latest_consumed[[route]]
  if (is.character(previous_key) && length(previous_key) == 1L &&
      !is.na(previous_key) && nzchar(previous_key) &&
      !identical(previous_key, key)) {
    previous <- state$inbox[[previous_key]]
    if (is.list(previous) && isTRUE(previous$consumed)) {
      expected <- .dsvert_relay_spool_path(state, previous_key, "in")
      if (is.character(previous$path) && length(previous$path) == 1L &&
          !is.na(previous$path) && nzchar(previous$path) &&
          identical(normalizePath(previous$path, mustWork = FALSE),
                    normalizePath(expected, mustWork = FALSE)) &&
          file.exists(previous$path)) {
        unlink(previous$path)
      }
      if (!is.null(previous$path) && file.exists(previous$path)) {
        stop("Could not reclaim a consumed relay payload.", call. = FALSE)
      }
      state$retained_bytes <- max(
        0, state$retained_bytes - as.numeric(previous$reserved_bytes))
      state$inbox[[previous_key]] <- NULL
    }
  }
  state$inbox_latest_consumed[[route]] <- key
  state$last_activity <- stream$consumed_at
  .session_progress(ss, state$last_activity)
  invisible(TRUE)
}

#' Canonical terminal-receipt message signed by the receiving peer.
#' @keywords internal
.dsvert_relay_receipt_message <- function(receipt) {
  fields <- c(
    receipt$version, receipt$session_id, receipt$operation_id,
    receipt$sender_peer_id, receipt$recipient_peer_id,
    receipt$capability_id,
    format(receipt$total_bytes, scientific = FALSE, trim = TRUE),
    receipt$payload_hash,
    format(receipt$ack_offset, scientific = FALSE, trim = TRUE))
  framed <- vapply(fields, function(value)
    paste0(nchar(value, type = "bytes"), ":", value), character(1L))
  charToRaw(paste0(.DSVERT_RELAY_RECEIPT_DOMAIN,
                   paste0(framed, collapse = "")))
}

#' @keywords internal
.dsvert_relay_terminal_receipt <- function(state, stream_key, signer = NULL) {
  stream <- state$inbox[[stream_key]]
  if (is.null(stream) || !isTRUE(stream$complete) || isTRUE(stream$poisoned))
    stop("Cannot receipt an incomplete relay envelope.", call. = FALSE)
  if (!is.null(stream$receipt)) return(stream$receipt)
  parts <- strsplit(stream_key, "|", fixed = TRUE)[[1L]]
  if (length(parts) != 3L)
    stop("Invalid completed relay stream key.", call. = FALSE)
  receipt <- list(
    version = .DSVERT_RELAY_RECEIPT_VERSION,
    session_id = state$session_id, operation_id = parts[[2L]],
    sender_peer_id = parts[[1L]], recipient_peer_id = state$self_peer_id,
    capability_id = parts[[3L]], total_bytes = stream$total_bytes,
    payload_hash = stream$payload_hash, ack_offset = stream$total_bytes,
    terminal = TRUE)
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    if (!identical(.dsvert_relay_peer_id(identity$identity_pk),
                   state$self_peer_id))
      stop("Runtime identity does not match the pinned relay identity.",
           call. = FALSE)
    signer <- function(message)
      .dsvert_relay_sign_message(message, identity$identity_sk)
  }
  receipt$signature <- signer(.dsvert_relay_receipt_message(receipt))
  if (length(.dsvert_relay_b64url_decode(
        receipt$signature, "relay receipt signature")) != 64L)
    stop("Invalid relay receipt signature length.", call. = FALSE)
  stream$receipt <- receipt
  state$inbox[[stream_key]] <- stream
  receipt
}

#' Verify a terminal receipt against the pinned receiving peer.
#' @keywords internal
.dsvert_relay_verify_receipt <- function(ss, receipt, verifier = NULL) {
  state <- .dsvert_relay_state(ss)
  required <- c(
    "version", "session_id", "operation_id", "sender_peer_id",
    "recipient_peer_id", "capability_id", "total_bytes", "payload_hash",
    "ack_offset", "terminal", "signature")
  if (!is.list(receipt) || !identical(sort(names(receipt)), sort(required)))
    stop("Relay terminal receipt schema is invalid.", call. = FALSE)
  if (!identical(receipt$version, .DSVERT_RELAY_RECEIPT_VERSION) ||
      !identical(.dsvert_relay_validate_session_id(receipt$session_id),
                 state$session_id) ||
      !identical(.dsvert_relay_validate_peer_id(receipt$sender_peer_id),
                 state$self_peer_id) ||
      !isTRUE(receipt$terminal))
    stop("Relay terminal receipt context is invalid.", call. = FALSE)
  recipient <- .dsvert_relay_validate_peer_id(receipt$recipient_peer_id)
  if (is.null(state$identity_pks[[recipient]]) ||
      identical(recipient, state$self_peer_id))
    stop("Relay receipt does not have a pinned receiving peer.", call. = FALSE)
  operation <- .dsvert_relay_validate_operation_id(receipt$operation_id)
  capability <- .dsvert_relay_validate_capability_id(receipt$capability_id)
  total <- .dsvert_relay_uint(receipt$total_bytes, "receipt total length")
  ack <- .dsvert_relay_uint(receipt$ack_offset, "receipt byte offset")
  if (!identical(total, ack) || total < 1 ||
      !is.character(receipt$payload_hash) ||
      length(receipt$payload_hash) != 1L || is.na(receipt$payload_hash) ||
      !grepl("^[0-9a-f]{64}$", receipt$payload_hash))
    stop("Relay terminal receipt bounds are invalid.", call. = FALSE)
  outgoing_key <- paste(recipient, operation, capability, sep = "|")
  outgoing <- state$outgoing[[outgoing_key]]
  if (is.null(outgoing) || !identical(outgoing$total_bytes, total) ||
      !identical(outgoing$payload_hash, receipt$payload_hash))
    stop("Relay terminal receipt does not match an outbound envelope.",
         call. = FALSE)
  signature <- .dsvert_relay_scalar_string(
    receipt$signature, "relay receipt signature")
  if (length(.dsvert_relay_b64url_decode(
        signature, "relay receipt signature")) != 64L)
    stop("Invalid relay receipt signature length.", call. = FALSE)
  normalized <- receipt
  normalized$total_bytes <- total
  normalized$ack_offset <- ack
  normalized$signature <- signature
  if (is.null(verifier)) verifier <- .dsvert_relay_verify_message
  if (!isTRUE(verifier(
        .dsvert_relay_receipt_message(normalized),
        state$identity_pks[[recipient]], signature)))
    stop("Relay terminal receipt signature verification failed.",
         call. = FALSE)
  TRUE
}

.dsvert_relay_record_verified_receipt <- function(ss, receipt) {
  state <- .dsvert_relay_state(ss)
  recipient <- .dsvert_relay_validate_peer_id(receipt$recipient_peer_id)
  operation <- .dsvert_relay_validate_operation_id(receipt$operation_id)
  capability <- .dsvert_relay_validate_capability_id(receipt$capability_id)
  key <- paste(recipient, operation, capability, sep = "|")
  outgoing <- state$outgoing[[key]]
  if (is.null(outgoing) ||
      !identical(outgoing$payload_hash, receipt$payload_hash) ||
      !identical(as.numeric(outgoing$total_bytes),
                 as.numeric(receipt$total_bytes))) {
    stop("Relay terminal receipt does not match retained outbound state.",
         call. = FALSE)
  }
  route <- paste(recipient, capability, sep = "|")
  previous_key <- state$outgoing_latest_receipt[[route]]
  if (is.character(previous_key) && length(previous_key) == 1L &&
      !is.na(previous_key) && nzchar(previous_key) &&
      !identical(previous_key, key)) {
    previous <- state$outgoing[[previous_key]]
    if (is.list(previous) && identical(previous$status, "acknowledged") &&
        is.null(previous$path)) {
      state$outgoing[[previous_key]] <- NULL
    }
  }
  state$outgoing_latest_receipt[[route]] <- key
  invisible(TRUE)
}

#' Compact only an exactly acknowledged prefix of the absolute byte stream.
#' @keywords internal
.dsvert_relay_compact_outbox <- function(state, cursor) {
  cursor <- .dsvert_relay_uint(cursor, "outbox byte cursor")
  eof <- if (length(state$outbox)) {
    state$outbox[[length(state$outbox)]]$end
  } else {
    state$outbox_base
  }
  boundaries <- c(state$outbox_base,
                  vapply(state$outbox, `[[`, numeric(1L), "end"))
  if (cursor < state$outbox_base || cursor > eof || !cursor %in% boundaries)
    stop("Relay outbox cursor is not an acknowledged frame boundary.",
         call. = FALSE)
  if (cursor == state$outbox_base) return(invisible(cursor))
  drop <- which(vapply(
    state$outbox, function(value) value$end <= cursor, logical(1L)))
  dropped_keys <- unique(vapply(
    state$outbox[drop], `[[`, character(1L), "stream_key"))
  state$outbox <- if (length(drop) == length(state$outbox)) list() else
    state$outbox[-drop]
  state$outbox_base <- cursor
  remaining_keys <- if (length(state$outbox)) unique(vapply(
    state$outbox, `[[`, character(1L), "stream_key")) else character()
  for (key in setdiff(dropped_keys, remaining_keys)) {
    stream <- state$outgoing[[key]]
    if (!is.null(stream) && identical(stream$status, "queued")) {
      if (file.exists(stream$path)) unlink(stream$path)
      state$retained_bytes <- max(0, state$retained_bytes - stream$reservation)
      stream$status <- "acknowledged"
      stream$path <- NULL
      stream$frame_offsets <- numeric()
      stream$frame_lengths <- numeric()
      stream$last_activity <- .dsvert_relay_now()
      state$outgoing[[key]] <- stream
    }
  }
  invisible(cursor)
}

#' Apply this node's slice of one DSI fan-out request atomically.
#'
#' The caller-owned cursor only selects a suffix; it never deletes the
#' append-only outbox.  It is an absolute byte acknowledgement and may compact
#' only complete frame boundaries.  One response is capped by the public
#' exchange-byte policy, which provides backpressure without a request quota.
#' @keywords internal
.dsvert_relay_exchange <- function(ss, request_map, verifier = NULL,
                                   receipt_signer = NULL,
                                   outbound_operation_id = NULL) {
  state <- .dsvert_relay_state(ss)
  .dsvert_relay_gc(ss)
  state <- .dsvert_relay_state(ss)
  if (!is.null(outbound_operation_id)) {
    outbound_operation_id <- .dsvert_relay_validate_operation_id(
      outbound_operation_id)
  }
  if (!is.list(request_map) || is.null(names(request_map)) ||
      any(!nzchar(names(request_map))) || anyDuplicated(names(request_map)))
    stop("Relay fan-out request must be a uniquely named map.", call. = FALSE)
  route_ids <- vapply(names(request_map), .dsvert_relay_validate_peer_id,
                      character(1L))
  if (any(!route_ids %in% names(state$identity_pks)))
    stop("Relay request contains an unpinned route.", call. = FALSE)
  route <- request_map[[state$self_peer_id]]
  if (is.null(route) || !is.list(route))
    stop("Relay request has no route for this pinned peer.", call. = FALSE)
  allowed <- c("outbox_cursor", "deliveries")
  if (is.null(names(route)) || any(!names(route) %in% allowed) ||
      anyDuplicated(names(route)))
    stop("Relay route schema is invalid.", call. = FALSE)
  cursor <- if (is.null(route$outbox_cursor)) state$outbox_base else
    .dsvert_relay_uint(route$outbox_cursor, "outbox cursor")
  previous_cursor <- state$outbox_base
  .dsvert_relay_compact_outbox(state, cursor)
  if (cursor > previous_cursor) {
    state$last_activity <- .dsvert_relay_now()
    .session_progress(ss, state$last_activity)
  }
  deliveries <- route$deliveries
  if (is.null(deliveries)) deliveries <- list()
  if (!is.list(deliveries))
    stop("Relay deliveries must be a list of frames.", call. = FALSE)
  declared <- vapply(deliveries, function(frame) {
    if (!is.list(frame) || is.null(frame$chunk_bytes))
      stop("Relay delivery frame schema is invalid.", call. = FALSE)
    .dsvert_relay_uint(frame$chunk_bytes, "relay declared chunk length")
  }, numeric(1L))
  declared_total <- sum(declared)
  if (declared_total > state$exchange_max_bytes) {
    .dsvert_resource_oversize(
      declared_total, state$exchange_max_bytes,
      "relay exchange deliveries")
  }

  before <- state$inbox
  before_retained <- state$retained_bytes
  before_activity <- state$last_activity
  before_session_activity <- ss$.last_activity
  before_paths <- unique(vapply(before, function(stream)
    if (is.character(stream$path) && length(stream$path) == 1L) stream$path else
      "", character(1L)))
  before_paths <- before_paths[nzchar(before_paths)]
  before_sizes <- if (length(before_paths)) stats::setNames(
    vapply(before_paths, function(path) {
      size <- if (file.exists(path)) file.size(path) else 0
      if (is.na(size)) stop("Invalid relay spool size.", call. = FALSE)
      as.numeric(size)
    }, numeric(1L)), before_paths) else numeric()
  accepted <- tryCatch({
    values <- lapply(deliveries, function(frame)
      .dsvert_relay_accept(ss, frame, verifier = verifier))
    for (index in seq_along(values)) {
      if (isTRUE(values[[index]]$terminal)) {
        values[[index]]$receipt <- .dsvert_relay_terminal_receipt(
          state, values[[index]]$stream_key, signer = receipt_signer)
      }
    }
    terminal_keys <- unique(vapply(
      values[vapply(values, `[[`, logical(1L), "terminal")],
      `[[`, character(1L), "stream_key"))
    for (stream_key in terminal_keys) {
      stream <- state$inbox[[stream_key]]
      members <- values[vapply(
        values, function(value) identical(value$stream_key, stream_key),
        logical(1L))]
      offsets <- vapply(members, `[[`, numeric(1L), "offset")
      offset_keys <- format(offsets, scientific = FALSE, trim = TRUE)
      replay <- stream$fingerprints[offset_keys]
      if (length(replay) != length(offset_keys) || any(vapply(
          replay, is.null, logical(1L)))) {
        stop("Relay terminal replay metadata is incomplete.", call. = FALSE)
      }
      stream$terminal_replay_fingerprints <- replay
      state$inbox[[stream_key]] <- stream
    }
    for (index in seq_along(values)) {
      values[[index]]$stream_key <- NULL
    }
    values
  }, error = function(e) {
      current_paths <- unique(vapply(state$inbox, function(stream)
        if (is.character(stream$path) && length(stream$path) == 1L)
          stream$path else "", character(1L)))
      current_paths <- current_paths[nzchar(current_paths)]
      for (path in setdiff(current_paths, before_paths)) unlink(path)
      for (path in before_paths) {
        .dsvert_relay_truncate(path, before_sizes[[path]])
      }
      state$inbox <- before
      state$retained_bytes <- before_retained
      state$last_activity <- before_activity
      ss$.last_activity <- before_session_activity
      stop(e)
    })
  selected <- list()
  selected_bytes <- 0
  if (length(state$outbox)) {
    for (descriptor in state$outbox) {
      if (!is.null(outbound_operation_id)) {
        stream <- state$outgoing[[descriptor$stream_key]]
        if (is.null(stream) ||
            !identical(stream$operation_id, outbound_operation_id)) break
      }
      if (selected_bytes + descriptor$chunk_bytes > state$exchange_max_bytes)
        break
      selected[[length(selected) + 1L]] <- descriptor
      selected_bytes <- selected_bytes + descriptor$chunk_bytes
    }
  }
  outbound <- lapply(selected, function(descriptor)
    .dsvert_relay_materialize_frame(
      state, descriptor$stream_key, descriptor$frame_index))
  next_cursor <- if (length(selected)) selected[[length(selected)]]$end else cursor
  eof <- if (length(state$outbox)) {
    state$outbox[[length(state$outbox)]]$end
  } else {
    state$outbox_base
  }
  list(peer_id = state$self_peer_id, accepted = accepted,
       outbox_cursor = as.numeric(next_cursor), outbox_eof = as.numeric(eof),
       outbound = outbound)
}
