# Durable local transport boundary for formal-GLM Phase 1.8 v2.
#
# This file deliberately exports no DataSHIELD method.  The source outbox
# commits the first encrypted bundle occupying a semantic source/block slot and
# returns those exact bytes on every retry.  The recipient inbox authenticates
# the pinned source bundle, selects only its ciphertext, and persists a bounded
# server-local frame for the Go Phase-1.9 finalizer.  Neither store ever writes
# decrypted coordinates, validity, alignment gates, or consensus digests.

.DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAGIC <- charToRaw("DSVFG182")
.DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAC_DOMAIN <-
  "dsVert/formal-glm/phase18/local-ingress-frame/v2"
.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAGIC <- charToRaw("DSVFG18O")
.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAC_DOMAIN <-
  "dsVert/formal-glm/phase18/source-outbox/v2"
.DSVERT_FORMAL_GLM_PHASE18_DURABLE_VERSION <-
  "dsvert-formal-glm-phase18-durable-local-boundary-v2"
.DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES <- 2L * 1024L^2
.DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES <- 4L * 1024L^2

.dsvert_formal_glm_phase18_durable_abort <- function(message, code) {
  .dsvert_formal_glm_phase18_abort(message, code)
}

.dsvert_formal_glm_phase18_durable_root <- function(
    root = file.path(.dsvert_state_root(), "formal-glm-phase18-v2")) {
  if (!is.character(root) || length(root) != 1L || is.na(root) ||
      !nzchar(root)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 durable state root is unavailable.",
      "durable_state_unavailable")
  }
  root <- path.expand(root)
  if (!grepl("^/", root)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 durable state root must be absolute.",
      "durable_state_unavailable")
  }
  root
}

.dsvert_formal_glm_phase18_private_dir <- function(path) {
  if (!dir.exists(path) &&
      !dir.create(path, recursive = TRUE, showWarnings = FALSE,
                  mode = "0700")) {
    .dsvert_formal_glm_phase18_durable_abort(
      "Could not create the private Phase-1.8 durable directory.",
      "durable_state_unavailable")
  }
  if (.dsvert_dp_path_is_link(path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable directory must not be a symbolic link.",
      "unsafe_durable_state")
  }
  Sys.chmod(path, mode = "0700")
  if (!.dsvert_dp_private_mode(path, directory = TRUE)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable directory must be owner-only.",
      "unsafe_durable_state")
  }
  normalizePath(path, winslash = "/", mustWork = TRUE)
}

.dsvert_formal_glm_phase18_private_file <- function(
    path, minimum_bytes = 1L,
    maximum_bytes = .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES + 1024L) {
  if (!file.exists(path) || !file_test("-f", path) ||
      .dsvert_dp_path_is_link(path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable record is not an owner-only regular file.",
      "unsafe_durable_state")
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) ||
      info$size < minimum_bytes || info$size > maximum_bytes) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable record has an invalid bounded size.",
      "unsafe_durable_state")
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  value <- readBin(path, what = "raw", n = info$size + 1L)
  after <- unname(file.info(path)[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(path) || !identical(before, after) ||
      length(value) != info$size) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable record changed while it was read.",
      "unsafe_durable_state")
  }
  value
}

.dsvert_formal_glm_phase18_key_path <- function(root) {
  file.path(root, "finalizer.key")
}

.dsvert_formal_glm_phase18_key_valid <- function(key) {
  is.raw(key) && length(key) == 32L && any(as.integer(key) != 0L)
}

.dsvert_formal_glm_phase18_validate_key <- function(path) {
  encoded <- .dsvert_formal_glm_phase18_private_file(
    path, minimum_bytes = 44L, maximum_bytes = 44L)
  text <- rawToChar(encoded)
  key <- tryCatch(jsonlite::base64_dec(text), error = function(error) raw())
  if (!.dsvert_formal_glm_phase18_key_valid(key) ||
      !identical(gsub("[\r\n]", "", jsonlite::base64_enc(key)), text)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 finalizer key is invalid.",
      "unsafe_durable_state")
  }
  key
}

.dsvert_formal_glm_phase18_init_key <- function(
    root = .dsvert_formal_glm_phase18_durable_root(),
    random_bytes = .dsvert_secure_random_bytes) {
  root <- .dsvert_formal_glm_phase18_private_dir(
    .dsvert_formal_glm_phase18_durable_root(root))
  path <- .dsvert_formal_glm_phase18_key_path(root)
  if (file.exists(path)) return(.dsvert_formal_glm_phase18_validate_key(path))
  if (.dsvert_dp_path_is_link(path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 finalizer key must not be a symbolic link.",
      "unsafe_durable_state")
  }
  lock_path <- paste0(path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 finalizer key lock must not be a symbolic link.",
      "unsafe_durable_state")
  }
  old_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(old_umask), silent = TRUE), add = TRUE)
  # LockFileEx is mandatory on Windows: never stat/chmod a lock through a
  # second handle while it is held.  The owner-only root plus umask protects
  # this empty coordination file.
  lock <- filelock::lock(lock_path, timeout = Inf)
  if (is.null(lock)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 finalizer key lock is unavailable.",
      "durable_state_unavailable")
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  if (file.exists(path)) return(.dsvert_formal_glm_phase18_validate_key(path))
  key <- random_bytes(32L)
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "Secure entropy did not return a 256-bit Phase-1.8 finalizer key.",
      "durable_state_unavailable")
  }
  temporary <- tempfile(
    paste0(".phase18-key-", Sys.getpid(), "."), tmpdir = root)
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(gsub(
    "[\r\n]", "", jsonlite::base64_enc(key))), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_formal_glm_phase18_validate_key(temporary))
  .dsvert_identity_require_sync(temporary, "staged Phase-1.8 finalizer key")
  if (file.exists(path)) return(.dsvert_formal_glm_phase18_validate_key(path))
  if (!file.rename(temporary, path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "Could not atomically commit the Phase-1.8 finalizer key.",
      "durable_state_unavailable")
  }
  Sys.chmod(path, mode = "0600")
  key <- .dsvert_formal_glm_phase18_validate_key(path)
  .dsvert_identity_require_sync(root, "Phase-1.8 finalizer directory")
  key
}

.dsvert_formal_glm_phase18_key_id <- function(key) {
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 finalizer key is unavailable.",
      "durable_state_unavailable")
  }
  .dsvert_formal_glm_phase18_sha256(c(
    charToRaw("dsVert/formal-glm/phase18/finalizer-key-id/v2|"), key))
}

.dsvert_formal_glm_phase18_uint32 <- function(value) {
  value <- .dsvert_formal_glm_phase18_integer(
    value, "durable uint32", 0, 2^32 - 1)
  as.raw(c(
    floor(value / 2^24) %% 256,
    floor(value / 2^16) %% 256,
    floor(value / 2^8) %% 256,
    value %% 256))
}

.dsvert_formal_glm_phase18_frame_append_string <- function(target, value) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, "durable frame string", maximum_bytes = 4096L)
  raw <- charToRaw(value)
  c(target, .dsvert_formal_glm_phase18_uint32(length(raw)), raw)
}

.dsvert_formal_glm_phase18_frame_mac <- function(key, message) {
  digest::hmac(
    key = key,
    object = c(charToRaw(.DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAC_DOMAIN),
               as.raw(0L), message),
    algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_formal_glm_phase18_frame_encode <- function(frame, key) {
  string_fields <- c(
    "capsule_sha256", "plan_sha256", "pre_execution_sha256",
    "global_materialization_root", "run_id", "source_name",
    "recipient_name", "recipient_ticket_sha256", "pair_commitment_sha256",
    "block_commitment_sha256", "ciphertext_sha256", "envelope_sha256")
  integer_fields <- c(
    "source_slot", "recipient_slot", "block_index", "total_blocks",
    "global_slot_offset", "slots_in_block", "coordinate_count",
    "coordinate_records", "ring_bits", "record_bytes", "validity_records")
  required <- c(string_fields, integer_fields, "ciphertext")
  if (!.dsvert_formal_glm_phase18_key_valid(key) ||
      !is.list(frame) || !setequal(names(frame), required) ||
      !is.raw(frame$ciphertext) || !length(frame$ciphertext)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress frame is invalid.",
      "invalid_durable_frame")
  }
  hash_fields <- c(
    "capsule_sha256", "plan_sha256", "pre_execution_sha256",
    "global_materialization_root", "recipient_ticket_sha256",
    "pair_commitment_sha256", "block_commitment_sha256",
    "ciphertext_sha256", "envelope_sha256")
  if (!all(vapply(frame[hash_fields], function(value) {
    is.character(value) && length(value) == 1L &&
      grepl("^[0-9a-f]{64}$", value)
  }, logical(1L))) ||
      !identical(frame$ciphertext_sha256,
        .dsvert_formal_glm_phase18_sha256(frame$ciphertext))) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress commitments are invalid.",
      "invalid_durable_frame")
  }
  values <- vapply(integer_fields, function(field) {
    .dsvert_formal_glm_phase18_integer(
      frame[[field]], paste0("frame ", field), 0, 2^53 - 1)
  }, numeric(1L))
  container_bits <- 64
  while (container_bits < values[["ring_bits"]]) {
    container_bits <- container_bits * 2
  }
  expected_record_bytes <- container_bits / 8
  share_bytes <- values[["coordinate_records"]] *
    values[["record_bytes"]] + values[["validity_records"]]
  maximum_ciphertext <- 60 + 4 + 65535 + share_bytes
  if (values[["source_slot"]] >= 2^31 ||
      values[["recipient_slot"]] > 1 || values[["total_blocks"]] < 1 ||
      values[["block_index"]] >= values[["total_blocks"]] ||
      values[["slots_in_block"]] < 1 || values[["slots_in_block"]] > 8 ||
      values[["coordinate_count"]] < 4 ||
      values[["coordinate_count"]] > 7 ||
      values[["coordinate_records"]] !=
        values[["slots_in_block"]] * values[["coordinate_count"]] ||
      values[["ring_bits"]] < 128 || values[["ring_bits"]] > 4096 ||
      values[["record_bytes"]] != expected_record_bytes ||
      values[["validity_records"]] != values[["slots_in_block"]] ||
      length(frame$ciphertext) < 60 + 4 + 2 + share_bytes ||
      length(frame$ciphertext) > maximum_ciphertext ||
      length(frame$ciphertext) + 512 >
        .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress shape is outside its fixed bound.",
      "invalid_durable_frame")
  }
  message <- .DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAGIC
  for (field in string_fields) {
    message <- .dsvert_formal_glm_phase18_frame_append_string(
      message, frame[[field]])
  }
  for (field in integer_fields) {
    message <- c(message, .dsvert_formal_glm_phase18_uint64(values[[field]]))
  }
  message <- c(
    message,
    .dsvert_formal_glm_phase18_uint32(length(frame$ciphertext)),
    frame$ciphertext)
  encoded <- c(message, .dsvert_formal_glm_phase18_frame_mac(key, message))
  if (length(encoded) > .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress frame exceeds its fixed bound.",
      "invalid_durable_frame")
  }
  encoded
}

.dsvert_formal_glm_phase18_read_uint32 <- function(value, offset) {
  if (offset < 1L || offset + 3L > length(value)) return(NULL)
  bytes <- as.numeric(value[offset:(offset + 3L)])
  list(value = sum(bytes * c(2^24, 2^16, 2^8, 1)), offset = offset + 4L)
}

.dsvert_formal_glm_phase18_frame_verify <- function(encoded, key) {
  if (!.dsvert_formal_glm_phase18_key_valid(key) ||
      !is.raw(encoded) || length(encoded) < 64L ||
      length(encoded) > .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress frame has an invalid size.",
      "invalid_durable_frame")
  }
  message <- encoded[seq_len(length(encoded) - 32L)]
  mac <- encoded[(length(encoded) - 31L):length(encoded)]
  if (!identical(mac, .dsvert_formal_glm_phase18_frame_mac(key, message)) ||
      !identical(message[seq_along(
        .DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAGIC)],
        .DSVERT_FORMAL_GLM_PHASE18_INGRESS_MAGIC)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 local ingress frame failed authentication.",
      "invalid_durable_frame")
  }
  invisible(TRUE)
}

.dsvert_formal_glm_phase18_atomic_cas <- function(
    path, payload, maximum_bytes, temporary_prefix) {
  if (!is.raw(payload) || !length(payload) || length(payload) > maximum_bytes) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 durable payload exceeds its fixed bound.",
      "invalid_durable_frame")
  }
  if (!is.character(temporary_prefix) || length(temporary_prefix) != 1L ||
      is.na(temporary_prefix) ||
      !grepl("^\\.phase18-[a-z0-9-]{1,160}$", temporary_prefix)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 temporary-file namespace is invalid.",
      "invalid_durable_frame")
  }
  directory <- .dsvert_formal_glm_phase18_private_dir(dirname(path))
  path <- file.path(directory, basename(path))
  lock_path <- paste0(path, ".lock")
  if (.dsvert_dp_path_is_link(path) || .dsvert_dp_path_is_link(lock_path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable slot must not be a symbolic link.",
      "unsafe_durable_state")
  }
  old_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(old_umask), silent = TRUE), add = TRUE)
  # See the key-lock note above: the lock itself carries no durable payload.
  lock <- filelock::lock(lock_path, timeout = Inf)
  if (is.null(lock)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable slot lock is unavailable.",
      "durable_state_unavailable")
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  stale <- list.files(
    directory, all.files = TRUE, no.. = TRUE, full.names = TRUE)
  stale <- stale[startsWith(basename(stale), temporary_prefix)]
  for (candidate in stale) {
    invisible(.dsvert_formal_glm_phase18_private_file(
      candidate, 1L, maximum_bytes))
    unlink(candidate, force = TRUE)
  }
  if (file.exists(path)) {
    existing <- .dsvert_formal_glm_phase18_private_file(
      path, 1L, maximum_bytes)
    if (!identical(existing, payload)) {
      .dsvert_formal_glm_phase18_durable_abort(
        "A conflicting authenticated retry targeted the same Phase-1.8 slot.",
        "conflicting_durable_replay")
    }
    return(list(replayed = TRUE, payload = existing, path = path))
  }
  temporary <- tempfile(temporary_prefix, tmpdir = directory)
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(payload, connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  staged <- .dsvert_formal_glm_phase18_private_file(
    temporary, 1L, maximum_bytes)
  if (!identical(staged, payload)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The staged Phase-1.8 durable payload changed before commit.",
      "unsafe_durable_state")
  }
  .dsvert_identity_require_sync(temporary, "staged Phase-1.8 durable record")
  if (file.exists(path)) {
    existing <- .dsvert_formal_glm_phase18_private_file(
      path, 1L, maximum_bytes)
    if (!identical(existing, payload)) {
      .dsvert_formal_glm_phase18_durable_abort(
        "A conflicting authenticated retry won the Phase-1.8 slot race.",
        "conflicting_durable_replay")
    }
    return(list(replayed = TRUE, payload = existing, path = path))
  }
  if (!file.rename(temporary, path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "Could not atomically commit the Phase-1.8 durable record.",
      "durable_state_unavailable")
  }
  Sys.chmod(path, mode = "0600")
  committed <- .dsvert_formal_glm_phase18_private_file(
    path, 1L, maximum_bytes)
  if (!identical(committed, payload)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The committed Phase-1.8 durable record changed.",
      "unsafe_durable_state")
  }
  .dsvert_identity_require_sync(directory, "Phase-1.8 durable slot directory")
  list(replayed = FALSE, payload = committed, path = path)
}

.dsvert_formal_glm_phase18_outbox_encode <- function(slot, bundle_json, key) {
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 source outbox key is unavailable.",
      "durable_state_unavailable")
  }
  slot <- .dsvert_formal_glm_phase18_scalar(
    slot, "outbox slot", pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
  bundle_json <- .dsvert_formal_glm_phase18_scalar(
    bundle_json, "durable encrypted bundle",
    maximum_bytes = .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES)
  payload <- charToRaw(bundle_json)
  message <- c(
    .DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAGIC, charToRaw(slot),
    .dsvert_formal_glm_phase18_uint32(length(payload)), payload)
  mac <- digest::hmac(
    key = key,
    object = c(charToRaw(.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAC_DOMAIN),
               as.raw(0L), message),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  c(message, mac)
}

.dsvert_formal_glm_phase18_outbox_decode <- function(encoded, slot, key) {
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 source outbox key is unavailable.",
      "durable_state_unavailable")
  }
  minimum <- length(.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAGIC) + 64L + 4L + 2L + 32L
  if (!is.raw(encoded) || length(encoded) < minimum ||
      length(encoded) > .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES + 108L) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 source outbox record has an invalid size.",
      "invalid_durable_frame")
  }
  message <- encoded[seq_len(length(encoded) - 32L)]
  mac <- encoded[(length(encoded) - 31L):length(encoded)]
  expected <- digest::hmac(
    key = key,
    object = c(charToRaw(.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAC_DOMAIN),
               as.raw(0L), message),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  magic_length <- length(.DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAGIC)
  observed_slot <- rawToChar(message[(magic_length + 1L):(magic_length + 64L)])
  parsed <- .dsvert_formal_glm_phase18_read_uint32(message, magic_length + 65L)
  if (is.null(parsed)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 source outbox record is truncated.",
      "invalid_durable_frame")
  }
  payload_offset <- parsed$offset
  if (!identical(mac, expected) ||
      !identical(message[seq_len(magic_length)],
                 .DSVERT_FORMAL_GLM_PHASE18_OUTBOX_MAGIC) ||
      !identical(observed_slot, slot) ||
      parsed$value < 2L ||
      payload_offset + parsed$value - 1L != length(message)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 source outbox record failed authentication.",
      "invalid_durable_frame")
  }
  rawToChar(message[payload_offset:length(message)])
}

.dsvert_formal_glm_phase18_sharded_path <- function(
    root, kind, key_id, slot) {
  base <- .dsvert_formal_glm_phase18_private_dir(file.path(root, kind))
  epoch <- .dsvert_formal_glm_phase18_private_dir(file.path(base, key_id))
  first <- .dsvert_formal_glm_phase18_private_dir(
    file.path(epoch, substr(slot, 1L, 2L)))
  second <- .dsvert_formal_glm_phase18_private_dir(
    file.path(first, substr(slot, 3L, 4L)))
  file.path(second, paste0("slot-", slot, ".bin"))
}

.dsvert_formal_glm_phase18_with_lock <- function(path, code) {
  if (!is.function(code) || .dsvert_dp_path_is_link(path)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable generation lock is invalid.",
      "unsafe_durable_state")
  }
  old_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(old_umask), silent = TRUE), add = TRUE)
  # Infinite wait is intentional: this serializes an identical retry without
  # turning slow materialization into a request quota or a 30-second failure.
  lock <- filelock::lock(path, timeout = Inf)
  if (is.null(lock)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "A Phase-1.8 durable generation lock is unavailable.",
      "durable_state_unavailable")
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  code()
}

.dsvert_formal_glm_phase18_source_slot <- function(
    authorization, block_index, first_ticket_json, second_ticket_json,
    verifier = .dsvert_relay_verify_message) {
  tickets <- lapply(
    list(first_ticket_json, second_ticket_json),
    .dsvert_formal_glm_phase18_ticket_validate,
    authorization = authorization, verifier = verifier)
  recipients <- vapply(tickets, function(ticket) {
    ticket$value$recipient_name
  }, character(1L))
  if (anyDuplicated(recipients) ||
      !setequal(recipients, authorization$designated)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The durable source ticket set is invalid.",
      "invalid_recipient_ticket")
  }
  tickets <- tickets[order(recipients, method = "radix")]
  .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/source-outbox-slot/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      run_id = authorization$pre$run_id,
      source_name = authorization$policy$peer_name,
      block_index = block_index,
      ticket_sha256 = lapply(tickets, `[[`, "sha256")))
}

.dsvert_formal_glm_phase18_materialize_block_durable <- function(
    authorization, block_index, first_ticket_json, second_ticket_json,
    .resolved_snapshots = NULL,
    .random_bytes = .dsvert_secure_random_bytes,
    .encryptor = NULL, .signer = NULL,
    .verifier = .dsvert_relay_verify_message,
    .root = .dsvert_formal_glm_phase18_durable_root(), .key = NULL) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  block_index <- as.integer(.dsvert_formal_glm_phase18_integer(
    block_index, "durable outbox block index", 0,
    authorization$pre$total_blocks - 1))
  root <- .dsvert_formal_glm_phase18_private_dir(
    .dsvert_formal_glm_phase18_durable_root(.root))
  key <- if (is.null(.key)) {
    .dsvert_formal_glm_phase18_init_key(root)
  } else .key
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The durable Phase-1.8 source key is invalid.",
      "durable_state_unavailable")
  }
  slot <- .dsvert_formal_glm_phase18_source_slot(
    authorization, block_index, first_ticket_json, second_ticket_json,
    .verifier)
  key_id <- .dsvert_formal_glm_phase18_key_id(key)
  path <- .dsvert_formal_glm_phase18_sharded_path(
    root, "source-outbox-v2", key_id, slot)
  read_existing <- function() {
    if (!file.exists(path)) return(NULL)
    encoded <- .dsvert_formal_glm_phase18_private_file(
      path, 1L, .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES + 108L)
    bundle <- .dsvert_formal_glm_phase18_outbox_decode(encoded, slot, key)
    invisible(.dsvert_formal_glm_phase18_block_bundle_validate(
      bundle, authorization, .verifier))
    bundle
  }
  existing <- read_existing()
  if (!is.null(existing)) return(existing)
  .dsvert_formal_glm_phase18_with_lock(
    paste0(path, ".materialize.lock"), function() {
      existing <- read_existing()
      if (!is.null(existing)) return(existing)
      bundle <- .dsvert_formal_glm_phase18_materialize_block(
        authorization, block_index, first_ticket_json, second_ticket_json,
        .resolved_snapshots = .resolved_snapshots,
        .random_bytes = .random_bytes, .encryptor = .encryptor,
        .signer = .signer, .verifier = .verifier)
      invisible(.dsvert_formal_glm_phase18_block_bundle_validate(
        bundle, authorization, .verifier))
      encoded <- .dsvert_formal_glm_phase18_outbox_encode(slot, bundle, key)
      committed <- .dsvert_formal_glm_phase18_atomic_cas(
        path, encoded, .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES + 108L,
        paste0(".phase18-outbox-", slot, "-tmp-"))
      .dsvert_formal_glm_phase18_outbox_decode(
        committed$payload, slot, key)
    })
}

.dsvert_formal_glm_phase18_recipient_bundle <- function(
    bundle_json, authorization,
    verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  preview <- .dsvert_formal_glm_phase18_decode_json(
    bundle_json, "recipient encrypted block bundle",
    .DSVERT_FORMAL_GLM_PHASE18_MAX_BUNDLE_BYTES)$value
  source <- tryCatch(.dsvert_formal_glm_phase18_scalar(
    preview$source_name, "recipient bundle source",
    maximum_bytes = 128L), error = function(error) NULL)
  recipient <- authorization$policy$peer_name
  if (is.null(source) || !source %in% authorization$peers ||
      !recipient %in% authorization$designated) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 recipient route is not in the pinned consortium.",
      "invalid_encrypted_block")
  }
  verification <- authorization
  verification$policy$peer_name <- source
  checked <- .dsvert_formal_glm_phase18_block_bundle_validate(
    bundle_json, verification, verifier)
  observed <- vapply(checked$value$envelopes, `[[`, character(1L),
                     "recipient_name")
  index <- match(recipient, observed)
  if (is.na(index) || sum(observed == recipient) != 1L) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 bundle lacks exactly one local recipient ciphertext.",
      "invalid_encrypted_block")
  }
  list(checked = checked, envelope = checked$value$envelopes[[index]],
       source = source, recipient = recipient)
}

.dsvert_formal_glm_phase18_enqueue_recipient <- function(
    bundle_json, authorization, global_materialization_root,
    verifier = .dsvert_relay_verify_message,
    .root = .dsvert_formal_glm_phase18_durable_root(), .key = NULL) {
  local <- .dsvert_formal_glm_phase18_recipient_bundle(
    bundle_json, authorization, verifier)
  root <- .dsvert_formal_glm_phase18_private_dir(
    .dsvert_formal_glm_phase18_durable_root(.root))
  key <- if (is.null(.key)) {
    .dsvert_formal_glm_phase18_init_key(root)
  } else .key
  if (!.dsvert_formal_glm_phase18_key_valid(key)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The durable Phase-1.8 recipient key is invalid.",
      "durable_state_unavailable")
  }
  global_materialization_root <- .dsvert_formal_glm_phase18_scalar(
    global_materialization_root, "global materialization root",
    pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
  bundle <- local$checked$value
  envelope <- local$envelope
  ciphertext <- .dsvert_relay_b64url_decode(
    envelope$ciphertext, "formal-GLM recipient ciphertext")
  source_slot <- match(local$source, authorization$peers) - 1L
  recipient_slot <- if (identical(
    local$recipient, authorization$pre$garbler_peer_name)) {
    0L
  } else if (identical(
    local$recipient, authorization$pre$evaluator_peer_name)) {
    1L
  } else NA_integer_
  if (is.na(source_slot) || is.na(recipient_slot)) {
    .dsvert_formal_glm_phase18_durable_abort(
      "The Phase-1.8 recipient/source slot is invalid.",
      "invalid_encrypted_block")
  }
  frame <- list(
    capsule_sha256 = envelope$capsule_id,
    plan_sha256 = envelope$plan_sha256,
    pre_execution_sha256 = envelope$pre_execution_sha256,
    global_materialization_root = global_materialization_root,
    run_id = envelope$run_id, source_name = local$source,
    recipient_name = local$recipient,
    recipient_ticket_sha256 = envelope$recipient_ticket_sha256,
    pair_commitment_sha256 = envelope$pair_commitment_sha256,
    block_commitment_sha256 = bundle$block_commitment_sha256,
    ciphertext_sha256 = envelope$ciphertext_sha256,
    envelope_sha256 = .dsvert_formal_glm_phase18_hash_object(
      "dsVert/formal-glm/phase18/signed-envelope/v2|", envelope),
    source_slot = source_slot, recipient_slot = recipient_slot,
    block_index = envelope$block_index, total_blocks = envelope$total_blocks,
    global_slot_offset = envelope$global_slot_offset,
    slots_in_block = envelope$slots_in_block,
    coordinate_count = envelope$coordinate_count,
    coordinate_records = envelope$coordinate_records_in_block,
    ring_bits = envelope$ring_bits, record_bytes = envelope$record_bytes,
    validity_records = envelope$validity_records_in_block,
    ciphertext = ciphertext)
  encoded <- .dsvert_formal_glm_phase18_frame_encode(frame, key)
  slot <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/recipient-inbox-slot/v2|", list(
      capsule_sha256 = frame$capsule_sha256,
      plan_sha256 = frame$plan_sha256,
      pre_execution_sha256 = frame$pre_execution_sha256,
      global_materialization_root = global_materialization_root,
      run_id = frame$run_id, source_name = frame$source_name,
      recipient_name = frame$recipient_name,
      block_index = frame$block_index))
  key_id <- .dsvert_formal_glm_phase18_key_id(key)
  path <- .dsvert_formal_glm_phase18_sharded_path(
    root, "recipient-inbox-v2", key_id, slot)
  committed <- .dsvert_formal_glm_phase18_atomic_cas(
    path, encoded, .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES,
    paste0(".phase18-inbox-", slot, "-tmp-"))
  invisible(.dsvert_formal_glm_phase18_frame_verify(committed$payload, key))
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_DURABLE_VERSION,
    phase = "recipient_ciphertext_queued_for_local_go_finalizer",
    handle = slot, source_name = frame$source_name,
    recipient_name = frame$recipient_name,
    block_index = frame$block_index,
    replayed = committed$replayed,
    openings_performed = 0L, production_ready = FALSE)))
}
