# Adaptive Session Storage (Memory + Disk)
#
# Transport blobs are stored adaptively: small objects stay in R memory and
# large opaque blobs go to a private session directory. Persistent secret keys
# always remain in memory; writing key material to a filesystem would widen the
# trust boundary and secure deletion cannot be guaranteed on journaling/CoW
# filesystems.
#
# Threshold: 50KB (nchar > 50000). This means:
#   - Small blobs (transport keys, party_id, ct_hashes): memory (~instant)
#   - Large blobs (encrypted shares, DCF keys, Beaver triples): disk
#   - Persistent keys: memory only
#
# Directory structure (created lazily, only when first large blob arrives):
#   <tempdir()>/dsvert_<session_id>/
#     blobs/   -- large transient blobs

.DISK_THRESHOLD <- 50000L  # nchar threshold for disk storage
.DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES <- 512 * 1024^2
.DSVERT_LEGACY_BLOB_OBJECT_METADATA_BYTES <- 4096L
.DSVERT_LEGACY_BLOB_FRAME_METADATA_BYTES <- 1024L

# Retained legacy state that is not already covered by the typed transport's
# disk inventory. Completed in-memory payloads are counted exactly. Multipart
# transfers reserve their full public frame-metadata geometry from the first
# frame, so many sparse transfers cannot bypass process-wide backpressure.
.dsvert_legacy_blob_memory_retained_bytes <- function(ss) {
  if (!is.environment(ss)) return(Inf)
  total <- 0

  memory <- ss$blobs
  if (!is.null(memory)) {
    if (!is.list(memory) || (length(memory) &&
        (is.null(names(memory)) || anyNA(names(memory)) ||
         any(!nzchar(names(memory))) || anyDuplicated(names(memory))))) {
      return(Inf)
    }
    sizes <- vapply(memory, function(value) {
      if (!is.character(value) || length(value) != 1L || is.na(value)) {
        return(Inf)
      }
      as.numeric(nchar(value, type = "bytes"))
    }, numeric(1L))
    if (any(!is.finite(sizes))) return(Inf)
    total <- total + sum(sizes)
  }

  receipts <- ss$blob_chunk_receipts
  if (!is.null(receipts)) {
    if (!is.list(receipts) || (length(receipts) &&
        (is.null(names(receipts)) || anyNA(names(receipts)) ||
         any(!nzchar(names(receipts))) || anyDuplicated(names(receipts))))) {
      return(Inf)
    }
    for (receipt in receipts) {
      required <- c(
        "purpose", "n_chunks", "chunk_digests", "blob_digest")
      if (!is.list(receipt) || is.null(names(receipt)) ||
          anyDuplicated(names(receipt)) ||
          !setequal(names(receipt), required) ||
          !is.character(receipt$purpose) ||
          length(receipt$purpose) != 1L || is.na(receipt$purpose) ||
          !receipt$purpose %in% c("generic", "psi") ||
          !is.numeric(receipt$n_chunks) ||
          length(receipt$n_chunks) != 1L || is.na(receipt$n_chunks) ||
          !is.finite(receipt$n_chunks) ||
          receipt$n_chunks != floor(receipt$n_chunks) ||
          receipt$n_chunks < 1 || receipt$n_chunks > 4096 ||
          !is.character(receipt$chunk_digests) ||
          length(receipt$chunk_digests) != receipt$n_chunks ||
          anyNA(receipt$chunk_digests) ||
          any(!grepl("^[0-9a-f]{64}$", receipt$chunk_digests)) ||
          !is.character(receipt$blob_digest) ||
          length(receipt$blob_digest) != 1L ||
          is.na(receipt$blob_digest) ||
          !grepl("^[0-9a-f]{64}$", receipt$blob_digest)) {
        return(Inf)
      }
      total <- total + .DSVERT_LEGACY_BLOB_OBJECT_METADATA_BYTES +
        as.numeric(receipt$n_chunks) *
          .DSVERT_LEGACY_BLOB_FRAME_METADATA_BYTES
    }
  }

  partial <- ss$blob_chunks
  if (!is.null(partial)) {
    if (!is.list(partial) || (length(partial) &&
        (is.null(names(partial)) || anyNA(names(partial)) ||
         any(!nzchar(names(partial))) || anyDuplicated(names(partial))))) {
      return(Inf)
    }
    if (!is.null(receipts) && length(intersect(
        names(partial), names(receipts)))) return(Inf)
    for (state in partial) {
      if (is.character(state)) {
        if (!length(state) || length(state) > 4096L || anyNA(state)) {
          return(Inf)
        }
        present <- nzchar(state)
        bytes <- sum(nchar(state[present], type = "bytes"))
        n_chunks <- length(state)
      } else if (is.environment(state)) {
        valid <- is.character(state$purpose) &&
          length(state$purpose) == 1L && !is.na(state$purpose) &&
          state$purpose %in% c("generic", "psi") &&
          is.numeric(state$n_chunks) && length(state$n_chunks) == 1L &&
          !is.na(state$n_chunks) && is.finite(state$n_chunks) &&
          state$n_chunks == floor(state$n_chunks) &&
          state$n_chunks >= 1 && state$n_chunks <= 4096 &&
          is.numeric(state$received_count) &&
          length(state$received_count) == 1L &&
          !is.na(state$received_count) &&
          is.finite(state$received_count) &&
          state$received_count == floor(state$received_count) &&
          state$received_count >= 0 &&
          state$received_count <= state$n_chunks &&
          is.numeric(state$received_bytes) &&
          length(state$received_bytes) == 1L &&
          !is.na(state$received_bytes) &&
          is.finite(state$received_bytes) &&
          state$received_bytes >= 0 &&
          state$received_bytes <= .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES &&
          is.environment(state$chunks) && is.environment(state$digests)
        if (!isTRUE(valid)) return(Inf)
        bytes <- as.numeric(state$received_bytes)
        n_chunks <- as.numeric(state$n_chunks)
      } else {
        return(Inf)
      }
      total <- total + bytes +
        .DSVERT_LEGACY_BLOB_OBJECT_METADATA_BYTES +
        n_chunks * .DSVERT_LEGACY_BLOB_FRAME_METADATA_BYTES
    }
  }

  if (!is.finite(total) || total < 0 || total > 2^53) Inf else total
}

# --- Session Directory ---

.validate_storage_component <- function(value, label) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 255L ||
      value %in% c(".", "..") ||
      !grepl("^[A-Za-z0-9._-]+$", value)) {
    stop("Invalid ", label,
         ": use 1-255 letters, digits, dots, underscores or hyphens",
         call. = FALSE)
  }
  invisible(TRUE)
}

.expected_session_dir <- function(ss) {
  sid <- ss$.session_id
  .validate_storage_component(sid, "session storage identifier")
  file.path(tempdir(), paste0("dsvert_", sid))
}

.assert_session_dir <- function(ss) {
  expected <- .expected_session_dir(ss)
  actual <- ss$.session_dir
  if (!is.null(actual) && !identical(
      normalizePath(actual, mustWork = FALSE),
      normalizePath(expected, mustWork = FALSE))) {
    stop("Invalid session storage path", call. = FALSE)
  }
  expected
}

#' Get or create the session's temp directory (lazy)
#' @param ss Session environment
#' @return Character path
#' @keywords internal
.ensure_session_dir <- function(ss) {
  if (is.null(ss$.session_dir)) {
    ss$.session_dir <- .expected_session_dir(ss)
    dir.create(file.path(ss$.session_dir, "blobs"), recursive = TRUE,
               showWarnings = FALSE, mode = "0700")
    Sys.chmod(ss$.session_dir, mode = "0700")
    Sys.chmod(file.path(ss$.session_dir, "blobs"), mode = "0700")
  } else {
    .assert_session_dir(ss)
  }
  ss$.session_dir
}

.private_write_lines <- function(value, path) {
  tmp <- tempfile(pattern = ".dsvert-write-", tmpdir = dirname(path))
  on.exit(unlink(tmp), add = TRUE)
  writeLines(value, tmp, useBytes = TRUE)
  Sys.chmod(tmp, mode = "0600")
  if (!file.rename(tmp, path)) {
    unlink(path)
    if (!file.rename(tmp, path)) {
      stop("Could not commit private session blob", call. = FALSE)
    }
  }
  Sys.chmod(path, mode = "0600")
  invisible(NULL)
}

# --- Transient Blob Operations ---

#' Write a blob (adaptive: memory for small, disk for large)
#' @param key Character. Blob key
#' @param value Character. Blob data (base64 string)
#' @param ss Session environment
#' @keywords internal
.blob_put <- function(key, value, ss) {
  .validate_storage_component(key, "blob key")
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Blob value must be one character string", call. = FALSE)
  }
  value_bytes <- as.numeric(nchar(value, type = "bytes"))
  if (value_bytes > .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES) {
    .dsvert_resource_oversize(
      value_bytes, .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES,
      "legacy blob object")
  }
  # A replacement may coexist briefly with its previous value or with the
  # completed multipart accumulator. Reserve the full new value before any
  # memory assignment, temporary-file write or rename.
  .dsvert_resource_admit(ss, value_bytes)
  if (value_bytes > .DISK_THRESHOLD) {
    d <- .ensure_session_dir(ss)
    .private_write_lines(value, file.path(d, "blobs", key))
  } else {
    if (is.null(ss$blobs)) ss$blobs <- list()
    ss$blobs[[key]] <- value
  }
  if (exists(".dsvert_typed_blob_accounting_invalidate", mode = "function",
             inherits = TRUE)) {
    .dsvert_typed_blob_accounting_invalidate(ss)
  }
  invisible(NULL)
}

#' Read a blob without consuming it
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_read <- function(key, ss) {
  .validate_storage_component(key, "blob key")
  value <- ss$blobs[[key]]
  if (!is.null(value)) return(value)
  directory <- ss$.session_dir
  if (is.null(directory)) return(NULL)
  .assert_session_dir(ss)
  path <- file.path(directory, "blobs", key)
  if (!file.exists(path) || nzchar(Sys.readlink(path))) return(NULL)
  paste0(readLines(path, warn = FALSE), collapse = "")
}

#' Read a blob and delete it (one-shot consumption)
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_consume <- function(key, ss, invalidate_accounting = TRUE) {
  .validate_storage_component(key, "blob key")
  if (!is.logical(invalidate_accounting) ||
      length(invalidate_accounting) != 1L || is.na(invalidate_accounting)) {
    stop("Invalid blob accounting mode", call. = FALSE)
  }
  clear_transfer_state <- function() {
    if (!is.null(ss$blob_chunk_receipts)) {
      ss$blob_chunk_receipts[[key]] <- NULL
    }
    if (!is.null(ss$blob_chunks)) ss$blob_chunks[[key]] <- NULL
    if (isTRUE(invalidate_accounting) && exists(
        ".dsvert_typed_blob_accounting_invalidate", mode = "function",
        inherits = TRUE)) {
      .dsvert_typed_blob_accounting_invalidate(ss)
    }
  }
  # Memory first
  val <- ss$blobs[[key]]
  if (!is.null(val)) {
    ss$blobs[[key]] <- NULL
    clear_transfer_state()
    return(val)
  }
  # Disk fallback
  d <- ss$.session_dir
  if (is.null(d)) return(NULL)
  path <- file.path(d, "blobs", key)
  if (!file.exists(path)) return(NULL)
  value <- paste0(readLines(path, warn = FALSE), collapse = "")
  unlink(path)
  clear_transfer_state()
  value
}

#' Read ALL blobs into a named list (memory + disk merged)
#' @param ss Session environment
#' @return Named list of blob values
#' @keywords internal
.blob_snapshot <- function(ss) {
  # Start with memory blobs
  result <- if (!is.null(ss$blobs)) as.list(ss$blobs) else list()
  # Add disk blobs (disk entries not already in memory)
  d <- ss$.session_dir
  if (!is.null(d)) {
    blob_dir <- file.path(d, "blobs")
    if (dir.exists(blob_dir)) {
      files <- list.files(blob_dir, full.names = FALSE)
      for (f in files) {
        if (is.null(result[[f]])) {
          result[[f]] <- paste0(readLines(file.path(blob_dir, f),
                                          warn = FALSE), collapse = "")
        }
      }
    }
  }
  result
}

#' Delete all blobs (memory + disk)
#' @param ss Session environment
#' @keywords internal
.blob_nuke <- function(ss) {
  ss$blobs <- NULL
  ss$blob_chunks <- NULL
  ss$blob_chunk_receipts <- NULL
  ss$.typed_blob_destinations <- NULL
  ss$.typed_blob_transfers <- NULL
  ss$.typed_blob_receipts <- NULL
  ss$.typed_blob_receipt_latest <- NULL
  ss$.typed_blob_ticket_index <- NULL
  ss$.typed_blob_outbound <- NULL
  ss$.typed_blob_outbound_ticket_index <- NULL
  ss$.typed_blob_outbound_receipts <- NULL
  ss$.typed_blob_outbound_receipt_latest <- NULL
  ss$.typed_blob_pending_operations <- NULL
  ss$.typed_blob_retained_head <- NULL
  ss$.typed_blob_receive_sweep_cursor <- NULL
  ss$.typed_blob_source_sweep_cursor <- NULL
  d <- ss$.session_dir
  if (!is.null(d)) {
    blob_dir <- file.path(d, "blobs")
    if (dir.exists(blob_dir)) {
      files <- list.files(blob_dir, full.names = TRUE)
      if (length(files) > 0L) unlink(files)
    }
  }
}

# --- Persistent Key Operations ---

#' Write a persistent key to session memory
#' @param name Character. Key name (e.g., "cpk", "secret_key")
#' @param value Character. Key data (single string or character vector)
#' @param ss Session environment
#' @keywords internal
.key_put <- function(name, value, ss) {
  .validate_storage_component(name, "key name")
  if (is.null(ss$keys)) ss$keys <- list()
  ss$keys[[name]] <- value
  invisible(NULL)
}

#' Read a persistent key (memory first, then disk)
#' @param name Character. Key name
#' @param ss Session environment
#' @return Character string (or vector for multi-line), or NULL
#' @keywords internal
.key_get <- function(name, ss) {
  .validate_storage_component(name, "key name")
  # Memory first
  val <- ss$keys[[name]]
  if (!is.null(val)) return(val)
  # Disk fallback
  d <- ss$.session_dir
  if (is.null(d)) return(NULL)
  path <- file.path(d, "keys", name)
  if (!file.exists(path)) return(NULL)
  lines <- readLines(path, warn = FALSE)
  if (length(lines) == 1L) lines else lines
}

#' Check if a persistent key exists (memory or disk)
#' @param name Character. Key name
#' @param ss Session environment
#' @return Logical
#' @keywords internal
.key_exists <- function(name, ss) {
  .validate_storage_component(name, "key name")
  if (!is.null(ss$keys[[name]])) return(TRUE)
  d <- ss$.session_dir
  if (is.null(d)) return(FALSE)
  file.exists(file.path(d, "keys", name))
}

# --- Session Cleanup ---

#' Clean up all session storage (memory + disk with secure deletion)
#' @param ss Session environment
#' @keywords internal
.session_dir_cleanup <- function(ss) {
  if (is.environment(ss$.dsvert_dsi_relay)) {
    tryCatch(.dsvert_relay_close(ss), error = function(e) NULL)
  }
  # Clear memory
  ss$blobs <- NULL
  ss$keys <- NULL
  ss$blob_chunks <- NULL
  ss$blob_chunk_receipts <- NULL
  ss$.typed_blob_destinations <- NULL
  ss$.typed_blob_transfers <- NULL
  ss$.typed_blob_receipts <- NULL
  ss$.typed_blob_receipt_latest <- NULL
  ss$.typed_blob_ticket_index <- NULL
  ss$.typed_blob_outbound <- NULL
  ss$.typed_blob_outbound_ticket_index <- NULL
  ss$.typed_blob_outbound_receipts <- NULL
  ss$.typed_blob_outbound_receipt_latest <- NULL
  ss$.typed_blob_pending_operations <- NULL
  ss$.typed_blob_retained_head <- NULL
  ss$.typed_blob_receive_sweep_cursor <- NULL
  ss$.typed_blob_source_sweep_cursor <- NULL
  # Clear disk
  d <- ss$.session_dir
  if (!is.null(d) && dir.exists(d)) {
    .assert_session_dir(ss)
    # Secure-delete key files
    key_dir <- file.path(d, "keys")
    if (dir.exists(key_dir)) {
      for (f in list.files(key_dir, full.names = TRUE)) {
        size <- file.info(f)$size
        if (!is.na(size) && size > 0L) {
          tryCatch(writeBin(raw(min(size, 1048576L)), f),
                   error = function(e) NULL)
        }
      }
    }
    unlink(d, recursive = TRUE)
  }
  ss$.session_dir <- NULL
  if (exists(".dsvert_resource_unregister", mode = "function",
             inherits = TRUE)) {
    .dsvert_resource_unregister(ss)
  }
}
