# Adaptive Session Storage (Memory + Disk)
#
# Blobs and persistent keys are stored adaptively: small objects stay in
# R memory for speed, large objects (>50KB) go to disk to prevent memory
# exhaustion. All consumers use the same API regardless of where data lives.
#
# Threshold: 50KB (nchar > 50000). This means:
#   - Small blobs (transport keys, party_id, ct_hashes): memory (~instant)
#   - Large blobs (CRP, ciphertexts, Galois keys, wrapped shares): disk
#   - Persistent keys: CPK/Galois/relin → disk; transport SK/PK → memory
#
# Directory structure (created lazily, only when first large blob arrives):
#   <tempdir()>/dsvert_<session_id>/
#     blobs/   -- large transient blobs
#     keys/    -- large persistent keys

.DISK_THRESHOLD <- 50000L  # nchar threshold for disk storage

# --- Session Directory ---

#' Get or create the session's temp directory (lazy)
#' @param ss Session environment
#' @return Character path
#' @keywords internal
.ensure_session_dir <- function(ss) {
  if (is.null(ss$.session_dir)) {
    sid <- ss$.session_id %||% "legacy"
    ss$.session_dir <- file.path(tempdir(), paste0("dsvert_", sid))
    dir.create(file.path(ss$.session_dir, "blobs"), recursive = TRUE,
               showWarnings = FALSE)
    dir.create(file.path(ss$.session_dir, "keys"), recursive = TRUE,
               showWarnings = FALSE)
  }
  ss$.session_dir
}

# --- Transient Blob Operations ---

#' Write a blob (adaptive: memory for small, disk for large)
#' @param key Character. Blob key
#' @param value Character. Blob data (base64 string)
#' @param ss Session environment
#' @keywords internal
.blob_put <- function(key, value, ss) {
  if (nchar(value) > .DISK_THRESHOLD) {
    d <- .ensure_session_dir(ss)
    writeLines(value, file.path(d, "blobs", key))
  } else {
    if (is.null(ss$blobs)) ss$blobs <- list()
    ss$blobs[[key]] <- value
  }
  invisible(NULL)
}

#' Read a blob (checks memory first, then disk)
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_get <- function(key, ss) {
  # Memory first (fast path)
  val <- ss$blobs[[key]]
  if (!is.null(val)) return(val)
  # Disk fallback
  d <- ss$.session_dir
  if (is.null(d)) return(NULL)
  path <- file.path(d, "blobs", key)
  if (!file.exists(path)) return(NULL)
  paste0(readLines(path, warn = FALSE), collapse = "")
}

#' Read a blob and delete it (one-shot consumption)
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_consume <- function(key, ss) {
  # Memory first
  val <- ss$blobs[[key]]
  if (!is.null(val)) {
    ss$blobs[[key]] <- NULL
    return(val)
  }
  # Disk fallback
  d <- ss$.session_dir
  if (is.null(d)) return(NULL)
  path <- file.path(d, "blobs", key)
  if (!file.exists(path)) return(NULL)
  value <- paste0(readLines(path, warn = FALSE), collapse = "")
  unlink(path)
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

#' Write a persistent key (adaptive: small → memory, large → disk)
#' @param name Character. Key name (e.g., "cpk", "secret_key")
#' @param value Character. Key data (single string or character vector)
#' @param ss Session environment
#' @keywords internal
.key_put <- function(name, value, ss) {
  total_size <- sum(nchar(value))
  if (total_size > .DISK_THRESHOLD) {
    d <- .ensure_session_dir(ss)
    writeLines(value, file.path(d, "keys", name))
  } else {
    if (is.null(ss$keys)) ss$keys <- list()
    ss$keys[[name]] <- value
  }
  invisible(NULL)
}

#' Read a persistent key (memory first, then disk)
#' @param name Character. Key name
#' @param ss Session environment
#' @return Character string (or vector for multi-line), or NULL
#' @keywords internal
.key_get <- function(name, ss) {
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
  if (!is.null(ss$keys[[name]])) return(TRUE)
  d <- ss$.session_dir
  if (is.null(d)) return(FALSE)
  file.exists(file.path(d, "keys", name))
}

#' Delete a persistent key (memory + disk with secure overwrite)
#' @param name Character. Key name
#' @param ss Session environment
#' @keywords internal
.key_delete <- function(name, ss) {
  ss$keys[[name]] <- NULL
  d <- ss$.session_dir
  if (!is.null(d)) {
    path <- file.path(d, "keys", name)
    if (file.exists(path)) {
      size <- file.info(path)$size
      if (!is.na(size) && size > 0L) {
        tryCatch(writeBin(raw(min(size, 1048576L)), path),
                 error = function(e) NULL)
      }
      unlink(path)
    }
  }
}

# --- Session Cleanup ---

#' Clean up all session storage (memory + disk with secure deletion)
#' @param ss Session environment
#' @keywords internal
.session_dir_cleanup <- function(ss) {
  # Clear memory
  ss$blobs <- NULL
  ss$keys <- NULL
  # Clear disk
  d <- ss$.session_dir
  if (!is.null(d) && dir.exists(d)) {
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
}
