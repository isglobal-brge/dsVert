# File-Backed Session Storage
#
# Replaces in-memory ss$blobs with a directory of files on disk.
# Prevents R memory exhaustion with large datasets (many variables ×
# large CKKS ciphertexts). Each session gets its own temp directory;
# blobs and persistent keys are stored as individual files.
#
# Directory structure:
#   <tempdir()>/dsvert_<session_id>/
#     blobs/   -- transient blobs (CRP, CTs, wrapped shares, etc.)
#     keys/    -- persistent keys (cpk, galois_keys, secret_key, etc.)

# --- Session Directory ---

#' Get or create the session's blob directory
#' @param ss Session environment (from .S())
#' @return Character path to the session directory
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

#' Write a blob to disk
#' @param key Character. Blob key (e.g., "crp", "ct_batch_1")
#' @param value Character. The blob data (base64 string)
#' @param ss Session environment
#' @keywords internal
.blob_put <- function(key, value, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "blobs", key)
  writeLines(value, path)
  invisible(path)
}

#' Read a blob from disk (returns NULL if missing)
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_get <- function(key, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "blobs", key)
  if (!file.exists(path)) return(NULL)
  paste0(readLines(path, warn = FALSE), collapse = "")
}

#' Read a blob and delete its file (one-shot consumption)
#' @param key Character. Blob key
#' @param ss Session environment
#' @return Character string or NULL
#' @keywords internal
.blob_consume <- function(key, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "blobs", key)
  if (!file.exists(path)) return(NULL)
  value <- paste0(readLines(path, warn = FALSE), collapse = "")
  unlink(path)
  value
}

#' Read ALL blobs into a named list (for "snapshot" pattern)
#' @param ss Session environment
#' @return Named list of blob values
#' @keywords internal
.blob_snapshot <- function(ss) {
  d <- .ensure_session_dir(ss)
  blob_dir <- file.path(d, "blobs")
  files <- list.files(blob_dir, full.names = FALSE)
  if (length(files) == 0L) return(list())
  result <- vector("list", length(files))
  names(result) <- files
  for (f in files) {
    result[[f]] <- paste0(readLines(file.path(blob_dir, f), warn = FALSE),
                          collapse = "")
  }
  result
}

#' Delete all blob files
#' @param ss Session environment
#' @keywords internal
.blob_nuke <- function(ss) {
  d <- .ensure_session_dir(ss)
  blob_dir <- file.path(d, "blobs")
  files <- list.files(blob_dir, full.names = TRUE)
  if (length(files) > 0L) unlink(files)
}

# --- Persistent Key Operations ---

#' Write a persistent key to disk
#' @param name Character. Key name (e.g., "cpk", "secret_key")
#' @param value Character. Key data (single string or character vector)
#' @param ss Session environment
#' @keywords internal
.key_put <- function(name, value, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "keys", name)
  writeLines(value, path)
  invisible(path)
}

#' Read a persistent key from disk
#' @param name Character. Key name
#' @param ss Session environment
#' @return Character string (or vector for multi-line), or NULL
#' @keywords internal
.key_get <- function(name, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "keys", name)
  if (!file.exists(path)) return(NULL)
  lines <- readLines(path, warn = FALSE)
  if (length(lines) == 1L) lines else lines
}

#' Check if a persistent key exists
#' @param name Character. Key name
#' @param ss Session environment
#' @return Logical
#' @keywords internal
.key_exists <- function(name, ss) {
  d <- .ensure_session_dir(ss)
  file.exists(file.path(d, "keys", name))
}

#' Delete a persistent key with optional secure overwrite
#' @param name Character. Key name
#' @param ss Session environment
#' @keywords internal
.key_delete <- function(name, ss) {
  d <- .ensure_session_dir(ss)
  path <- file.path(d, "keys", name)
  if (!file.exists(path)) return(invisible(NULL))
  # Secure overwrite for all key material (defense-in-depth)
  size <- file.info(path)$size
  if (!is.na(size) && size > 0L) {
    tryCatch(writeBin(raw(min(size, 1048576L)), path), error = function(e) NULL)
  }
  unlink(path)
}

# --- Session Cleanup ---

#' Clean up all session files (blobs + keys with secure deletion)
#' @param ss Session environment
#' @keywords internal
.session_dir_cleanup <- function(ss) {
  d <- ss$.session_dir
  if (is.null(d) || !dir.exists(d)) return(invisible(NULL))
  # Secure-delete all key files
  key_dir <- file.path(d, "keys")
  if (dir.exists(key_dir)) {
    key_files <- list.files(key_dir, full.names = TRUE)
    for (f in key_files) {
      size <- file.info(f)$size
      if (!is.na(size) && size > 0L) {
        tryCatch(writeBin(raw(min(size, 1048576L)), f), error = function(e) NULL)
      }
    }
  }
  # Remove entire directory tree
  unlink(d, recursive = TRUE)
  ss$.session_dir <- NULL
}
