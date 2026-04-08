#' @title MHE Encryption and Ciphertext Storage
#' @description Encryption of local data columns, chunked ciphertext transfer,
#'   cross-product computation, and blob storage for the MHE protocol.
#' @name mhe-encryption
NULL

#' Encrypt local data columns using stored CPK
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to encrypt
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with encrypted_columns
#' @export
mheEncryptLocalDS <- function(data_name, variables, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("cpk", ss)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  # Get data
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize to Z-scores (mean=0, sd=1) before encryption.
  # This is necessary because CKKS has limited multiplicative depth:
  # operating on values near [-1, 1] minimizes precision loss.
  # NaN values (from zero-variance columns) are replaced with 0.
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to row-major format: data[row][col] as Go expects.
  # as.list() is critical: jsonlite's auto_unbox converts length-1 atomic
  # vectors to JSON scalars, but Go expects arrays even for single-column data.
  data_rows <- lapply(seq_len(nrow(Z)), function(i) as.list(as.numeric(Z[i, ])))

  input <- list(
    data = data_rows,
    collective_public_key = .key_get("cpk", ss),
    log_n = as.integer(ss$log_n %||% 13),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("encrypt-columns", input)

  list(
    encrypted_columns = sapply(result$encrypted_columns, base64_to_base64url, USE.NAMES = FALSE),
    num_rows = result$num_rows,
    num_cols = result$num_cols
  )
}

#' Store a chunk of an encrypted column (for transferring large ciphertexts)
#'
#' @param col_index Integer. Column index (1-based)
#' @param chunk_index Integer. Chunk index (1-based)
#' @param chunk Character. Base64url-encoded chunk of ciphertext
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreEncChunkDS <- function(col_index, chunk_index, chunk, session_id = NULL) {
  ss <- .S(session_id)
  key <- paste0("enc_chunks_", col_index)
  if (is.null(ss[[key]])) {
    ss[[key]] <- list()
  }
  ss[[key]][[chunk_index]] <- chunk
  TRUE
}

#' Assemble stored chunks into a complete encrypted column
#'
#' @param col_index Integer. Column index (1-based)
#' @param n_chunks Integer. Total number of chunks
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheAssembleEncColumnDS <- function(col_index, n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  key <- paste0("enc_chunks_", col_index)
  chunks <- ss[[key]]
  if (is.null(chunks) || length(chunks) < n_chunks) {
    stop("Missing chunks for column ", col_index, call. = FALSE)
  }

  # Concatenate all chunks and convert from base64url
  full_b64url <- paste0(chunks[1:n_chunks], collapse = "")
  full_b64 <- .base64url_to_base64(full_b64url)

  if (is.null(ss$remote_enc_cols)) {
    ss$remote_enc_cols <- list()
  }
  ss$remote_enc_cols[[col_index]] <- full_b64

  # Clean up chunks
  ss[[key]] <- NULL
  TRUE
}

#' Compute encrypted cross-product using STORED evaluation keys and STORED encrypted columns
#' Returns ENCRYPTED result that requires threshold decryption
#'
#' @param data_name Character. Name of local data frame
#' @param variables Character vector. Local variables (plaintext)
#' @param n_enc_cols Integer. Number of stored encrypted columns to use
#' @param n_obs Integer. Number of observations
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with encrypted_results matrix (base64url encoded ciphertexts)
#' @export
mheCrossProductEncDS <- function(data_name, variables, n_enc_cols, n_obs,
                                 session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$remote_enc_cols) || length(ss$remote_enc_cols) < n_enc_cols) {
    stop("Encrypted columns not stored. Call mheStoreEncChunkDS/mheAssembleEncColumnDS first.", call. = FALSE)
  }

  # Get local data
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to column format
  plaintext_cols <- lapply(seq_len(ncol(Z)), function(j) as.numeric(Z[, j]))

  # Use stored encrypted columns (no eval keys needed!)
  enc_cols <- ss$remote_enc_cols[1:n_enc_cols]

  input <- list(
    plaintext_columns = plaintext_cols,
    encrypted_columns = enc_cols,
    log_n = as.integer(ss$log_n %||% 13),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-cross-product", input)

  # Clear stored encrypted columns after use
  ss$remote_enc_cols <- NULL

  # Protocol Firewall: register each produced ciphertext.
  # Returns ct_hashes so the client can relay them to other servers
  # for batch authorization before threshold decryption.
  er <- result$encrypted_results
  ct_hashes <- character(0)

  if (is.matrix(er)) {
    n_rows <- nrow(er)
    n_cols <- ncol(er)
    for (i in seq_len(n_rows)) {
      for (j in seq_len(n_cols)) {
        h <- .register_ciphertext(er[i, j], "cross-product", session_id = session_id)
        ct_hashes <- c(ct_hashes, h)
        er[i, j] <- base64_to_base64url(er[i, j])
      }
    }
  } else {
    n_rows <- length(er)
    n_cols <- if (n_rows > 0) length(er[[1]]) else 0
    for (i in seq_along(er)) {
      for (j in seq_along(er[[i]])) {
        h <- .register_ciphertext(er[[i]][[j]], "cross-product", session_id = session_id)
        ct_hashes <- c(ct_hashes, h)
      }
    }
    er <- lapply(er, function(row) sapply(row, base64_to_base64url, USE.NAMES = FALSE))
  }

  list(
    encrypted_results = er,
    ct_hashes = ct_hashes,
    n_rows = n_rows,
    n_cols = n_cols
  )
}

#' Store a blob in server-side storage (with chunking support)
#'
#' Generic function for storing large data on the server via chunked
#' transfer. DataSHIELD's R expression parser imposes a limit on the
#' size of arguments passed inline in \code{call()} expressions.
#' Cryptographic objects (CKKS ciphertexts, EC points, key shares,
#' transport-encrypted blobs) routinely exceed this limit. This
#' function provides a store-and-assemble pattern: the client splits
#' large data into chunks (adaptive size, starting at 200 KB), sends each chunk via a
#' separate \code{datashield.aggregate} call, and the server
#' auto-assembles them when the last chunk arrives. Downstream
#' functions read the assembled blob via \code{from_storage = TRUE}.
#'
#' All data transferred through this mechanism is base64url-encoded
#' (standard base64 uses \code{+} and \code{/}, which the DSOpal
#' expression serializer can misinterpret).
#'
#' This pattern is used throughout the dsVert protocol stack:
#' \itemize{
#'   \item PSI: EC point vectors (\code{psiProcessTargetDS},
#'     \code{psiDoubleMaskDS}, \code{psiMatchAndAlignDS},
#'     \code{psiFilterCommonDS})
#'   \item MHE key setup: CRP, GKG seed, public key shares, Galois
#'     keys (\code{mheInitDS}, \code{mheCombineDS},
#'     \code{mheStoreCPKDS})
#'   \item Threshold decryption: ciphertext chunks, wrapped shares
#'   \item GLM Secure Routing: transport-encrypted vectors (eta,
#'     mu/w/v)
#'   \item Protocol Firewall: CT hash batches
#'     (\code{mheAuthorizeCTDS})
#' }
#'
#' @param key Character. Storage key (e.g., "mwv", "eta_server1")
#' @param chunk Character. The blob data (or a chunk of it)
#' @param chunk_index Integer. Current chunk index (1-based). Default 1.
#' @param n_chunks Integer. Total number of chunks. Default 1 (no chunking).
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreBlobDS <- function(key, chunk, chunk_index = 1L, n_chunks = 1L,
                           session_id = NULL) {
  ss <- .S(session_id)
  if (n_chunks == 1L) {
    .blob_put(key, chunk, ss)
  } else {
    if (is.null(ss$blob_chunks)) ss$blob_chunks <- list()
    if (!is.null(ss$blob_chunks[[key]]) &&
        length(ss$blob_chunks[[key]]) != n_chunks) {
      ss$blob_chunks[[key]] <- NULL
    }
    if (is.null(ss$blob_chunks[[key]])) {
      ss$blob_chunks[[key]] <- character(n_chunks)
    }
    ss$blob_chunks[[key]][chunk_index] <- chunk
    if (all(nzchar(ss$blob_chunks[[key]]))) {
      .blob_put(key, paste0(ss$blob_chunks[[key]], collapse = ""), ss)
      ss$blob_chunks[[key]] <- NULL
    }
  }
  TRUE
}

#' Store a chunk of a ciphertext for partial decryption
#'
#' @param chunk_index Integer. Chunk index (1-based)
#' @param chunk Character. Base64url-encoded chunk
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreCTChunkDS <- function(chunk_index, chunk, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$ct_chunks)) {
    ss$ct_chunks <- list()
  }
  ss$ct_chunks[[chunk_index]] <- chunk
  TRUE
}
