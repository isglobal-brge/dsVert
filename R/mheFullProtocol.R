#' @title MHE Full Protocol - Server-Side Functions
#' @description These functions implement the full Multiparty Homomorphic Encryption
#'   protocol with threshold decryption. The client CANNOT decrypt data without
#'   cooperation from ALL servers.
#'
#' @name mhe-full-protocol
NULL

# Global storage for MHE keys on each server
.mhe_storage <- new.env(parent = emptyenv())

#' Initialize MHE keys for this server
#'
#' @param party_id Integer. This server's party ID (0-indexed)
#' @param crp Character. CRP from party 0 (NULL if this is party 0)
#' @param num_obs Integer. Number of observations (affects galois keys)
#' @param log_n Integer. Ring dimension parameter
#' @param log_scale Integer. Scale parameter
#'
#' @return List with public_key_share and crp (if party 0)
#' @export
mheInitDS <- function(party_id, crp = NULL, num_obs = 100, log_n = 12, log_scale = 40) {
  input <- list(
    party_id = as.integer(party_id),
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  # If not party 0, include CRP
  if (party_id > 0 && !is.null(crp)) {
    input$crp <- .base64url_to_base64(crp)
    input$gkg_crp <- input$crp
    input$rkg_crp <- input$crp
  }

  result <- .callMheTool("mhe-setup", input)

  # Store secret key locally (NEVER returned to client)
  .mhe_storage$secret_key <- result$secret_key
  .mhe_storage$party_id <- party_id
  .mhe_storage$log_n <- log_n
  .mhe_storage$log_scale <- log_scale

  # Return only public information
  output <- list(
    public_key_share = base64_to_base64url(result$public_key_share),
    party_id = party_id
  )

  # Party 0 also returns CRP
  if (party_id == 0) {
    output$crp <- base64_to_base64url(result$crp)
  }

  output
}

#' Combine public key shares into collective public key
#'
#' @param public_key_shares Character vector. Public key shares from all servers
#' @param crp Character. CRP from party 0
#' @param num_obs Integer. Number of observations
#' @param log_n Integer. Ring dimension
#' @param log_scale Integer. Scale parameter
#'
#' @return List with collective_public_key
#' @export
mheCombineDS <- function(public_key_shares, crp, num_obs = 100, log_n = 12, log_scale = 40) {
  # Convert from base64url
  pk_shares <- sapply(public_key_shares, .base64url_to_base64, USE.NAMES = FALSE)
  crp_std <- .base64url_to_base64(crp)

  input <- list(
    public_key_shares = as.list(pk_shares),
    galois_key_shares = list(),
    rkg_shares_round1 = list(),
    crp = crp_std,
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("mhe-combine", input)

  # Store combined keys locally for use in computations
  .mhe_storage$cpk <- result$collective_public_key
  .mhe_storage$galois_keys <- result$galois_keys
  .mhe_storage$relin_key <- result$relinearization_key

  list(
    collective_public_key = base64_to_base64url(result$collective_public_key)
  )
}

#' Store collective public key received from combine step
#'
#' @param cpk Character. Collective public key (base64url)
#' @param galois_keys Character vector. Galois keys (base64url)
#' @param relin_key Character. Relinearization key (base64url)
#'
#' @return TRUE on success
#' @export
mheStoreCPKDS <- function(cpk, galois_keys = NULL, relin_key = NULL) {
  .mhe_storage$cpk <- .base64url_to_base64(cpk)

  if (!is.null(galois_keys)) {
    .mhe_storage$galois_keys <- sapply(galois_keys, .base64url_to_base64, USE.NAMES = FALSE)
  }
  if (!is.null(relin_key)) {
    .mhe_storage$relin_key <- .base64url_to_base64(relin_key)
  }

  TRUE
}

#' Encrypt local data columns using stored CPK
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to encrypt
#'
#' @return List with encrypted_columns
#' @export
mheEncryptLocalDS <- function(data_name, variables) {
  if (is.null(.mhe_storage$cpk)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  # Get data
  data <- eval(parse(text = data_name), envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to row-major format: data[row][col] as Go expects
  data_rows <- lapply(seq_len(nrow(Z)), function(i) as.numeric(Z[i, ]))

  input <- list(
    data = data_rows,
    collective_public_key = .mhe_storage$cpk,
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
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
#'
#' @return TRUE on success
#' @export
mheStoreEncChunkDS <- function(col_index, chunk_index, chunk) {
  key <- paste0("enc_chunks_", col_index)
  if (is.null(.mhe_storage[[key]])) {
    .mhe_storage[[key]] <- list()
  }
  .mhe_storage[[key]][[chunk_index]] <- chunk
  TRUE
}

#' Assemble stored chunks into a complete encrypted column
#'
#' @param col_index Integer. Column index (1-based)
#' @param n_chunks Integer. Total number of chunks
#'
#' @return TRUE on success
#' @export
mheAssembleEncColumnDS <- function(col_index, n_chunks) {
  key <- paste0("enc_chunks_", col_index)
  chunks <- .mhe_storage[[key]]
  if (is.null(chunks) || length(chunks) < n_chunks) {
    stop("Missing chunks for column ", col_index, call. = FALSE)
  }

  # Concatenate all chunks and convert from base64url
  full_b64url <- paste0(chunks[1:n_chunks], collapse = "")
  full_b64 <- .base64url_to_base64(full_b64url)

  if (is.null(.mhe_storage$remote_enc_cols)) {
    .mhe_storage$remote_enc_cols <- list()
  }
  .mhe_storage$remote_enc_cols[[col_index]] <- full_b64

  # Clean up chunks
  .mhe_storage[[key]] <- NULL
  TRUE
}

#' Compute encrypted cross-product using STORED evaluation keys and STORED encrypted columns
#' Returns ENCRYPTED result that requires threshold decryption
#'
#' @param data_name Character. Name of local data frame
#' @param variables Character vector. Local variables (plaintext)
#' @param n_enc_cols Integer. Number of stored encrypted columns to use
#' @param n_obs Integer. Number of observations
#'
#' @return List with encrypted_results matrix (base64url encoded ciphertexts)
#' @export
mheCrossProductEncDS <- function(data_name, variables, n_enc_cols, n_obs) {
  if (is.null(.mhe_storage$remote_enc_cols) || length(.mhe_storage$remote_enc_cols) < n_enc_cols) {
    stop("Encrypted columns not stored. Call mheStoreEncChunkDS/mheAssembleEncColumnDS first.", call. = FALSE)
  }

  # Get local data
  data <- eval(parse(text = data_name), envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to column format
  plaintext_cols <- lapply(seq_len(ncol(Z)), function(j) as.numeric(Z[, j]))

  # Use stored encrypted columns (no eval keys needed!)
  enc_cols <- .mhe_storage$remote_enc_cols[1:n_enc_cols]

  input <- list(
    plaintext_columns = plaintext_cols,
    encrypted_columns = enc_cols,
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-cross-product", input)

  # Clear stored encrypted columns after use
  .mhe_storage$remote_enc_cols <- NULL

  # Convert results to base64url, handling matrix or list return from jsonlite
  er <- result$encrypted_results
  if (is.matrix(er)) {
    n_rows <- nrow(er)
    n_cols <- ncol(er)
    # Convert each element to base64url
    for (i in seq_len(n_rows)) {
      for (j in seq_len(n_cols)) {
        er[i, j] <- base64_to_base64url(er[i, j])
      }
    }
  } else {
    n_rows <- length(er)
    n_cols <- if (n_rows > 0) length(er[[1]]) else 0
    er <- lapply(er, function(row) sapply(row, base64_to_base64url, USE.NAMES = FALSE))
  }

  list(
    encrypted_results = er,
    n_rows = n_rows,
    n_cols = n_cols
  )
}

#' Store a chunk of a ciphertext for partial decryption
#'
#' @param chunk_index Integer. Chunk index (1-based)
#' @param chunk Character. Base64url-encoded chunk
#'
#' @return TRUE on success
#' @export
mheStoreCTChunkDS <- function(chunk_index, chunk) {
  if (is.null(.mhe_storage$ct_chunks)) {
    .mhe_storage$ct_chunks <- list()
  }
  .mhe_storage$ct_chunks[[chunk_index]] <- chunk
  TRUE
}

#' Compute partial decryption using stored secret key and stored ciphertext chunks
#'
#' @param n_chunks Integer. Number of stored ciphertext chunks
#'
#' @return List with decryption_share (chunked as a character vector)
#' @export
mhePartialDecryptDS <- function(n_chunks) {
  if (is.null(.mhe_storage$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(.mhe_storage$ct_chunks) || length(.mhe_storage$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(.mhe_storage$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)

  # Clean up chunks
  .mhe_storage$ct_chunks <- NULL

  input <- list(
    ciphertext = ct_b64,
    secret_key = .mhe_storage$secret_key,
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-partial-decrypt", input)

  # Return share as chunks (to avoid large return through DataSHIELD)
  share_b64url <- base64_to_base64url(result$decryption_share)

  list(
    decryption_share = share_b64url,
    party_id = .mhe_storage$party_id
  )
}

#' Get number of observations for a variable
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to check
#'
#' @return Integer. Number of complete observations
#' @export
mheGetObsDS <- function(data_name, variables) {
  data <- eval(parse(text = data_name), envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  sum(complete.cases(X))
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
