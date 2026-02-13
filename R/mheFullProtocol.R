#' @title MHE Threshold Protocol - Server-Side Functions
#' @description These functions implement the Multiparty Homomorphic Encryption (MHE)
#'   protocol with threshold decryption using the CKKS approximate homomorphic
#'   encryption scheme (Lattigo v6). Decryption requires ALL servers to cooperate
#'   by providing their partial decryption shares.
#'
#' @details
#' The protocol proceeds in 6 phases, orchestrated by the client
#' (\code{ds.vertCor} in the dsVertClient package):
#'
#' \enumerate{
#'   \item \strong{Key Generation} (\code{mheInitDS}): Each server generates a
#'     secret key share and a public key share. Party 0 also generates the Common
#'     Reference Polynomial (CRP).
#'   \item \strong{Key Combination} (\code{mheCombineDS} + \code{mheStoreCPKDS}):
#'     Public key shares are aggregated into a Collective Public Key (CPK).
#'   \item \strong{Encryption} (\code{mheEncryptLocalDS}): Each server standardizes
#'     its data and encrypts columns under the CPK.
#'   \item \strong{Local Correlation} (\code{localCorDS}): Within-server correlations
#'     are computed in plaintext.
#'   \item \strong{Cross-Server Correlation} (\code{mheCrossProductEncDS} +
#'     \code{mhePartialDecryptDS}): Encrypted element-wise products are computed,
#'     then each server provides a partial decryption share.
#'   \item \strong{Fusion} (client-side \code{mhe-fuse}): The client fuses all
#'     partial shares to recover the inner products (correlation coefficients).
#' }
#'
#' @section Security:
#' The secret key is split across K servers: \eqn{sk = sk_1 + sk_2 + ... + sk_K}.
#' Decryption requires ALL K partial decryption shares. Neither the client nor
#' any subset of K-1 servers can decrypt individual data.
#'
#' @references
#' Mouchet, C. et al. (2021). "Multiparty Homomorphic Encryption from
#' Ring-Learning-With-Errors". \emph{Proceedings on Privacy Enhancing Technologies}.
#'
#' Cheon, J.H. et al. (2017). "Homomorphic Encryption for Arithmetic of
#' Approximate Numbers". \emph{ASIACRYPT 2017}.
#'
#' @name mhe-full-protocol
NULL

# ---------------------------------------------------------------------------
# Persistent server-side state: .mhe_storage
# ---------------------------------------------------------------------------
# DataSHIELD aggregate/assign calls run in ephemeral environments, so local
# variables are lost between calls. We use a package-level environment to
# persist state across the multi-step MHE and PSI protocols.
#
# Stored keys during MHE protocol:
#   $secret_key     - This server's RLWE secret key share (NEVER returned)
#   $party_id       - Integer party index (0-based)
#   $cpk            - Collective Public Key (standard base64)
#   $galois_keys    - Galois rotation keys (standard base64 vector)
#   $relin_key      - Relinearization key (standard base64)
#   $log_n, $log_scale - CKKS parameters
#
# Stored during GLM protocol:
#   $enc_y          - Encrypted response ciphertext (non-label servers)
#   $remote_enc_cols - List of received encrypted columns (correlation)
#   $std_data       - Standardized data frame
#   $std_data_name  - Name key for .resolveData() lookup
#
# Stored during PSI protocol:
#   $psi_scalar     - P-256 secret scalar (NEVER returned)
#   $psi_ref_dm     - Double-masked reference points
#   $psi_ref_indices - Reference row indices
#   $psi_matched_ref_indices - Matched indices for Phase 8 intersection
#
# Protocol Firewall state:
#   $op_counter     - Monotonic operation counter
#   $ct_registry    - Named list: ct_hash -> list(op_id, op_type, timestamp)
#                     Only registered ciphertexts can be partially decrypted.
#                     Each entry is consumed (deleted) after one decryption
#                     to prevent replay attacks.
# ---------------------------------------------------------------------------
.mhe_storage <- new.env(parent = emptyenv())

# ---------------------------------------------------------------------------
# Protocol Firewall: Ciphertext Registry
# ---------------------------------------------------------------------------
# Prevents the decryption oracle attack (arbitrary ciphertext decryption)
# by requiring every ciphertext to be registered at production time.
# Uses SHA-256 hashes of ciphertext content as keys.
# ---------------------------------------------------------------------------

#' Register a ciphertext as authorized for decryption (producing server)
#'
#' Called by operations that produce ciphertexts (cross-product, GLM gradient).
#' Returns the SHA-256 hash for client-side relay to other servers.
#'
#' @param ct_b64 Character. The ciphertext in standard base64 encoding
#' @param op_type Character. Operation that produced this ciphertext
#' @return Character. SHA-256 hash of the ciphertext
#' @keywords internal
.register_ciphertext <- function(ct_b64, op_type) {
  if (is.null(.mhe_storage$op_counter)) {
    .mhe_storage$op_counter <- 0L
  }
  if (is.null(.mhe_storage$ct_registry)) {
    .mhe_storage$ct_registry <- list()
  }

  .mhe_storage$op_counter <- .mhe_storage$op_counter + 1L

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  .mhe_storage$ct_registry[[ct_hash]] <- list(
    op_id = .mhe_storage$op_counter,
    op_type = op_type,
    timestamp = Sys.time()
  )

  ct_hash
}

#' Validate and consume a ciphertext authorization (one-time use)
#' @param ct_b64 Character. The ciphertext in standard base64 encoding
#' @return TRUE if authorized (entry is consumed), stops with error otherwise
#' @keywords internal
.validate_and_consume_ciphertext <- function(ct_b64) {
  if (is.null(.mhe_storage$ct_registry)) {
    stop("Protocol Firewall: no ciphertexts registered. ",
         "Decryption denied.", call. = FALSE)
  }

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  entry <- .mhe_storage$ct_registry[[ct_hash]]
  if (is.null(entry)) {
    stop("Protocol Firewall: ciphertext not authorized for decryption. ",
         "Only ciphertexts produced by legitimate operations ",
         "(cross-product, glm-gradient) can be decrypted.", call. = FALSE)
  }

  # One-time use: consume the authorization (anti-replay)
  .mhe_storage$ct_registry[[ct_hash]] <- NULL

  TRUE
}

#' Initialize MHE keys and transport keypair for this server
#'
#' Generates a CKKS MHE secret/public key share pair and an X25519
#' transport keypair. The secret keys (MHE SK share and transport SK) are
#' stored locally and NEVER returned to the client.
#'
#' Party 0 additionally generates and returns the Common Reference Polynomial
#' (CRP) and the Galois Key Generation (GKG) seed, which must be relayed
#' to all other parties.
#'
#' @param party_id Integer. This server's party ID (0-indexed). Party 0
#'   generates the CRP and GKG seed.
#' @param crp Character or NULL. Common Reference Polynomial from party 0
#'   (base64url). NULL if this is party 0.
#' @param gkg_seed Character or NULL. GKG seed from party 0 (base64url).
#'   NULL if this is party 0.
#' @param num_obs Integer. Number of observations (determines galois key
#'   rotation indices). Default 100.
#' @param log_n Integer. CKKS ring dimension parameter (12, 13, or 14).
#'   Default 12.
#' @param log_scale Integer. CKKS scale parameter controlling precision.
#'   Default 40.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{public_key_share}: This server's MHE public key share (base64url)
#'     \item \code{galois_key_shares}: Galois key generation shares (base64url vector)
#'     \item \code{party_id}: Echo of the party ID
#'     \item \code{transport_pk}: X25519 transport public key (base64url)
#'     \item \code{crp}: Common Reference Polynomial (party 0 only, base64url)
#'     \item \code{gkg_seed}: Galois Key Generation seed (party 0 only, base64url)
#'   }
#'
#' @seealso \code{\link{mheStoreTransportKeysDS}} for distributing transport PKs,
#'   \code{\link{mheCombineDS}} for combining public key shares
#' @export
mheInitDS <- function(party_id, crp = NULL, gkg_seed = NULL,
                      num_obs = 100, log_n = 12, log_scale = 40) {
  input <- list(
    party_id = as.integer(party_id),
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  # If not party 0, include CRP and shared GKG seed
  if (party_id > 0 && !is.null(crp)) {
    input$crp <- .base64url_to_base64(crp)
  }
  if (!is.null(gkg_seed)) {
    input$gkg_seed <- .base64url_to_base64(gkg_seed)
  }

  result <- .callMheTool("mhe-setup", input)

  # SECURITY: secret key share is stored locally and NEVER returned to the
  # client. This is the foundation of the threshold property: the collective
  # secret key sk = sk_1 + sk_2 + ... + sk_K is never reconstructed.
  .mhe_storage$secret_key <- result$secret_key
  .mhe_storage$party_id <- party_id
  .mhe_storage$log_n <- log_n
  .mhe_storage$log_scale <- log_scale

  # Generate X25519 transport keypair for share-wrapping and GLM secure routing.
  # The transport SK is stored locally (NEVER returned); the PK is distributed
  # to all other servers via the client so they can encrypt data for us.
  transport <- .callMheTool("transport-keygen", list())
  .mhe_storage$transport_sk <- transport$secret_key
  .mhe_storage$transport_pk <- transport$public_key

  # Return only public information: the public key share (safe to combine)
  # and Galois key generation shares (for enabling ciphertext rotations).
  output <- list(
    public_key_share = base64_to_base64url(result$public_key_share),
    galois_key_shares = sapply(result$galois_key_shares, base64_to_base64url, USE.NAMES = FALSE),
    party_id = party_id,
    transport_pk = base64_to_base64url(transport$public_key)
  )

  # Party 0 also returns CRP and GKG seed
  if (party_id == 0) {
    output$crp <- base64_to_base64url(result$crp)
    output$gkg_seed <- base64_to_base64url(result$gkg_seed)
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
mheCombineDS <- function(public_key_shares = NULL, crp = NULL, galois_key_shares = NULL,
                         gkg_seed = NULL, num_obs = 100, log_n = 12, log_scale = 40,
                         from_storage = FALSE, n_parties = 0, n_gkg_shares = 0) {
  if (from_storage) {
    # Read all inputs from blob storage (set via mheStoreBlobDS)
    blobs <- .mhe_storage$blobs
    if (is.null(blobs)) stop("No blobs stored for combine", call. = FALSE)

    pk_shares <- character(n_parties)
    for (i in seq_len(n_parties)) {
      pk_shares[i] <- .base64url_to_base64(blobs[[paste0("pk_", i - 1)]])
    }
    crp_std <- .base64url_to_base64(blobs[["crp"]])
    gkg_seed_std <- if (!is.null(blobs[["gkg_seed"]])) .base64url_to_base64(blobs[["gkg_seed"]]) else ""

    gkg_shares_std <- list()
    if (n_gkg_shares > 0) {
      for (i in seq_len(n_parties)) {
        party_shares <- character(n_gkg_shares)
        for (j in seq_len(n_gkg_shares)) {
          party_shares[j] <- .base64url_to_base64(blobs[[paste0("gkg_", i - 1, "_", j - 1)]])
        }
        gkg_shares_std[[i]] <- party_shares
      }
    }

    # Clean up blobs
    .mhe_storage$blobs <- NULL
  } else {
    # Direct arguments (backward-compatible, small datasets only)
    pk_shares <- sapply(public_key_shares, .base64url_to_base64, USE.NAMES = FALSE)
    crp_std <- .base64url_to_base64(crp)

    gkg_shares_std <- list()
    if (!is.null(galois_key_shares) && length(galois_key_shares) > 0) {
      gkg_shares_std <- lapply(galois_key_shares, function(party_shares) {
        sapply(party_shares, .base64url_to_base64, USE.NAMES = FALSE)
      })
    }

    gkg_seed_std <- ""
    if (!is.null(gkg_seed)) {
      gkg_seed_std <- .base64url_to_base64(gkg_seed)
    }
  }

  input <- list(
    public_key_shares = as.list(pk_shares),
    galois_key_shares = gkg_shares_std,
    gkg_seed = gkg_seed_std,
    crp = crp_std,
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("mhe-combine", input)

  # Store combined keys locally. The CPK is used for encryption;
  # Galois keys enable ciphertext rotations (needed for inner-product
  # computation). The combining server stores these directly; other
  # servers receive them via mheStoreCPKDS.
  .mhe_storage$cpk <- result$collective_public_key
  .mhe_storage$galois_keys <- result$galois_keys
  .mhe_storage$relin_key <- result$relinearization_key

  # Return CPK and Galois keys to client for distribution to other servers.
  gk_out <- NULL
  if (!is.null(result$galois_keys) && length(result$galois_keys) > 0) {
    gk_out <- sapply(result$galois_keys, base64_to_base64url, USE.NAMES = FALSE)
  }

  list(
    collective_public_key = base64_to_base64url(result$collective_public_key),
    galois_keys = gk_out
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
mheStoreCPKDS <- function(cpk = NULL, galois_keys = NULL, relin_key = NULL,
                          from_storage = FALSE) {
  if (from_storage) {
    blobs <- .mhe_storage$blobs
    if (is.null(blobs)) stop("No blobs stored for CPK", call. = FALSE)

    .mhe_storage$cpk <- .base64url_to_base64(blobs[["cpk"]])

    # Read Galois keys from blobs gk_0, gk_1, ...
    gk_keys <- sort(grep("^gk_", names(blobs), value = TRUE))
    if (length(gk_keys) > 0) {
      .mhe_storage$galois_keys <- sapply(gk_keys, function(k) {
        .base64url_to_base64(blobs[[k]])
      }, USE.NAMES = FALSE)
    }

    if (!is.null(blobs[["rk"]])) {
      .mhe_storage$relin_key <- .base64url_to_base64(blobs[["rk"]])
    }

    .mhe_storage$blobs <- NULL
  } else {
    .mhe_storage$cpk <- .base64url_to_base64(cpk)

    if (!is.null(galois_keys)) {
      .mhe_storage$galois_keys <- sapply(galois_keys, .base64url_to_base64, USE.NAMES = FALSE)
    }
    if (!is.null(relin_key)) {
      .mhe_storage$relin_key <- .base64url_to_base64(relin_key)
    }
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
        h <- .register_ciphertext(er[i, j], "cross-product")
        ct_hashes <- c(ct_hashes, h)
        er[i, j] <- base64_to_base64url(er[i, j])
      }
    }
  } else {
    n_rows <- length(er)
    n_cols <- if (n_rows > 0) length(er[[1]]) else 0
    for (i in seq_along(er)) {
      for (j in seq_along(er[[i]])) {
        h <- .register_ciphertext(er[[i]][[j]], "cross-product")
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

#' Batch-authorize ciphertexts for decryption on this server
#'
#' Called by the client to authorize a batch of ciphertexts for partial
#' decryption. The ct_hashes are SHA-256 hashes of ciphertexts produced by
#' a legitimate operation on another server. The client relays these hashes
#' (which do not reveal ciphertext content) so that this server knows which
#' ciphertexts are authorized for decryption.
#'
#' This prevents the decryption oracle attack: a client cannot fabricate
#' arbitrary ciphertexts for decryption because the hashes must match
#' ciphertexts produced by actual server-side operations.
#'
#' @param ct_hashes Character vector. SHA-256 hashes of authorized ciphertexts
#' @param op_type Character. Operation type ("cross-product" or "glm-gradient")
#'
#' @return Integer. Number of ciphertexts authorized
#' @export
mheAuthorizeCTDS <- function(ct_hashes, op_type = "cross-product") {
  if (is.null(.mhe_storage$secret_key)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  if (is.null(.mhe_storage$ct_registry)) {
    .mhe_storage$ct_registry <- list()
  }
  if (is.null(.mhe_storage$op_counter)) {
    .mhe_storage$op_counter <- 0L
  }

  for (ct_hash in ct_hashes) {
    .mhe_storage$op_counter <- .mhe_storage$op_counter + 1L
    .mhe_storage$ct_registry[[ct_hash]] <- list(
      op_id = .mhe_storage$op_counter,
      op_type = op_type,
      timestamp = Sys.time()
    )
  }

  length(ct_hashes)
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
#' Protected by the Protocol Firewall: only ciphertexts that were registered
#' (by the producing server) or authorized (via \code{mheAuthorizeCTDS} with
#' a valid HMAC token) can be decrypted. Each authorization is consumed after
#' one use (anti-replay).
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

  # Reassemble ciphertext from chunks. CKKS ciphertexts can be 50-200KB
  # as base64, exceeding DataSHIELD/R parser limits for single string
  # arguments. Chunking at ~10KB per chunk avoids these limits.
  ct_b64url <- paste0(.mhe_storage$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)

  # Clean up chunks after use to free memory
  .mhe_storage$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized for decryption.
  # This prevents the decryption oracle attack where an adversary submits
  # arbitrary ciphertexts to recover plaintext or secret key information.
  .validate_and_consume_ciphertext(ct_b64)

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

# ============================================================================
# Share-Wrapping: Transport key distribution + wrapped partial decrypt + fusion
# ============================================================================

#' Store transport public keys from other servers
#'
#' Called by the client after \code{\link{mheInitDS}} to distribute each
#' server's X25519 transport public key to all other servers. These keys
#' enable two security features:
#' \itemize{
#'   \item \strong{Share-wrapping}: encrypting partial decryption shares
#'     under the fusion server's transport PK so the client cannot read them
#'   \item \strong{GLM Secure Routing}: encrypting eta/mu/w/v vectors
#'     end-to-end between the coordinator and non-label servers
#' }
#'
#' @param transport_keys Named list. Server name -> transport public key
#'   (base64url). Must include a \code{"fusion"} entry identifying the
#'   fusion server's (party 0) transport PK.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mheInitDS}} which generates the transport keypair,
#'   \code{\link{mhePartialDecryptWrappedDS}} which uses the fusion PK
#' @export
mheStoreTransportKeysDS <- function(transport_keys) {
  if (is.null(.mhe_storage$secret_key)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  # Convert from base64url to standard base64 for internal use
  .mhe_storage$peer_transport_pks <- lapply(transport_keys, .base64url_to_base64)

  TRUE
}

#' Compute wrapped partial decryption share
#'
#' Same as \code{\link{mhePartialDecryptDS}} but the resulting decryption
#' share is transport-encrypted (wrapped) under the fusion server's X25519
#' public key before being returned. The client receives an opaque blob it
#' cannot read; it relays this blob to the fusion server via
#' \code{\link{mheStoreWrappedShareDS}} for server-side fusion.
#'
#' This eliminates the client's ability to fuse shares locally, preventing
#' share reuse or manipulation by a malicious client.
#'
#' @param n_chunks Integer. Number of stored ciphertext chunks (previously
#'   sent via \code{\link{mheStoreCTChunkDS}}).
#'
#' @return List with:
#'   \itemize{
#'     \item \code{wrapped_share}: Transport-encrypted decryption share
#'       (base64url). Opaque to the client.
#'     \item \code{party_id}: This server's party ID.
#'   }
#'
#' @seealso \code{\link{mhePartialDecryptDS}} for the unwrapped variant,
#'   \code{\link{mheFuseServerDS}} for server-side fusion
#' @export
mhePartialDecryptWrappedDS <- function(n_chunks) {
  if (is.null(.mhe_storage$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(.mhe_storage$ct_chunks) || length(.mhe_storage$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  fusion_pk <- .mhe_storage$peer_transport_pks[["fusion"]]
  if (is.null(fusion_pk)) {
    stop("Fusion server transport PK not stored. Call mheStoreTransportKeysDS first.",
         call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(.mhe_storage$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  .mhe_storage$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized
  .validate_and_consume_ciphertext(ct_b64)

  # Compute raw partial decryption share
  input <- list(
    ciphertext = ct_b64,
    secret_key = .mhe_storage$secret_key,
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )
  result <- .callMheTool("mhe-partial-decrypt", input)

  # Transport-encrypt (wrap) the share under the fusion server's PK.
  # The share is a serialized KeySwitch share in standard base64.
  # After wrapping, the client sees only ciphertext it cannot decrypt.
  sealed <- .callMheTool("transport-encrypt", list(
    data = result$decryption_share,
    recipient_pk = fusion_pk
  ))

  list(
    wrapped_share = base64_to_base64url(sealed$sealed),
    party_id = .mhe_storage$party_id
  )
}

#' Store a wrapped share on the fusion server
#'
#' Called by the client to relay a transport-encrypted partial decryption
#' share to the fusion server (party 0). The client cannot read the share
#' because it is encrypted under the fusion server's X25519 transport key.
#'
#' Supports chunked transfer: multiple calls with the same \code{party_id}
#' concatenate the data. The full share is assembled when
#' \code{\link{mheFuseServerDS}} is called.
#'
#' @param party_id Integer or character. Party ID of the server that
#'   produced this share.
#' @param share_data Character. The wrapped share data (base64url encoded),
#'   or a chunk of it. Multiple calls with the same \code{party_id}
#'   concatenate the data.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mhePartialDecryptWrappedDS}} which produces the
#'   wrapped share, \code{\link{mheFuseServerDS}} which consumes them
#' @export
mheStoreWrappedShareDS <- function(party_id, share_data) {
  if (is.null(.mhe_storage$wrapped_share_parts)) {
    .mhe_storage$wrapped_share_parts <- list()
  }
  key <- as.character(party_id)
  # Concatenate chunks: multiple calls with the same party_id append data
  if (is.null(.mhe_storage$wrapped_share_parts[[key]])) {
    .mhe_storage$wrapped_share_parts[[key]] <- share_data
  } else {
    .mhe_storage$wrapped_share_parts[[key]] <- paste0(
      .mhe_storage$wrapped_share_parts[[key]], share_data)
  }
  TRUE
}

#' Fuse partial decryption shares server-side (fusion server only)
#'
#' Called on the fusion server (party 0) after all wrapped shares have been
#' relayed via \code{\link{mheStoreWrappedShareDS}} and the ciphertext
#' stored via \code{\link{mheStoreCTChunkDS}}. This function:
#' \enumerate{
#'   \item Reassembles the ciphertext from stored chunks
#'   \item Validates the ciphertext via the Protocol Firewall (one-time use)
#'   \item Unwraps (transport-decrypts) each wrapped share using its X25519 SK
#'   \item Computes its own partial decryption share (with noise smudging)
#'   \item Aggregates all shares and applies KeySwitch + DecodePublic(logprec=32)
#'   \item Returns only the final sanitized scalar/vector
#' }
#'
#' The client never sees raw decryption shares or unsanitized plaintext.
#'
#' @param n_parties Integer. Total number of MHE parties (including this
#'   fusion server). Used for validation only.
#' @param n_ct_chunks Integer. Number of stored ciphertext chunks.
#' @param num_slots Integer. Number of valid slots to return. Use 0 for a
#'   single scalar (slot 0 only), or n_obs for a vector. Default 0.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{value}: Decrypted scalar (first slot)
#'     \item \code{values}: Numeric vector of length \code{num_slots}
#'       (present only when \code{num_slots > 0})
#'   }
#'
#' @seealso \code{\link{mheStoreWrappedShareDS}} for storing wrapped shares,
#'   \code{\link{mhePartialDecryptWrappedDS}} for producing wrapped shares
#' @export
mheFuseServerDS <- function(n_parties, n_ct_chunks, num_slots = 0) {
  if (is.null(.mhe_storage$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(.mhe_storage$transport_sk)) {
    stop("Transport secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(.mhe_storage$ct_chunks) || length(.mhe_storage$ct_chunks) < n_ct_chunks) {
    stop("Ciphertext chunks not stored.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(.mhe_storage$ct_chunks[1:n_ct_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  .mhe_storage$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext
  .validate_and_consume_ciphertext(ct_b64)

  # Collect wrapped shares (from other servers, stored via mheStoreWrappedShareDS)
  parts <- .mhe_storage$wrapped_share_parts
  if (is.null(parts) || length(parts) == 0) {
    stop("No wrapped shares stored. Relay shares via mheStoreWrappedShareDS first.",
         call. = FALSE)
  }
  # Convert each assembled share from base64url to base64 (unnamed list for JSON array)
  wrapped_shares <- unname(lapply(parts, .base64url_to_base64))

  # Call mhe-fuse-server: unwrap + own partial decrypt + aggregate + DecodePublic
  result <- .callMheTool("mhe-fuse-server", list(
    ciphertext = ct_b64,
    secret_key = .mhe_storage$secret_key,
    wrapped_shares = wrapped_shares,
    transport_secret_key = .mhe_storage$transport_sk,
    num_slots = as.integer(num_slots),
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  ))

  # Clean up wrapped shares
  .mhe_storage$wrapped_share_parts <- NULL

  list(value = result$value, values = result$values)
}

#' Store a blob in server-side storage (with chunking support)
#'
#' Generic function for storing base64url-encoded blobs on the server.
#' Used by GLM Secure Routing to relay encrypted vectors (eta, mu/w/v)
#' between servers through the client.
#'
#' For large blobs that exceed DataSHIELD's parser limits, call this
#' function multiple times with chunk_index and n_chunks. The blob is
#' auto-assembled when the last chunk arrives.
#'
#' @param key Character. Storage key (e.g., "mwv", "eta_server1")
#' @param chunk Character. The blob data (or a chunk of it)
#' @param chunk_index Integer. Current chunk index (1-based). Default 1.
#' @param n_chunks Integer. Total number of chunks. Default 1 (no chunking).
#'
#' @return TRUE on success
#' @export
mheStoreBlobDS <- function(key, chunk, chunk_index = 1L, n_chunks = 1L) {
  if (n_chunks == 1L) {
    # Single-call mode (no chunking)
    if (is.null(.mhe_storage$blobs)) .mhe_storage$blobs <- list()
    .mhe_storage$blobs[[key]] <- chunk
  } else {
    # Chunked mode
    if (is.null(.mhe_storage$blob_chunks)) .mhe_storage$blob_chunks <- list()
    if (is.null(.mhe_storage$blob_chunks[[key]])) {
      .mhe_storage$blob_chunks[[key]] <- character(n_chunks)
    }
    .mhe_storage$blob_chunks[[key]][chunk_index] <- chunk

    # Auto-assemble when all chunks are present
    if (all(nzchar(.mhe_storage$blob_chunks[[key]]))) {
      if (is.null(.mhe_storage$blobs)) .mhe_storage$blobs <- list()
      .mhe_storage$blobs[[key]] <- paste0(.mhe_storage$blob_chunks[[key]], collapse = "")
      .mhe_storage$blob_chunks[[key]] <- NULL
    }
  }
  TRUE
}

#' Get number of observations for a variable
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to check
#'
#' @return Integer. Number of complete observations
#' @export
mheGetObsDS <- function(data_name, variables) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  sum(complete.cases(X))
}

#' Clean up MHE cryptographic state
#'
#' Removes all cryptographic material from server memory: secret key, CPK,
#' Galois keys, ciphertext registry, and any residual protocol state.
#' Called by the client at the end of each protocol execution to minimize
#' the window during which keys exist in memory.
#'
#' @return TRUE on success
#' @export
mheCleanupDS <- function() {
  # Remove all cryptographic state
  rm(list = ls(.mhe_storage), envir = .mhe_storage)
  # Force garbage collection to release memory holding key material
  gc(verbose = FALSE)
  TRUE
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
