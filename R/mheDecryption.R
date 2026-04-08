#' @title MHE Threshold Decryption and Fusion
#' @description Protocol Firewall authorization, partial decryption, share
#'   wrapping, transport key distribution, and server-side fusion for the
#'   MHE threshold decryption protocol.
#' @name mhe-decryption
NULL

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
#' @param ct_hashes Character vector. SHA-256 hashes of authorized ciphertexts.
#'   Ignored when \code{from_storage = TRUE}.
#' @param op_type Character. Operation type ("cross-product" or "glm-gradient")
#' @param from_storage Logical. If \code{TRUE}, read \code{ct_hashes} from
#'   server-side blob storage (comma-separated) instead of inline argument.
#'   Default \code{FALSE}.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return Integer. Number of ciphertexts authorized
#' @export
mheAuthorizeCTDS <- function(ct_hashes = NULL, op_type = "cross-product",
                             from_storage = FALSE, auto_from_ct = FALSE,
                             session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  # Auto-register: compute hashes directly from stored ct_batch blobs
  # Used for masked eta decryption (avoids sending hashes via DataSHIELD parser)
  if (isTRUE(auto_from_ct)) {
    blobs <- .blob_snapshot(ss)
    ct_keys <- sort(grep("^ct_batch_", names(blobs), value = TRUE))
    ct_hashes <- character(0)
    for (key in ct_keys) {
      ct_b64 <- .base64url_to_base64(blobs[[key]])
      ct_hashes <- c(ct_hashes, digest::digest(ct_b64, algo = "sha256", serialize = FALSE))
    }
    if (length(ct_hashes) == 0) stop("No ct_batch blobs for auto-authorization", call. = FALSE)
  } else if (from_storage) {
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L || is.null(blobs[["ct_hashes"]])) {
      stop("No ct_hashes blob stored", call. = FALSE)
    }
    ct_hashes <- strsplit(blobs[["ct_hashes"]], ",", fixed = TRUE)[[1]]
    .blob_consume("ct_hashes", ss)  # Only remove ct_hashes, not all blobs
  }

  if (is.null(ss$ct_registry)) {
    ss$ct_registry <- list()
  }
  if (is.null(ss$op_counter)) {
    ss$op_counter <- 0L
  }

  for (ct_hash in ct_hashes) {
    ss$op_counter <- ss$op_counter + 1L
    ss$ct_registry[[ct_hash]] <- list(
      op_id = ss$op_counter,
      op_type = op_type,
      timestamp = Sys.time()
    )
  }

  length(ct_hashes)
}

#' Compute partial decryption using stored secret key and stored ciphertext chunks
#'
#' Protected by the Protocol Firewall: only ciphertexts that were registered
#' (by the producing server) or authorized (via \code{mheAuthorizeCTDS} with
#' a valid HMAC token) can be decrypted. Each authorization is consumed after
#' one use (anti-replay).
#'
#' @param n_chunks Integer. Number of stored ciphertext chunks
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with decryption_share (chunked as a character vector)
#' @export
mhePartialDecryptDS <- function(n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks. CKKS ciphertexts can be 50-200KB
  # as base64, exceeding DataSHIELD/R parser limits for single string
  # arguments. The client uses adaptive chunking (default 200KB, auto-reduced
  # on failure) to stay within these limits.
  ct_b64url <- paste0(ss$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)

  # Clean up chunks after use to free memory
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized for decryption.
  # This prevents the decryption oracle attack where an adversary submits
  # arbitrary ciphertexts to recover plaintext or secret key information.
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  input <- list(
    ciphertext = ct_b64,
    secret_key = .key_get("secret_key", ss),
    log_n = as.integer(ss$log_n %||% 13),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-partial-decrypt", input)

  # Return share as chunks (to avoid large return through DataSHIELD)
  share_b64url <- base64_to_base64url(result$decryption_share)

  list(
    decryption_share = share_b64url,
    party_id = ss$party_id
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
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mheInitDS}} which generates the transport keypair,
#'   \code{\link{mhePartialDecryptWrappedDS}} which uses the fusion PK
#' @export
mheStoreTransportKeysDS <- function(transport_keys, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  # Convert from base64url to standard base64 for internal use
  ss$peer_transport_pks <- lapply(transport_keys, .base64url_to_base64)

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
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
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
mhePartialDecryptWrappedDS <- function(n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  fusion_pk <- ss$peer_transport_pks[["fusion"]]
  if (is.null(fusion_pk)) {
    stop("Fusion server transport PK not stored. Call mheStoreTransportKeysDS first.",
         call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(ss$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  # Compute raw partial decryption share
  input <- list(
    ciphertext = ct_b64,
    secret_key = .key_get("secret_key", ss),
    log_n = as.integer(ss$log_n %||% 13),
    log_scale = as.integer(ss$log_scale %||% 40)
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
    party_id = ss$party_id
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
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mhePartialDecryptWrappedDS}} which produces the
#'   wrapped share, \code{\link{mheFuseServerDS}} which consumes them
#' @export
mheStoreWrappedShareDS <- function(party_id, share_data, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$wrapped_share_parts)) {
    ss$wrapped_share_parts <- list()
  }
  key <- as.character(party_id)
  # Concatenate chunks: multiple calls with the same party_id append data
  if (is.null(ss$wrapped_share_parts[[key]])) {
    ss$wrapped_share_parts[[key]] <- share_data
  } else {
    ss$wrapped_share_parts[[key]] <- paste0(
      ss$wrapped_share_parts[[key]], share_data)
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
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
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
mheFuseServerDS <- function(n_parties, n_ct_chunks, num_slots = 0,
                            session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (!.key_exists("transport_sk", ss)) {
    stop("Transport secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_ct_chunks) {
    stop("Ciphertext chunks not stored.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(ss$ct_chunks[1:n_ct_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  # Collect wrapped shares (from other servers, stored via mheStoreWrappedShareDS)
  parts <- ss$wrapped_share_parts
  if (is.null(parts) || length(parts) == 0) {
    stop("No wrapped shares stored. Relay shares via mheStoreWrappedShareDS first.",
         call. = FALSE)
  }
  # Convert each assembled share from base64url to base64 (unnamed list for JSON array)
  wrapped_shares <- unname(lapply(parts, .base64url_to_base64))

  # Call mhe-fuse-server: unwrap + own partial decrypt + aggregate + DecodePublic
  result <- .callMheTool("mhe-fuse-server", list(
    ciphertext = ct_b64,
    secret_key = .key_get("secret_key", ss),
    wrapped_shares = wrapped_shares,
    transport_secret_key = .key_get("transport_sk", ss),
    num_slots = as.integer(num_slots),
    log_n = as.integer(ss$log_n %||% 13),
    log_scale = as.integer(ss$log_scale %||% 40)
  ))

  # Clean up wrapped shares
  ss$wrapped_share_parts <- NULL

  list(value = result$value, values = result$values)
}

#' Batch partial decryption with share-wrapping
#'
#' Processes multiple ciphertexts stored in blob storage in a single call,
#' returning all wrapped partial decryption shares concatenated. This reduces
#' client-server round-trips from O(n_cts * K) to O(K) for the threshold
#' decryption phase.
#'
#' @param n_cts Integer. Number of ciphertexts stored as blobs with keys
#'   \code{"ct_batch_1"}, \code{"ct_batch_2"}, ..., \code{"ct_batch_N"}.
#' @param session_id Character or NULL. Session identifier.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{wrapped_shares}: Character vector of length \code{n_cts},
#'       each element a transport-encrypted partial decryption share (base64url).
#'     \item \code{party_id}: This server's party ID.
#'   }
#' @export
mhePartialDecryptBatchWrappedDS <- function(n_cts, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss))
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)

  fusion_pk <- ss$peer_transport_pks[["fusion"]]
  if (is.null(fusion_pk))
    stop("Fusion server transport PK not stored.", call. = FALSE)

  sk <- .key_get("secret_key", ss)
  wrapped <- character(n_cts)

  for (i in seq_len(n_cts)) {
    key <- paste0("ct_batch_", i)
    ct_b64url <- .blob_consume(key, ss)
    if (is.null(ct_b64url))
      stop("Ciphertext batch blob '", key, "' not found.", call. = FALSE)
    ct_b64 <- .base64url_to_base64(ct_b64url)

    .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

    result <- .callMheTool("mhe-partial-decrypt", list(
      ciphertext = ct_b64,
      secret_key = sk,
      log_n = as.integer(ss$log_n %||% 13),
      log_scale = as.integer(ss$log_scale %||% 40)
    ))

    sealed <- .callMheTool("transport-encrypt", list(
      data = result$decryption_share,
      recipient_pk = fusion_pk
    ))
    wrapped[i] <- base64_to_base64url(sealed$sealed)
  }

  list(wrapped_shares = wrapped, party_id = ss$party_id)
}

#' Batch fusion of wrapped partial decryption shares
#'
#' Unwraps and fuses partial decryption shares for multiple ciphertexts
#' in a single call. Each ciphertext has shares from all non-fusion parties
#' stored via blob storage, plus the fusion server's own ciphertext.
#'
#' @param n_cts Integer. Number of ciphertexts to fuse.
#' @param n_parties Integer. Total number of parties (K).
#' @param num_slots Integer. Number of CKKS slots (observations).
#' @param session_id Character or NULL. Session identifier.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{values}: Numeric vector of length \code{n_cts}, the
#'       decrypted and sanitized scalar values.
#'   }
#' @export
mheFuseBatchDS <- function(n_cts, n_parties, num_slots, session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("secret_key", ss))
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  if (!.key_exists("transport_sk", ss))
    stop("Transport SK not stored.", call. = FALSE)

  sk <- .key_get("secret_key", ss)
  tsk <- .key_get("transport_sk", ss)
  values <- numeric(n_cts)
  slot_values <- if (num_slots > 0) vector("list", n_cts) else NULL

  for (i in seq_len(n_cts)) {
    ct_key <- paste0("ct_batch_", i)
    ct_b64url <- .blob_consume(ct_key, ss)
    if (is.null(ct_b64url))
      stop("Ciphertext '", ct_key, "' not found.", call. = FALSE)
    ct_b64 <- .base64url_to_base64(ct_b64url)

    .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

    # Collect wrapped shares from all non-fusion parties
    shares <- list()
    for (pid in seq_len(n_parties - 1)) {
      share_key <- paste0("wrapped_share_", pid, "_ct_", i)
      share_data <- .blob_consume(share_key, ss)
      if (is.null(share_data))
        stop("Wrapped share for party ", pid, " CT ", i, " not found.", call. = FALSE)
      shares[[length(shares) + 1]] <- .base64url_to_base64(share_data)
    }

    # Fuse: unwrap all shares, compute own share, aggregate
    fuse_input <- list(
      ciphertext = ct_b64,
      secret_key = sk,
      transport_secret_key = tsk,
      wrapped_shares = shares,
      num_slots = as.integer(num_slots),
      log_n = as.integer(ss$log_n %||% 13),
      log_scale = as.integer(ss$log_scale %||% 40)
    )
    fuse_result <- .callMheTool("mhe-fuse-server", fuse_input)
    values[i] <- fuse_result$value
    # When num_slots > 0, Go returns individual slot values in $values
    if (!is.null(slot_values) && !is.null(fuse_result$values))
      slot_values[[i]] <- fuse_result$values
  }

  result <- list(values = values)
  if (!is.null(slot_values)) result$slot_values <- slot_values
  result
}
