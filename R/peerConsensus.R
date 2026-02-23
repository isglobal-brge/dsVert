#' @title Peer Manifest Consensus
#' @description Functions for cross-validating that all servers see the same
#'   peer set and configuration. Prevents a malicious client from telling
#'   different servers different peer sets (phantom peer injection).
#'
#' @details
#' After transport key distribution, each server computes
#' \code{SHA-256(canonical_manifest_json)} and transport-encrypts its hash
#' to each peer. Each peer decrypts and compares. Mismatch triggers a stop.
#'
#' @name peer-consensus
NULL

# ============================================================================
# Internal Helpers
# ============================================================================

#' Build a canonical JSON manifest for deterministic hashing
#'
#' Creates a JSON string with sorted keys for reproducible SHA-256 hashing.
#' The manifest captures the essential session parameters that all servers
#' must agree on.
#'
#' @param job_id Character. Session/job identifier.
#' @param method Character. The GLM method/family.
#' @param peers Character vector. Sorted list of all server names.
#' @param transport_pks Named list. Server name -> transport PK (standard base64).
#' @param y_server Character. Name of the label server.
#' @param non_label_servers Character vector. Non-label server names.
#' @param topology Character. Topology mode ("pairwise" or "ring").
#' @return Character. Canonical JSON string.
#' @keywords internal
.build_manifest <- function(job_id, method, peers, transport_pks,
                            y_server, non_label_servers, topology) {
  # Sort all vectors and keys for determinism
  peers <- sort(peers)
  non_label_servers <- sort(non_label_servers)

  # Build transport_pks in sorted-key order
  pk_sorted <- transport_pks[sort(names(transport_pks))]

  manifest <- list(
    job_id = job_id,
    method = method,
    non_label_servers = non_label_servers,
    peers = peers,
    topology = topology,
    transport_pks = pk_sorted,
    y_server = y_server
  )

  # jsonlite with auto_unbox for scalar values, sorted keys already enforced
  jsonlite::toJSON(manifest, auto_unbox = TRUE)
}

#' Compute SHA-256 hash of a manifest JSON string
#'
#' @param manifest_json Character. Canonical JSON manifest string.
#' @return Character. Hex-encoded SHA-256 hash.
#' @keywords internal
.compute_manifest_hash <- function(manifest_json) {
  digest::digest(manifest_json, algo = "sha256", serialize = FALSE)
}

# ============================================================================
# Exported Functions
# ============================================================================

#' Store peer manifest and compute hash for consensus validation
#'
#' Called by the client after transport key distribution. Stores the canonical
#' manifest and its SHA-256 hash in session storage. Returns transport-encrypted
#' hashes for each peer so the client can relay them.
#'
#' @param manifest_json Character. Canonical JSON manifest string (built by
#'   the client using the same deterministic key-sorting as
#'   \code{.build_manifest}).
#' @param session_id Character or NULL. Session identifier.
#'
#' @return Named list. Peer name -> transport-encrypted hash blob (base64url).
#'   Each blob is encrypted under the corresponding peer's transport PK.
#' @export
peerManifestStoreDS <- function(manifest_json, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$transport_sk)) {
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$peer_transport_pks)) {
    stop("Peer transport PKs not stored. Call mheStoreTransportKeysDS first.",
         call. = FALSE)
  }

  # Store manifest and its hash
  ss$manifest_json <- manifest_json
  ss$manifest_hash <- .compute_manifest_hash(manifest_json)

  # Transport-encrypt our hash for each peer
  hash_blob <- ss$manifest_hash
  encrypted_hashes <- list()

  for (peer_name in names(ss$peer_transport_pks)) {
    peer_pk <- ss$peer_transport_pks[[peer_name]]
    # Encrypt the hash string under the peer's transport PK
    data_b64 <- jsonlite::base64_enc(charToRaw(hash_blob))
    sealed <- .callMheTool("transport-encrypt", list(
      data = data_b64,
      recipient_pk = peer_pk
    ))
    encrypted_hashes[[peer_name]] <- base64_to_base64url(sealed$sealed)
  }

  # Initialize validated peers tracking
  ss$validated_peers <- character(0)

  encrypted_hashes
}

#' Validate a peer's manifest hash against our own
#'
#' Called by the client after relaying encrypted hashes between servers.
#' Decrypts a peer's hash blob from blob storage, compares against our
#' own manifest hash, and tracks validation state.
#'
#' @param peer_name Character. Name of the peer whose hash to validate.
#' @param session_id Character or NULL. Session identifier.
#'
#' @return \code{TRUE} if the peer's hash matches ours.
#' @export
peerManifestValidateDS <- function(peer_name, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$manifest_hash)) {
    stop("Manifest not stored. Call peerManifestStoreDS first.", call. = FALSE)
  }
  if (is.null(ss$transport_sk)) {
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  }

  # Read the encrypted hash blob from blob storage
  blob_key <- paste0("manifest_hash_", peer_name)
  blobs <- ss$blobs
  if (is.null(blobs) || is.null(blobs[[blob_key]])) {
    stop("No manifest hash blob stored for peer '", peer_name, "'",
         call. = FALSE)
  }

  sealed_b64url <- blobs[[blob_key]]
  ss$blobs[[blob_key]] <- NULL  # consume

  # Decrypt the peer's hash using our transport SK
  sealed_b64 <- .base64url_to_base64(sealed_b64url)
  result <- .callMheTool("transport-decrypt", list(
    sealed = sealed_b64,
    recipient_sk = ss$transport_sk
  ))
  peer_hash <- rawToChar(jsonlite::base64_dec(result$data))

  # Compare against our own hash

  if (peer_hash != ss$manifest_hash) {
    stop("Manifest consensus FAILED: peer '", peer_name,
         "' has a different manifest hash. ",
         "Possible phantom peer injection by client.",
         call. = FALSE)
  }

  # Track this peer as validated
  ss$validated_peers <- unique(c(ss$validated_peers, peer_name))

  TRUE
}
