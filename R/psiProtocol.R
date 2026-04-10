#' @title ECDH-PSI Record Alignment - Server-Side Functions (Blind Relay)
#' @description These functions implement Elliptic Curve Diffie-Hellman Private Set
#'   Intersection (ECDH-PSI) for privacy-preserving record alignment across vertically
#'   partitioned data. All EC point exchanges are transport-encrypted (X25519 +
#'   AES-256-GCM ECIES) so the client acts as a blind relay, never seeing raw
#'   elliptic curve points.
#'
#' @details
#' The protocol exploits the commutativity of scalar multiplication on P-256:
#' \eqn{\alpha \cdot (\beta \cdot H(id)) = \beta \cdot (\alpha \cdot H(id))}.
#'
#' Security (DDH assumption on P-256, malicious-client model):
#' \itemize{
#'   \item The client sees only opaque encrypted blobs (not reversible)
#'   \item Each server's scalar never leaves the server
#'   \item The PSI firewall enforces phase ordering and one-shot semantics
#'   \item No party can perform dictionary attacks or OPRF oracle attacks
#' }
#'
#' @references
#' De Cristofaro, E. & Tsudik, G. (2010). "Practical Private Set Intersection
#' Protocols with Linear Complexity". \emph{FC 2010}.
#'
#' @name psi-protocol
NULL

# ============================================================================
# PSI Firewall: Phase Ordering FSM
# ============================================================================
# Prevents out-of-order function calls that could be exploited by a
# malicious client. Each PSI function checks the current phase and
# transitions to the next valid phase.
#
# State transitions (ref server):
#   (none) -> init:   psiInitDS()
#   init -> masked:   psiMaskIdsDS()
#   masked -> masked: psiExportMaskedDS() [per target]
#   masked -> masked: psiDoubleMaskDS()   [one-shot per target]
#
# State transitions (target server):
#   (none) -> init:              psiInitDS()
#   init -> target_processed:    psiProcessTargetDS()
#   target_processed -> matched: psiMatchAndAlignDS()
# ============================================================================

#' Check PSI firewall phase (internal)
#' @param operation Character. Name of the operation being attempted.
#' @param required_phase Character. Required phase for this operation.
#' @keywords internal
.psi_firewall_check <- function(operation, required_phase, session_id = NULL) {
  current <- .S(session_id)$psi_phase
  if (is.null(current) || current != required_phase) {
    stop("PSI Firewall: operation '", operation, "' not allowed in phase '",
         if (is.null(current)) "none" else current,
         "'. Required: '", required_phase, "'", call. = FALSE)
  }
}

# ============================================================================
# PSI Transport Encryption Helpers
# ============================================================================

#' Encrypt a string blob under a recipient's transport PK (internal)
#' @param data_str Character. The string data to encrypt.
#' @param recipient_pk_b64 Character. Recipient's X25519 PK (standard base64).
#' @return Character. Sealed data in standard base64.
#' @keywords internal
.psi_encrypt_blob <- function(data_str, recipient_pk_b64) {
  # Convert string to raw bytes, then to base64 for the Go tool
  data_b64 <- jsonlite::base64_enc(charToRaw(data_str))
  result <- .callMpcTool("transport-encrypt", list(
    data = data_b64,
    recipient_pk = recipient_pk_b64
  ))
  result$sealed
}

#' Decrypt a sealed blob using this server's PSI transport SK (internal)
#' @param sealed_b64url Character. Sealed data in base64url (as stored in
#'   blob storage for DataSHIELD parser safety). Converted to standard
#'   base64 before passing to the Go tool.
#' @return Character. The decrypted string.
#' @keywords internal
.psi_decrypt_blob <- function(sealed_b64url, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_transport_sk)) {
    stop("PSI transport SK not available. Call psiInitDS first.", call. = FALSE)
  }
  # Convert from base64url (parser-safe) back to standard base64 (Go tool)
  sealed_b64 <- .base64url_to_base64(sealed_b64url)
  result <- .callMpcTool("transport-decrypt", list(
    sealed = sealed_b64,
    recipient_sk = ss$psi_transport_sk
  ))
  rawToChar(jsonlite::base64_dec(result$data))
}

#' Encrypt already-base64-encoded binary data under a recipient's transport PK (internal)
#'
#' Unlike \code{.psi_encrypt_blob} which takes a string and converts it to raw,
#' this takes data that is already base64-encoded (e.g. from psi-pack-points output)
#' and passes it directly to transport-encrypt.
#'
#' @param data_b64 Character. Already base64-encoded data.
#' @param recipient_pk_b64 Character. Recipient's X25519 PK (standard base64).
#' @return Character. Sealed data in standard base64.
#' @keywords internal
.psi_encrypt_b64data <- function(data_b64, recipient_pk_b64) {
  result <- .callMpcTool("transport-encrypt", list(
    data = data_b64,
    recipient_pk = recipient_pk_b64
  ))
  result$sealed
}

#' Decrypt a sealed blob and return as base64-encoded data (internal)
#'
#' Unlike \code{.psi_decrypt_blob} which returns a character string,
#' this returns the raw base64-encoded payload (for binary packed data).
#'
#' @param sealed_b64url Character. Sealed data in base64url.
#' @param session_id Character or NULL.
#' @return Character. Base64-encoded decrypted data.
#' @keywords internal
.psi_decrypt_to_b64data <- function(sealed_b64url, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_transport_sk)) {
    stop("PSI transport SK not available. Call psiInitDS first.", call. = FALSE)
  }
  sealed_b64 <- .base64url_to_base64(sealed_b64url)
  result <- .callMpcTool("transport-decrypt", list(
    sealed = sealed_b64,
    recipient_sk = ss$psi_transport_sk
  ))
  result$data
}

#' Read and consume a PSI blob from chunked storage (internal)
#' @param key Character. The blob storage key.
#' @return Character. The assembled blob string.
#' @keywords internal
.read_psi_blob <- function(key, session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume(key, ss)
  if (is.null(blob)) {
    stop("No PSI blob stored with key '", key, "'", call. = FALSE)
  }
  blob
}

# ============================================================================
# Pre-Shared Key Pinning (MITM Prevention)
# ============================================================================
# dsVert supports two security modes for PSI transport key exchange:
#
# MODE 1: Semi-Honest (default)
#   - Ephemeral X25519 keys are generated per session
#   - Client mediates key exchange between servers
#   - Protects against passive eavesdropping but NOT active MITM by the client
#   - Suitable for trusted DataSHIELD deployments where the client is trusted
#   - No configuration needed — this is the default when dsvert.psi_key_pinning
#     is unset or FALSE
#
# MODE 2: Full MITM-Resistant (pre-shared keys)
#   - Persistent X25519 keypairs are pre-configured on each server
#   - Servers validate client-provided PKs against pre-configured peers
#   - Detects and rejects MITM attacks where the client substitutes keys
#   - Suitable for untrusted or multi-tenant environments
#
# Configuration (via DataSHIELD R options, following dsBase pattern):
#
# The admin configures these per-server via the Opal DataSHIELD profile
# settings (web UI or dsadmin.set_option()), or via the Rock server's
# .Rprofile / R config:
#
#   options(
#     dsvert.psi_key_pinning = TRUE,           # enable pre-shared key mode
#     dsvert.psi_sk          = "<base64>",      # this server's X25519 secret key
#     dsvert.psi_pk          = "<base64>",      # this server's X25519 public key
#     dsvert.psi_peers       = '["<pk_peer1>","<pk_peer2>"]'
#   )
#
# The dsvert.psi_peers option is a JSON array of trusted peer X25519 public
# keys (standard base64). Validation is by PK value, not by name — so it
# works regardless of what server names the client uses.
#
# Security of R options in DataSHIELD:
#   - The client CANNOT call getOption() remotely — the DataSHIELD parser
#     only allows registered methods (getOption is not registered).
#   - listDisclosureSettingsDS() in dsBase only returns specific nfilter
#     values, NOT arbitrary options like dsvert.psi_sk.
#   - The Opal admin REST API (GET /datashield/options) can read options,
#     but only with administrator credentials — the admin is already trusted.
#   - Our registered functions (psiInitDS, etc.) never return the private key.
#
# All options follow the dsBase two-tier fallback pattern:
#   getOption("dsvert.psi_key_pinning") -> getOption("default.dsvert.psi_key_pinning")
#
# The default for dsvert.psi_key_pinning is FALSE (declared in DESCRIPTION
# Options section), so key pinning is disabled unless explicitly enabled.
# ============================================================================

#' Read a dsVert option using the dsBase two-tier fallback pattern (internal)
#'
#' Checks \code{getOption(name)} first, then falls back to
#' \code{getOption(paste0("default.", name))}. This allows Opal administrators
#' to override settings per DataSHIELD profile.
#'
#' @param name Character. Option name (e.g. "dsvert.psi_key_pinning").
#' @param fallback Default value if neither option is set. Default NULL.
#' @return The option value, or fallback if not set.
#' @keywords internal
.read_dsvert_option <- function(name, fallback = NULL) {
  val <- getOption(name)
  if (is.null(val)) val <- getOption(paste0("default.", name))
  if (is.null(val)) val <- fallback
  val
}

# ============================================================================
# Phase 0: PSI Transport Key Exchange
# ============================================================================

#' Initialize PSI transport keys (aggregate function)
#'
#' Generates an X25519 transport keypair for blind-relay PSI. The secret key
#' is stored locally and NEVER returned to the client. The public key is
#' returned so the client can distribute it to other servers.
#'
#' This must be called before any other PSI function. Initializes the PSI
#' firewall state machine.
#'
#' @section Security Modes:
#' \describe{
#'   \item{Semi-Honest (default)}{Ephemeral X25519 keys are generated per
#'     session. Protects against passive eavesdropping but not active MITM
#'     by the client. Suitable for trusted DataSHIELD deployments.}
#'   \item{Full MITM-Resistant}{Persistent X25519 keys loaded from
#'     DataSHIELD R options (\code{dsvert.psi_key_pinning = TRUE}).
#'     Servers validate client-provided PKs against pre-configured peers,
#'     detecting and rejecting key substitution attacks. See
#'     \code{\link{psiStoreTransportKeysDS}} for validation details.}
#' }
#'
#' @section Configuration (Full MITM-Resistant mode):
#' Set the following R options per server via the Opal DataSHIELD profile
#' settings or Rock server config:
#' \preformatted{
#' options(
#'   dsvert.psi_key_pinning = TRUE,
#'   dsvert.psi_sk = "<base64 X25519 secret key>",
#'   dsvert.psi_pk = "<base64 X25519 public key>",
#'   dsvert.psi_peers = '["<pk_peer1>","<pk_peer2>"]'
#' )
#' }
#' All options follow the dsBase two-tier fallback pattern:
#' \code{getOption("dsvert.X")} then \code{getOption("default.dsvert.X")}.
#'
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with transport_pk (base64url) and pinned (logical indicating
#'   whether pre-shared keys are in use).
#' @export
psiInitDS <- function(session_id = NULL) {
  ss <- .S(session_id)

  # Generate fresh ephemeral keypair for this session
  transport <- .callMpcTool("transport-keygen", list())
  ss$psi_transport_sk <- transport$secret_key
  ss$psi_transport_pk <- transport$public_key

  ss$psi_phase <- "init"
  ss$psi_dm_used <- character(0)

  list(transport_pk = base64_to_base64url(ss$psi_transport_pk))
}

#' Store peer transport public keys (aggregate function)
#'
#' Stores other servers' transport PKs for encrypting PSI messages.
#' Called by the client after collecting PKs from all servers.
#'
#' @section MITM Detection (Full MITM-Resistant mode):
#' When \code{dsvert.psi_key_pinning = TRUE}, this function validates every
#' client-provided PK against the trusted peer set in \code{dsvert.psi_peers}.
#' Validation is by PK value, not by server name — so it works regardless of
#' what aliases the client uses. Any unknown PK triggers an error (possible
#' key substitution / MITM attack).
#'
#' In semi-honest mode (default), the client-provided PKs are used as-is.
#'
#' @param transport_keys Named list. Server name -> transport PK (base64url).
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#' @return TRUE (invisible).
#' @export
psiStoreTransportKeysDS <- function(transport_keys, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_phase)) {
    stop("PSI not initialized. Call psiInitDS first.", call. = FALSE)
  }

  ss$psi_peer_pks <- lapply(transport_keys, .base64url_to_base64)

  invisible(TRUE)
}

# ============================================================================
# Phase 1: Reference server masks its IDs
# ============================================================================

#' Mask identifiers using ECDH (aggregate function)
#'
#' Hashes identifiers to P-256 curve points and multiplies by a random scalar.
#' The scalar and masked points are stored locally and NEVER returned to the
#' client. Points are exported per-target via \code{\link{psiExportMaskedDS}}.
#'
#' @param data_name Character. Name of data frame.
#' @param id_col Character. Name of identifier column.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with n (count only — no points returned).
#' @export
psiMaskIdsDS <- function(data_name, id_col, session_id = NULL) {
  ss <- .S(session_id)
  .psi_firewall_check("mask", "init", session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  ids <- as.character(data[[id_col]])

  # Anti-dictionary-attack: require minimum dataset size
  # A phantom server with a small ID list (< privacyLevel * 10) is suspicious
  privacy_level <- getOption("datashield.privacyLevel", 5)
  min_records <- privacy_level * 10L  # default: 50 records minimum
  if (length(ids) < min_records) {
    stop("Dataset has ", length(ids), " records, minimum ", min_records,
         " required for PSI (anti-dictionary protection)", call. = FALSE)
  }

  result <- .callMpcTool("psi-mask", list(
    ids = as.list(ids),
    scalar = ""
  ))

  # SECURITY: scalar and masked points stored locally, NEVER returned.
  ss$psi_scalar <- result$scalar
  ss$psi_masked_points <- sapply(
    result$masked_points, base64_to_base64url, USE.NAMES = FALSE
  )

  ss$psi_phase <- "masked"

  list(n = length(ids))
}

# ============================================================================
# Phase 2: Reference exports encrypted masked points for a target
# ============================================================================

#' Export encrypted masked points for a target server (aggregate function)
#'
#' Encrypts stored masked points under the specified target server's transport
#' PK. The client receives an opaque blob it cannot decrypt.
#'
#' @param target_name Character. Name of the target server.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with encrypted_blob (base64url).
#' @export
psiExportMaskedDS <- function(target_name, session_id = NULL) {
  ss <- .S(session_id)
  .psi_firewall_check("export", "masked", session_id)

  if (is.null(ss$psi_masked_points)) {
    stop("No masked points to export. Call psiMaskIdsDS first.", call. = FALSE)
  }

  target_pk <- ss$psi_peer_pks[[target_name]]
  if (is.null(target_pk)) {
    stop("No transport PK for target '", target_name, "'. ",
         "Call psiStoreTransportKeysDS first.", call. = FALSE)
  }

  # Pack points into binary format, encrypt under target's PK
  # Points are stored as base64url, convert to standard base64 for Go tool
  points_std <- sapply(ss$psi_masked_points, .base64url_to_base64, USE.NAMES = FALSE)
  packed <- .callMpcTool("psi-pack-points", list(
    points = as.list(points_std)
  ))
  sealed <- .psi_encrypt_b64data(packed$packed, target_pk)

  list(encrypted_blob = base64_to_base64url(sealed))
}

# ============================================================================
# Phase 3: Target processes encrypted ref points AND masks own IDs
# ============================================================================

#' Process reference points on target server (aggregate function)
#'
#' Decrypts the encrypted ref points blob, generates own scalar, double-masks
#' reference points (stored locally for Phase 7 matching), masks own IDs, and
#' returns encrypted own masked points under the ref server's transport PK.
#'
#' @param data_name Character. Name of data frame.
#' @param id_col Character. Name of identifier column.
#' @param from_storage Logical. If \code{TRUE}, read encrypted blob from
#'   server-side blob storage. Default \code{FALSE}.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with encrypted_blob (base64url) and n (count).
#' @export
psiProcessTargetDS <- function(data_name, id_col, from_storage = FALSE,
                               session_id = NULL) {
  ss <- .S(session_id)
  .psi_firewall_check("process_target", "init", session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  # 1. Read encrypted blob from storage and decrypt to binary packed data
  encrypted_blob <- .read_psi_blob("ref_encrypted_blob", session_id)
  packed_b64 <- .psi_decrypt_to_b64data(encrypted_blob, session_id)
  unpacked <- .callMpcTool("psi-unpack-points", list(packed = packed_b64))
  ref_masked_points <- unpacked$points  # already standard base64

  ids <- as.character(data[[id_col]])

  # Anti-dictionary-attack: require minimum dataset size
  privacy_level <- getOption("datashield.privacyLevel", 5)
  min_records <- privacy_level * 10L
  if (length(ids) < min_records) {
    stop("Dataset has ", length(ids), " records, minimum ", min_records,
         " required for PSI (anti-dictionary protection)", call. = FALSE)
  }

  # 2. Mask own IDs (generates new random scalar)
  own_result <- .callMpcTool("psi-mask", list(
    ids = as.list(ids),
    scalar = ""
  ))

  ss$psi_scalar <- own_result$scalar

  # 3. Double-mask ref points with own scalar (points already standard base64)
  ref_dm <- .callMpcTool("psi-double-mask", list(
    points = as.list(ref_masked_points),
    scalar = own_result$scalar
  ))

  # 4. Store double-masked ref points for Phase 7 matching
  ss$psi_ref_dm <- ref_dm$double_masked_points
  ss$psi_ref_indices <- as.integer(0:(length(ref_masked_points) - 1L))

  # 5. Pack and encrypt own masked points under ref server's transport PK
  ref_pk <- ss$psi_peer_pks[["ref"]]
  if (is.null(ref_pk)) {
    stop("No transport PK for ref server. Call psiStoreTransportKeysDS first.",
         call. = FALSE)
  }
  packed_own <- .callMpcTool("psi-pack-points", list(
    points = as.list(own_result$masked_points)
  ))
  sealed <- .psi_encrypt_b64data(packed_own$packed, ref_pk)

  ss$psi_phase <- "target_processed"

  list(
    encrypted_blob = base64_to_base64url(sealed),
    n = length(ids)
  )
}

# ============================================================================
# Phase 5: Reference server double-masks target points (blind relay)
# ============================================================================

#' Double-mask target points using stored scalar (aggregate function)
#'
#' Decrypts the encrypted target points blob, multiplies by the scalar
#' generated in Phase 1, and re-encrypts the result under the target's
#' transport PK. The client never sees raw EC points.
#'
#' PSI Firewall: one-shot per target — each target can only be double-masked
#' once, preventing the OPRF oracle attack.
#'
#' @param target_name Character. Name of the target server whose points
#'   are being double-masked.
#' @param from_storage Logical. If \code{TRUE}, read encrypted blob from
#'   server-side blob storage. Default \code{FALSE}.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with encrypted_blob (base64url).
#' @export
psiDoubleMaskDS <- function(target_name, from_storage = FALSE,
                            session_id = NULL) {
  ss <- .S(session_id)
  .psi_firewall_check("double_mask", "masked", session_id)

  if (is.null(ss$psi_scalar)) {
    stop("PSI scalar not stored. Call psiMaskIdsDS first.", call. = FALSE)
  }

  # Firewall: one-shot per target (prevents OPRF oracle attack)
  if (target_name %in% ss$psi_dm_used) {
    stop("PSI Firewall: double-mask already called for target '",
         target_name, "'. Each target can only be processed once.",
         call. = FALSE)
  }

  # 1. Read encrypted blob from storage and decrypt to binary packed data
  encrypted_blob <- .read_psi_blob("target_encrypted_blob", session_id)
  packed_b64 <- .psi_decrypt_to_b64data(encrypted_blob, session_id)
  unpacked <- .callMpcTool("psi-unpack-points", list(packed = packed_b64))
  points <- unpacked$points  # already standard base64

  # 2. Double-mask with stored scalar
  result <- .callMpcTool("psi-double-mask", list(
    points = as.list(points),
    scalar = ss$psi_scalar
  ))

  # 3. Pack and encrypt result under target's transport PK
  target_pk <- ss$psi_peer_pks[[target_name]]
  if (is.null(target_pk)) {
    stop("No transport PK for target '", target_name, "'.", call. = FALSE)
  }
  packed_dm <- .callMpcTool("psi-pack-points", list(
    points = as.list(result$double_masked_points)
  ))
  sealed <- .psi_encrypt_b64data(packed_dm$packed, target_pk)

  # 4. Record one-shot usage
  ss$psi_dm_used <- c(ss$psi_dm_used, target_name)

  list(encrypted_blob = base64_to_base64url(sealed))
}

# ============================================================================
# Phase 7: Target matches double-masked points and aligns data
# ============================================================================

#' Match and align data using PSI result (assign function)
#'
#' Decrypts the encrypted double-masked own points blob, matches against
#' stored double-masked reference points, and creates an aligned data frame
#' ordered by reference index.
#'
#' @param data_name Character. Name of data frame to align.
#' @param from_storage Logical. If \code{TRUE}, read encrypted blob from
#'   server-side blob storage. Default \code{FALSE}.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Aligned data frame (assigned to server environment).
#' @export
psiMatchAndAlignDS <- function(data_name, from_storage = FALSE,
                               session_id = NULL) {
  ss <- .S(session_id)
  .psi_firewall_check("match", "target_processed", session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (is.null(ss$psi_ref_dm)) {
    stop("PSI ref double-masked points not stored. Call psiProcessTargetDS first.",
         call. = FALSE)
  }

  # 1. Read encrypted blob from storage and decrypt to binary packed data
  encrypted_blob <- .read_psi_blob("dm_encrypted_blob", session_id)
  packed_b64 <- .psi_decrypt_to_b64data(encrypted_blob, session_id)
  unpacked <- .callMpcTool("psi-unpack-points", list(packed = packed_b64))
  own_dm_std <- unpacked$points  # already standard base64

  # 2. Call psi-match: find which own rows match which ref indices
  result <- .callMpcTool("psi-match", list(
    own_doubled = as.list(own_dm_std),
    ref_doubled = as.list(ss$psi_ref_dm),
    ref_indices = as.list(ss$psi_ref_indices)
  ))

  # Store matched ref indices for Phase 8 multi-server intersection
  ss$psi_matched_ref_indices <- as.integer(result$matched_ref_indices)

  # Clean up Phase 3 state (no longer needed)
  ss$psi_ref_dm <- NULL
  ss$psi_ref_indices <- NULL

  if (result$n_matched == 0) {
    stop("PSI: no matching records found", call. = FALSE)
  }

  # Reorder data by matched_own_rows
  aligned_data <- data[as.integer(result$matched_own_rows) + 1L, , drop = FALSE]
  rownames(aligned_data) <- NULL

  ss$psi_phase <- "matched"

  aligned_data
}

# ============================================================================
# Phase 7 for reference server: Self-align (identity)
# ============================================================================

#' Self-align reference server data (assign function)
#'
#' Creates an aligned copy of the data on the reference server. Since
#' the reference defines the index order, this is an identity operation.
#' Stores all row indices as matched for Phase 8.
#'
#' @param data_name Character. Name of data frame.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Copy of data frame (assigned to server environment).
#' @export
psiSelfAlignDS <- function(data_name, session_id = NULL) {
  ss <- .S(session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  # All ref indices are matched (the ref matches itself)
  ss$psi_matched_ref_indices <- as.integer(0:(nrow(data) - 1L))

  # Return copy (same order — ref is the reference)
  data
}

# ============================================================================
# Phase 8 helpers: Multi-server intersection
# ============================================================================

#' Get matched reference indices (aggregate function)
#'
#' Returns the set of reference indices that this server matched during
#' PSI alignment. Used by the client to compute the multi-server intersection.
#'
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Integer vector of matched reference indices (0-based).
#' @export
psiGetMatchedIndicesDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available. Run alignment first.", call. = FALSE)
  }
  ss$psi_matched_ref_indices
}

#' Filter aligned data to common intersection (assign function)
#'
#' Keeps only the rows corresponding to reference indices that are present
#' on ALL servers. This is the final step of the PSI alignment protocol.
#'
#' @param data_name Character. Name of aligned data frame.
#' @param common_indices Integer vector. Reference indices common to all
#'   servers (0-based). Ignored when \code{from_storage = TRUE}.
#' @param from_storage Logical. If \code{TRUE}, read \code{common_indices}
#'   from server-side blob storage (comma-separated integers).
#'   Default \code{FALSE}.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Filtered data frame (assigned to server environment).
#' @export
psiFilterCommonDS <- function(data_name, common_indices = NULL,
                              from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available.", call. = FALSE)
  }

  # Read from blob storage or inline argument
  if (from_storage) {
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L || is.null(blobs[["common_indices"]])) {
      stop("No common_indices blob stored", call. = FALSE)
    }
    common_indices <- as.integer(strsplit(blobs[["common_indices"]], ",", fixed = TRUE)[[1]])
    .blob_nuke(ss)
  } else {
    common_indices <- as.integer(common_indices)
  }
  n_common <- length(common_indices)
  n_original <- nrow(data)

  # Disclosure control: nfilter.subset (dsBase pattern)
  settings <- .dsvert_disclosure_settings()
  if (n_common > 0 && n_common < settings$nfilter.subset) {
    stop(
      "Disclosure control: PSI intersection too small (",
      n_common, " records). Minimum allowed: nfilter.subset = ",
      settings$nfilter.subset, ".",
      call. = FALSE
    )
  }

  # Differencing check
  n_excluded <- n_original - n_common
  if (n_excluded > 0 && n_excluded < settings$nfilter.subset) {
    stop(
      "Disclosure control: PSI exclusion set too small (",
      n_excluded, " excluded records). An attacker could identify excluded ",
      "individuals by differencing. Minimum exclusion: nfilter.subset = ",
      settings$nfilter.subset, ".",
      call. = FALSE
    )
  }

  keep <- ss$psi_matched_ref_indices %in% common_indices
  filtered_data <- data[keep, , drop = FALSE]
  rownames(filtered_data) <- NULL

  # Clean up all PSI state
  ss$psi_scalar <- NULL
  ss$psi_matched_ref_indices <- NULL
  ss$psi_masked_points <- NULL
  ss$psi_transport_sk <- NULL
  ss$psi_transport_pk <- NULL
  ss$psi_peer_pks <- NULL
  ss$psi_trusted_pks <- NULL
  ss$psi_phase <- NULL
  ss$psi_dm_used <- NULL

  filtered_data
}
