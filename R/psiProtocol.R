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
#'   \item The client sees only opaque encrypted blobs
#'   \item Each server's scalar never leaves the server
#'   \item The PSI firewall enforces phase ordering and one-shot semantics
#'   \item When server policy provides a per-study PSI pseudonym key, identifiers
#'     are first mapped through a study-separated keyed PRF before ECDH masking
#'   \item The client receives no identifiers, pseudonyms, EC points or row maps
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

.psi_option <- function(name, default = NULL) {
  value <- getOption(name)
  if (is.null(value)) value <- getOption(paste0("default.", name))
  if (is.null(value)) default else value
}

.psi_scalar_option <- function(name, default = NULL) {
  value <- .psi_option(name, default)
  if (is.null(value) || length(value) == 0L) return("")
  as.character(value[[1L]])
}

.psi_bool_option <- function(name, default = FALSE) {
  isTRUE(as.logical(.psi_option(name, default)))
}

.psi_int_option <- function(name, default) {
  value <- suppressWarnings(as.integer(.psi_option(name, default)[[1L]]))
  if (length(value) != 1L || is.na(value)) as.integer(default) else value
}

.psi_num_option <- function(name, default) {
  value <- suppressWarnings(as.numeric(.psi_option(name, default)[[1L]]))
  if (length(value) != 1L || is.na(value)) as.numeric(default) else value
}

.psi_policy <- function(session_id) {
  key <- .psi_scalar_option("dsvert.psi.pseudonym_key", "")
  mode <- .psi_scalar_option("dsvert.psi.pseudonym_mode", "auto")
  if (!nzchar(mode) || identical(mode, "auto")) {
    mode <- if (nzchar(key)) "shared_key" else "none"
  }
  mode <- match.arg(mode, c("none", "shared_key", "threshold"))
  if (identical(mode, "threshold")) {
    stop(
      "PSI threshold-OPRF key custody is not implemented in this build. ",
      "Use dsvert.psi.pseudonym_mode='shared_key' with pinned peers, or ",
      "disable the threshold policy for this profile.",
      call. = FALSE
    )
  }
  if (.psi_bool_option("dsvert.psi.require_keyed_pseudonyms", FALSE) &&
      identical(mode, "none")) {
    stop("PSI keyed pseudonymisation is required by server policy.", call. = FALSE)
  }
  if (identical(mode, "shared_key") && !nzchar(key)) {
    stop("PSI pseudonym_mode='shared_key' requires dsvert.psi.pseudonym_key.",
         call. = FALSE)
  }

  study_id <- .psi_scalar_option("dsvert.psi.study_id", "")
  if (!nzchar(study_id)) study_id <- session_id
  key_custody <- .psi_scalar_option("dsvert.psi.key_custody", "")
  if (!nzchar(key_custody)) {
    key_custody <- if (identical(mode, "shared_key")) "shared_key" else "none"
  }
  if (!identical(mode, "shared_key")) {
    key_custody <- "none"
  }

  key_id <- if (identical(mode, "shared_key")) {
    digest::hmac(key, paste0("dsVert-PSI-key-id-v1|", study_id),
                 algo = "sha256")
  } else {
    ""
  }
  list(
    pseudonym_mode = mode,
    pseudonym_key = key,
    key_custody = key_custody,
    study_id = study_id,
    study_id_hash = digest::digest(study_id, algo = "sha256"),
    key_id = key_id,
    max_input_ids = .psi_int_option("dsvert.psi.max_input_ids", 1000000L),
    rate_limit_n = .psi_int_option("dsvert.psi.rate_limit_n", 1000L),
    rate_limit_window_sec = .psi_num_option("dsvert.psi.rate_limit_window_sec", 60)
  )
}

.psi_public_policy <- function(policy) {
  list(
    pseudonym_mode = policy$pseudonym_mode,
    key_custody = policy$key_custody,
    study_id_hash = policy$study_id_hash,
    key_id = policy$key_id,
    max_input_ids = policy$max_input_ids,
    rate_limit_n = policy$rate_limit_n,
    rate_limit_window_sec = policy$rate_limit_window_sec
  )
}

.psi_audit_event <- function(session_id, operation, status,
                             n_input = NA_integer_, n_valid = NA_integer_,
                             detail = "") {
  ss <- .S(session_id)
  policy <- ss$psi_policy %||% .psi_policy(session_id)
  event <- list(
    ts = format(Sys.time(), "%Y-%m-%dT%H:%M:%OS3Z", tz = "UTC"),
    session_hash = digest::digest(session_id, algo = "sha256"),
    operation = operation,
    status = status,
    n_input = as.integer(n_input),
    n_valid = as.integer(n_valid),
    skipped = as.integer(max(0L, n_input - n_valid)),
    pseudonym_mode = policy$pseudonym_mode,
    key_custody = policy$key_custody,
    study_id_hash = policy$study_id_hash,
    detail = detail
  )
  ss$psi_audit <- c(ss$psi_audit %||% list(), list(event))
  path <- .psi_scalar_option("dsvert.psi.audit_log_path", "")
  if (nzchar(path)) {
    dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
    cat(jsonlite::toJSON(event, auto_unbox = TRUE), "\n",
        file = path, append = TRUE)
  }
  invisible(event)
}

.psi_rate_limit_check <- function(session_id, operation) {
  policy <- .S(session_id)$psi_policy %||% .psi_policy(session_id)
  limit <- policy$rate_limit_n
  window <- policy$rate_limit_window_sec
  if (!is.finite(limit) || limit <= 0L || !is.finite(window) || window <= 0) {
    return(invisible(TRUE))
  }
  storage <- .session_storage()
  key <- paste0("psi:", operation)
  now <- Sys.time()
  log <- storage$.psi_rate_log %||% list()
  times <- log[[key]]
  if (is.null(times)) times <- as.POSIXct(character(0), origin = "1970-01-01")
  keep <- as.numeric(difftime(now, times, units = "secs")) <= window
  times <- times[keep]
  if (length(times) >= limit) {
    .psi_audit_event(session_id, operation, "blocked_rate_limit",
                     detail = paste0("limit=", limit, "/", window, "s"))
    stop("PSI rate limit exceeded for operation '", operation,
         "' (limit ", limit, " per ", window, " seconds).", call. = FALSE)
  }
  log[[key]] <- c(times, now)
  storage$.psi_rate_log <- log
  invisible(TRUE)
}

.psi_valid_id_rows <- function(ids) {
  which(!is.na(ids) & nzchar(ids))
}

.psi_guard_input_set <- function(session_id, operation, n_input, n_valid) {
  policy <- .S(session_id)$psi_policy %||% .psi_policy(session_id)
  .psi_rate_limit_check(session_id, operation)
  max_ids <- policy$max_input_ids
  if (is.finite(max_ids) && max_ids > 0L && n_input > max_ids) {
    .psi_audit_event(session_id, operation, "blocked_max_input",
                     n_input = n_input, n_valid = n_valid,
                     detail = paste0("max_input_ids=", max_ids))
    stop("PSI input set has ", n_input, " records, exceeding ",
         "dsvert.psi.max_input_ids = ", max_ids, ".", call. = FALSE)
  }

  privacy_level <- getOption("datashield.privacyLevel", 5)
  min_records <- as.integer(privacy_level) * 10L
  if (n_valid < min_records) {
    .psi_audit_event(session_id, operation, "blocked_min_input",
                     n_input = n_input, n_valid = n_valid,
                     detail = paste0("min_records=", min_records))
    stop("Dataset has ", n_valid, " valid identifiers, minimum ", min_records,
         " required for PSI (anti-dictionary protection)", call. = FALSE)
  }
  .psi_audit_event(session_id, operation, "accepted",
                   n_input = n_input, n_valid = n_valid)
  invisible(TRUE)
}

.psi_guard_intersection_count <- function(n, what = "PSI intersection") {
  settings <- .dsvert_disclosure_settings()
  if (n <= 0L) {
    stop(what, " is empty.", call. = FALSE)
  }
  if (n < settings$nfilter.subset) {
    stop(
      "Disclosure control: ", what, " too small (", n,
      " records). Minimum allowed: nfilter.subset = ",
      settings$nfilter.subset, ".",
      call. = FALSE
    )
  }
  invisible(TRUE)
}

.psi_mask_payload <- function(ids, scalar = "", session_id = NULL) {
  policy <- .S(session_id)$psi_policy %||% .psi_policy(session_id)
  list(
    ids = as.list(ids),
    scalar = scalar,
    pseudonym_mode = policy$pseudonym_mode,
    pseudonym_key = policy$pseudonym_key,
    study_id = policy$study_id
  )
}

# ============================================================================
# PSI Transport Encryption Helpers
# ============================================================================

#' Encrypt already-base64-encoded binary data under a recipient's transport PK (internal)
#'
#' Takes data that is already base64-encoded (e.g. from psi-pack-points output)
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
#' Decrypts a sealed blob and returns the raw base64-encoded payload
#' (for binary packed data).
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

.psi_text_to_b64 <- function(text) {
  if (!is.character(text) || length(text) != 1L) {
    stop("PSI payload must be a single character string", call. = FALSE)
  }
  jsonlite::base64_enc(charToRaw(text))
}

.psi_b64_to_text <- function(data_b64) {
  rawToChar(jsonlite::base64_dec(data_b64))
}

.psi_encrypt_text <- function(text, recipient_pk_b64) {
  sealed <- .psi_encrypt_b64data(.psi_text_to_b64(text), recipient_pk_b64)
  base64_to_base64url(sealed)
}

.psi_decrypt_text <- function(sealed_b64url, session_id = NULL) {
  .psi_b64_to_text(.psi_decrypt_to_b64data(sealed_b64url, session_id))
}

.psi_pack_indices <- function(indices) {
  indices <- as.integer(indices)
  if (!length(indices)) return("")
  paste(indices, collapse = ",")
}

.psi_unpack_indices <- function(payload) {
  if (is.null(payload) || !nzchar(payload)) return(integer(0))
  as.integer(strsplit(payload, ",", fixed = TRUE)[[1L]])
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
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation.
#'
#' @return List with transport_pk (base64url).
#' @export
psiInitDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  ss$psi_policy <- .psi_policy(session_id)

  # Generate fresh ephemeral keypair for this session
  transport <- .callMpcTool("transport-keygen", list())
  ss$psi_transport_sk <- transport$secret_key
  ss$psi_transport_pk <- transport$public_key

  # Ed25519 identity: derive keypair, sign transport PK
  identity <- .get_identity_keypair()
  ss$psi_identity_pk <- identity$identity_pk
  signature <- .sign_transport_pk(transport$public_key, identity$identity_sk)

  ss$psi_phase <- "init"
  ss$psi_dm_used <- character(0)

  list(
    transport_pk = base64_to_base64url(ss$psi_transport_pk),
    identity_pk  = base64_to_base64url(identity$identity_pk),
    signature    = base64_to_base64url(signature),
    psi_policy   = .psi_public_policy(ss$psi_policy)
  )
}

#' Store peer transport public keys (aggregate function)
#'
#' Stores other servers' transport PKs for encrypting PSI messages.
#' Called by the client after collecting PKs from all servers.
#'
#' @param transport_keys Named list. Server name -> transport PK (base64url).
#' @param session_id Character or NULL. UUID for session-scoped storage.
#' @param transport_keys_b64 Character (base64url). JSON-encoded peer transport public keys.
#' @param identity_info Named list. Per-server identity public keys and signatures (NULL to skip).
#' @param identity_info_b64 Character (base64url). JSON-encoded identity info / Ed25519 signatures.
#' @return TRUE (invisible).
#' @export
psiStoreTransportKeysDS <- function(transport_keys = NULL,
                                     transport_keys_b64 = NULL,
                                     identity_info = NULL,
                                     identity_info_b64 = NULL,
                                     session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_phase)) {
    stop("PSI not initialized. Call psiInitDS first.", call. = FALSE)
  }

  # Accept list args as base64url-encoded JSON (avoids Opal parser issues)
  .from_b64url <- function(x) {
    x <- gsub("-","+",gsub("_","/",x,fixed=TRUE),fixed=TRUE)
    pad <- nchar(x)%%4; if(pad==2) x<-paste0(x,"=="); if(pad==3) x<-paste0(x,"="); x
  }
  if (is.null(transport_keys) && !is.null(transport_keys_b64) && nzchar(transport_keys_b64))
    transport_keys <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(.from_b64url(transport_keys_b64))), simplifyVector = FALSE)
  if (is.null(identity_info) && !is.null(identity_info_b64) && nzchar(identity_info_b64))
    identity_info <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(.from_b64url(identity_info_b64))), simplifyVector = FALSE)

  if (!is.null(identity_info)) {
    .verify_all_peer_identities(identity_info, transport_keys,
                                 ss$psi_identity_pk)
  } else {
    require_tp <- getOption("dsvert.require_trusted_peers")
    if (is.null(require_tp)) require_tp <- getOption("default.dsvert.require_trusted_peers")
    if (is.null(require_tp)) require_tp <- TRUE
    if (isTRUE(as.logical(require_tp)))
      stop("Trusted peers required but no identity_info provided by client.",
           call. = FALSE)
  }

  ss$psi_peer_pks <- lapply(transport_keys, .base64url_to_base64)
  invisible(TRUE)
}

# ============================================================================
# Phase 1: Reference server masks its IDs
# ============================================================================

#' Mask identifiers using ECDH (aggregate function)
#'
#' Applies the server PSI pseudonymisation policy, hashes identifiers to P-256
#' curve points and multiplies by a random scalar. The scalar and masked points
#' are stored locally and NEVER returned to the client. Points are exported
#' per-target via \code{\link{psiExportMaskedDS}}.
#'
#' @param data_name Character. Name of data frame.
#' @param id_col Character. Name of identifier column.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return List with n (count only -- no points returned).
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
  valid_rows <- .psi_valid_id_rows(ids)
  ids <- ids[valid_rows]
  .psi_guard_input_set(session_id, "mask", nrow(data), length(ids))

  result <- .callMpcTool("psi-mask", .psi_mask_payload(
    ids = ids,
    scalar = "",
    session_id = session_id
  ))

  # SECURITY: scalar and masked points stored locally, NEVER returned.
  ss$psi_scalar <- result$scalar
  ss$psi_masked_points <- sapply(
    result$masked_points, base64_to_base64url, USE.NAMES = FALSE
  )
  ss$psi_valid_rows <- as.integer(valid_rows)

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
  valid_rows <- .psi_valid_id_rows(ids)
  ids <- ids[valid_rows]
  .psi_guard_input_set(session_id, "process_target", nrow(data), length(ids))

  # 2. Mask own IDs (generates new random scalar)
  own_result <- .callMpcTool("psi-mask", .psi_mask_payload(
    ids = ids,
    scalar = "",
    session_id = session_id
  ))

  ss$psi_scalar <- own_result$scalar
  ss$psi_valid_rows <- as.integer(valid_rows)

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
#' transport PK. The client never sees raw EC points or row maps.
#'
#' PSI Firewall: one-shot per target -- each target can only be double-masked
#' once, preventing repeated online use of this phase as an identifier-testing
#' oracle by the analyst.
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

  # Firewall: one-shot per target (prevents repeated online oracle use)
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
  .psi_guard_intersection_count(as.integer(result$n_matched),
                                "PSI pairwise match")

  # Store matched ref indices for Phase 8 multi-server intersection
  ss$psi_matched_ref_indices <- as.integer(result$matched_ref_indices)

  # Clean up Phase 3 state (no longer needed)
  ss$psi_ref_dm <- NULL
  ss$psi_ref_indices <- NULL

  # Reorder data by matched valid-ID rows
  valid_rows <- ss$psi_valid_rows %||% seq_len(nrow(data))
  matched_rows <- valid_rows[as.integer(result$matched_own_rows) + 1L]
  aligned_data <- data[matched_rows, , drop = FALSE]
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

  valid_rows <- ss$psi_valid_rows %||% seq_len(nrow(data))
  valid_rows <- as.integer(valid_rows)

  # All valid ref IDs are matched against the reference itself.
  ss$psi_matched_ref_indices <- as.integer(0:(length(valid_rows) - 1L))

  # Return copy in valid-ID reference order.
  aligned_data <- data[valid_rows, , drop = FALSE]
  rownames(aligned_data) <- NULL
  aligned_data
}

# ============================================================================
# Phase 8 helpers: Multi-server intersection
# ============================================================================

#' Get matched reference indices (aggregate function)
#'
#' Returns the set of reference indices that this server matched during
#' PSI alignment. This legacy diagnostic helper is disabled by default because
#' the index vector is patient-level metadata; production alignment uses
#' encrypted index export plus server-side intersection.
#'
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Integer vector of matched reference indices (0-based).
#' @export
psiGetMatchedIndicesDS <- function(session_id = NULL) {
  allow_reveal <- getOption("dsvert.psi.allow_matched_indices_reveal", FALSE)
  if (!isTRUE(as.logical(allow_reveal))) {
    stop(
      "Disclosure control: psiGetMatchedIndicesDS is disabled by default ",
      "because matched row indices are patient-level metadata. Use encrypted ",
      "PSI phase-8 helpers instead.",
      call. = FALSE
    )
  }
  ss <- .S(session_id)
  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available. Run alignment first.", call. = FALSE)
  }
  ss$psi_matched_ref_indices
}

#' Export encrypted matched reference indices for server-side intersection
#'
#' Encrypts this server's matched reference-index vector under the recipient
#' server transport public key. The client relays only an opaque blob and sees
#' no row indices.
#'
#' @param recipient_name Character. Recipient server name, usually the PSI
#'   reference server.
#' @param session_id Character or NULL. UUID for session-scoped storage.
#'
#' @return List with encrypted_blob and n_matched.
#' @export
psiExportMatchedIndicesDS <- function(recipient_name = "ref",
                                      session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available. Run alignment first.",
         call. = FALSE)
  }
  recipient_pk <- ss$psi_peer_pks[[recipient_name]]
  if (is.null(recipient_pk)) {
    stop("No transport PK for recipient '", recipient_name, "'.",
         call. = FALSE)
  }

  .psi_guard_intersection_count(length(ss$psi_matched_ref_indices),
                                "PSI pairwise match")
  payload <- .psi_pack_indices(ss$psi_matched_ref_indices)
  list(
    encrypted_blob = .psi_encrypt_text(payload, recipient_pk),
    n_matched = length(ss$psi_matched_ref_indices)
  )
}

#' Compute the multi-server PSI intersection on the reference server
#'
#' Reads encrypted matched-index blobs from server-side storage, decrypts them
#' on the reference server, intersects them with the reference index set, and
#' stores the common index set server-side. Only counts are returned.
#'
#' @param target_names Character vector. Names of target servers whose encrypted
#'   index blobs were stored on the reference server.
#' @param session_id Character or NULL. UUID for session-scoped storage.
#'
#' @return List with n_common and n_targets.
#' @export
psiComputeCommonIndicesDS <- function(target_names, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available on reference server.",
         call. = FALSE)
  }
  if (!is.character(target_names)) {
    target_names <- as.character(target_names)
  }

  common_indices <- as.integer(ss$psi_matched_ref_indices)
  for (target_name in target_names) {
    key <- paste0("matched_indices_", target_name)
    encrypted_blob <- .read_psi_blob(key, session_id)
    payload <- .psi_decrypt_text(encrypted_blob, session_id)
    target_indices <- .psi_unpack_indices(payload)
    common_indices <- intersect(common_indices, target_indices)
  }
  common_indices <- sort(as.integer(common_indices))
  .psi_guard_intersection_count(length(common_indices),
                                "PSI common intersection")
  ss$psi_common_indices <- common_indices

  list(n_common = length(common_indices), n_targets = length(target_names))
}

#' Export encrypted common PSI indices from the reference server
#'
#' Encrypts the server-side common index set under a target server transport
#' public key so the target can filter without exposing indices to the client.
#'
#' @param target_name Character. Target server name.
#' @param session_id Character or NULL. UUID for session-scoped storage.
#'
#' @return List with encrypted_blob and n_common.
#' @export
psiExportCommonIndicesDS <- function(target_name, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$psi_common_indices)) {
    stop("PSI common indices not available. Run psiComputeCommonIndicesDS.",
         call. = FALSE)
  }
  .psi_guard_intersection_count(length(ss$psi_common_indices),
                                "PSI common intersection")
  target_pk <- ss$psi_peer_pks[[target_name]]
  if (is.null(target_pk)) {
    stop("No transport PK for target '", target_name, "'.", call. = FALSE)
  }

  payload <- .psi_pack_indices(ss$psi_common_indices)
  list(
    encrypted_blob = .psi_encrypt_text(payload, target_pk),
    n_common = length(ss$psi_common_indices)
  )
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
#'   from server-side blob storage.
#' @param encrypted Logical. If \code{TRUE}, the stored common-index blob is
#'   transport-encrypted for this server.
#'   Default \code{FALSE}.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage (not recommended for concurrent jobs).
#'
#' @return Filtered data frame (assigned to server environment).
#' @export
psiFilterCommonDS <- function(data_name, common_indices = NULL,
                              from_storage = FALSE, encrypted = FALSE,
                              session_id = NULL) {
  ss <- .S(session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (is.null(ss$psi_matched_ref_indices)) {
    stop("PSI matched indices not available.", call. = FALSE)
  }

  # Read from blob storage or inline argument
  if (from_storage) {
    blobs <- .blob_snapshot(ss)
    key <- if (isTRUE(encrypted)) "common_indices_encrypted" else "common_indices"
    if (length(blobs) == 0L || is.null(blobs[[key]])) {
      stop("No ", key, " blob stored", call. = FALSE)
    }
    payload <- blobs[[key]]
    if (isTRUE(encrypted)) {
      payload <- .psi_decrypt_text(payload, session_id)
    }
    common_indices <- .psi_unpack_indices(payload)
    .blob_nuke(ss)
  } else if (is.null(common_indices) && !is.null(ss$psi_common_indices)) {
    common_indices <- ss$psi_common_indices
  } else {
    common_indices <- as.integer(common_indices)
  }
  n_common <- length(common_indices)
  n_original <- nrow(data)

  # Disclosure control: nfilter.subset (dsBase pattern)
  settings <- .dsvert_disclosure_settings()
  if (n_common < settings$nfilter.subset) {
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
  ss$psi_common_indices <- NULL
  ss$psi_phase <- NULL
  ss$psi_dm_used <- NULL
  ss$psi_valid_rows <- NULL
  ss$psi_policy <- NULL

  filtered_data
}
