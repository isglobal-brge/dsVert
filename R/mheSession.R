#' @title MHE Session Management
#' @description Session-scoped persistent storage, context reuse, and lifecycle
#'   management for the Multiparty Homomorphic Encryption protocol.
#' @name mhe-session
NULL

# ---------------------------------------------------------------------------
# Session-Scoped Persistent Storage
# ---------------------------------------------------------------------------
# DataSHIELD aggregate/assign calls run in ephemeral environments, so local
# variables are lost between calls. We use a package-level environment to
# persist state across the multi-step MHE, PSI, and GLM protocols.
#
# SESSION ISOLATION: Each job (identified by session_id) gets its own
# sub-environment within .mhe_sessions. This prevents concurrent jobs from
# interfering with each other (critical for DSLite testing and parallel
# Opal jobs). All server functions receive session_id and access their
# session via .S(session_id).
#
# Stored per-session keys during MHE protocol:
#   $secret_key     - This server's RLWE secret key share (NEVER returned)
#   $party_id       - Integer party index (0-based)
#   $cpk            - Collective Public Key (standard base64)
#   $galois_keys    - Galois rotation keys (standard base64 vector)
#   $relin_key      - Relinearization key (standard base64)
#   $log_n, $log_scale - CKKS parameters
#   $transport_sk, $transport_pk - X25519 keypair
#
# Stored per-session during GLM protocol:
#   $enc_y          - Encrypted response ciphertext (non-label servers)
#   $remote_enc_cols - List of received encrypted columns (correlation)
#   $std_data       - Standardized data frame
#   $std_data_name  - Name key for .resolveData() lookup
#   $glm_eta_label, $glm_eta_other - Eta vectors for deviance
#
# Stored per-session during PSI protocol:
#   $psi_scalar     - P-256 secret scalar (NEVER returned)
#   $psi_ref_dm     - Double-masked reference points
#   $psi_ref_indices - Reference row indices
#   $psi_matched_ref_indices - Matched indices for Phase 8 intersection
#
# Protocol Firewall state (per-session):
#   $op_counter     - Monotonic operation counter
#   $ct_registry    - Named list: ct_hash -> list(op_id, op_type, timestamp)
#
# GLM FSM state (per-session, replaces .glm_fsm):
#   $fsm_session_id - Session ID for FSM validation
#   $fsm_state      - Current FSM state
#   $fsm_iteration  - Current iteration
#   $fsm_n_nonlabel - Expected non-label count
#   $fsm_etas_received - Character vector of received etas
#   $fsm_blocks_completed - Block completion counter
# ---------------------------------------------------------------------------

# Container for all sessions. Each session_id -> sub-environment.
.mhe_sessions <- new.env(parent = emptyenv())

# Legacy fallback for backward compatibility (non-session-scoped callers).
# New code should always use .S(session_id).
.mhe_storage <- new.env(parent = emptyenv())

# Session TTL: 24 hours (very long to avoid premature cleanup)
.SESSION_TTL_SECONDS <- 86400L

# ---------------------------------------------------------------------------
# MHE Context Cache: maps context_id -> session_id for key reuse
# ---------------------------------------------------------------------------
# When the peer set and CKKS parameters haven't changed between analyses,
# the expensive key generation + combination steps can be skipped by reusing
# cryptographic keys from a previous session. The context_id is a canonical
# string encoding the peer set, parameters, and RLK flag. Fresh transport
# keys are always generated (forward secrecy per job).
# ---------------------------------------------------------------------------
.mhe_context_cache <- new.env(parent = emptyenv())

#' Get or create a session-scoped storage environment
#'
#' Returns the sub-environment for the given session_id. Creates it if it
#' does not exist. Falls back to the legacy .mhe_storage if session_id is
#' NULL or empty (backward compatibility).
#'
#' Opportunistically reaps expired sessions on creation of new ones.
#'
#' @param session_id Character or NULL. Session identifier.
#' @return An environment for storing session state.
#' @keywords internal
.S <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    return(.mhe_storage)
  }
  s <- .mhe_sessions[[session_id]]
  if (is.null(s)) {
    s <- new.env(parent = emptyenv())
    s$.created_at <- Sys.time()
    s$.session_id <- session_id
    .mhe_sessions[[session_id]] <- s
    # Opportunistic reap of expired sessions
    .reap_expired_sessions()
  }
  s
}

#' Remove a session and all its state
#'
#' @param session_id Character. Session to clean up.
#' @return TRUE (invisible)
#' @keywords internal
.cleanup_session <- function(session_id) {
  if (!is.null(session_id) && nzchar(session_id)) {
    s <- .mhe_sessions[[session_id]]
    if (!is.null(s)) {
      tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
      rm(list = ls(s), envir = s)
    }
    rm(list = session_id, envir = .mhe_sessions)
  }
  gc(verbose = FALSE)
  invisible(TRUE)
}

#' Reap sessions older than TTL
#'
#' Called opportunistically when new sessions are created. Removes
#' sessions whose .created_at timestamp is older than .SESSION_TTL_SECONDS.
#'
#' @keywords internal
.reap_expired_sessions <- function() {
  now <- Sys.time()
  for (sid in ls(.mhe_sessions)) {
    s <- .mhe_sessions[[sid]]
    if (!is.null(s) && !is.null(s$.created_at)) {
      age <- as.numeric(difftime(now, s$.created_at, units = "secs"))
      if (age > .SESSION_TTL_SECONDS) {
        .cleanup_session(sid)
      }
    }
  }
}

# ---------------------------------------------------------------------------
# MHE Context Reuse Functions
# ---------------------------------------------------------------------------
# Skip expensive key generation + combination when the same peer set and
# CKKS parameters are used across consecutive analyses. The context_id is
# a canonical string encoding sorted peer names, log_n, log_scale, num_obs,
# and generate_rlk. Fresh X25519 transport keys are always generated to
# maintain forward secrecy per job.
# ---------------------------------------------------------------------------

#' Check for reusable MHE context and copy keys to a new session
#'
#' Looks up the context cache for a previous session with the same
#' cryptographic configuration (peer set, CKKS parameters, RLK flag).
#' If found and the old session's keys are still valid, copies them
#' to the new session. Fresh transport keys are always generated.
#'
#' @param context_id Character. Canonical string identifying the MHE
#'   configuration (computed by the client from sorted peer names and params).
#' @param session_id Character. New session ID to copy keys into.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{reusable}: Logical. TRUE if keys were successfully reused.
#'     \item \code{party_id}: Integer. This server's party ID (only if reusable).
#'     \item \code{transport_pk}: Character. Fresh X25519 public key (only if reusable).
#'   }
#' @export
mheReuseContextDS <- function(context_id, session_id) {
  old_sid <- .mhe_context_cache[[context_id]]

  if (is.null(old_sid)) {
    return(list(reusable = FALSE))
  }

  # Check that the old session still exists and has keys
  old_ss <- .mhe_sessions[[old_sid]]
  if (is.null(old_ss) || !.key_exists("secret_key", old_ss) || !.key_exists("cpk", old_ss)) {
    # Old session expired or incomplete - remove stale cache entry
    if (exists(context_id, envir = .mhe_context_cache)) {
      rm(list = context_id, envir = .mhe_context_cache)
    }
    return(list(reusable = FALSE))
  }

  # Create new session and copy MHE keys
  ss <- .S(session_id)
  .key_put("secret_key", .key_get("secret_key", old_ss), ss)
  ss$party_id    <- old_ss$party_id
  .key_put("cpk", .key_get("cpk", old_ss), ss)
  old_gk <- .key_get("galois_keys", old_ss)
  if (!is.null(old_gk)) .key_put("galois_keys", old_gk, ss)
  old_rk <- .key_get("relin_key", old_ss)
  if (!is.null(old_rk)) .key_put("relin_key", old_rk, ss)
  ss$log_n       <- old_ss$log_n
  ss$log_scale   <- old_ss$log_scale

  # Generate FRESH transport keys (forward secrecy for each job)
  transport <- .callMheTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)

  # Update cache to point to the new session
  .mhe_context_cache[[context_id]] <- session_id

  list(
    reusable     = TRUE,
    party_id     = ss$party_id,
    transport_pk = base64_to_base64url(transport$public_key)
  )
}

#' Register the current session's MHE context for future reuse
#'
#' Called after a successful \code{mheCombineDS} to register the context
#' in the cache. Subsequent analyses with the same peer set and parameters
#' can skip key generation by calling \code{mheReuseContextDS}.
#'
#' @param context_id Character. Canonical string identifying the MHE
#'   configuration.
#' @param session_id Character. Session ID that completed key combination.
#'
#' @return TRUE (invisible)
#' @export
mheRegisterContextDS <- function(context_id, session_id) {
  ss <- .S(session_id)
  if (!.key_exists("cpk", ss)) {
    stop("Cannot register context: MHE keys not yet combined", call. = FALSE)
  }
  .mhe_context_cache[[context_id]] <- session_id
  invisible(TRUE)
}

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
.register_ciphertext <- function(ct_b64, op_type, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$op_counter)) {
    ss$op_counter <- 0L
  }
  if (is.null(ss$ct_registry)) {
    ss$ct_registry <- list()
  }

  ss$op_counter <- ss$op_counter + 1L

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  ss$ct_registry[[ct_hash]] <- list(
    op_id = ss$op_counter,
    op_type = op_type,
    timestamp = Sys.time()
  )

  ct_hash
}

#' Validate and consume a ciphertext authorization (one-time use)
#' @param ct_b64 Character. The ciphertext in standard base64 encoding
#' @return TRUE if authorized (entry is consumed), stops with error otherwise
#' @keywords internal
.validate_and_consume_ciphertext <- function(ct_b64, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$ct_registry)) {
    stop("Protocol Firewall: no ciphertexts registered. ",
         "Decryption denied.", call. = FALSE)
  }

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  entry <- ss$ct_registry[[ct_hash]]
  if (is.null(entry)) {
    stop("Protocol Firewall: ciphertext not authorized for decryption. ",
         "Only ciphertexts produced by legitimate operations ",
         "(cross-product, glm-gradient) can be decrypted.", call. = FALSE)
  }

  # One-time use: consume the authorization (anti-replay)
  ss$ct_registry[[ct_hash]] <- NULL

  TRUE
}

#' Get number of observations for a variable
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to check
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. Unused (stateless function) but accepted for API
#'   consistency.
#'
#' @return Integer. Number of complete observations
#' @export
mheGetObsDS <- function(data_name, variables, session_id = NULL) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  sum(complete.cases(X))
}

#' Force garbage collection on the server
#'
#' Lightweight function that triggers R garbage collection without removing
#' any session state. Used periodically during long-running protocol loops
#' to prevent memory accumulation from intermediate CKKS objects.
#'
#' @return TRUE
#' @export
mheGcDS <- function() {
  gc(verbose = FALSE)
  TRUE
}

#' Clean up MHE cryptographic state
#'
#' Removes all cryptographic material from server memory: secret key, CPK,
#' Galois keys, ciphertext registry, and any residual protocol state.
#' Called by the client at the end of each protocol execution to minimize
#' the window during which keys exist in memory.
#'
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When not NULL, cleans up only the specified session.
#'   When NULL, falls back to clearing the legacy global storage.
#'
#' @return TRUE on success
#' @export
mheCleanupDS <- function(session_id = NULL) {
  if (!is.null(session_id)) {
    .cleanup_session(session_id)
  } else {
    # Legacy fallback: clear global storage
    rm(list = ls(.mhe_storage), envir = .mhe_storage)
  }
  # Force garbage collection to release memory holding key material
  gc(verbose = FALSE)
  TRUE
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
