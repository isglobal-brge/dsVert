#' @title Session Management
#' @description Session-scoped persistent storage and lifecycle management
#'   for Ring63 MPC, PSI, and vertCor protocols.
#' @name session-management
NULL

# ---------------------------------------------------------------------------
# Session-Scoped Persistent Storage
# ---------------------------------------------------------------------------
# DataSHIELD aggregate/assign calls run in ephemeral environments, so local
# variables are lost between calls. We use a package-level environment to
# persist state across the multi-step GLM, PSI, and vertCor protocols.
#
# Each job gets its own sub-environment within .sessions, keyed by session_id.
# This prevents concurrent jobs from interfering with each other.
# All server functions receive session_id and access their session via
# .S(session_id).
#
# Stored per-session:
#   $transport_sk, $transport_pk - X25519 keypair (NEVER returned)
#   $peer_transport_pks          - Peer public keys
#   $k2_x_share_fp, $k2_y_share_fp - Ring63 FP data shares
#   $secure_mu_share             - Link function output (Ring63 FP)
#   $k2_dcf_keys_persistent      - DCF comparison keys
#   $psi_scalar                  - P-256 secret scalar (NEVER returned)
# ---------------------------------------------------------------------------

# Container for all sessions. Each session_id -> sub-environment.
.mpc_sessions <- new.env(parent = emptyenv())

# Session TTL: 24 hours
.SESSION_TTL_SECONDS <- 86400L

#' Get or create a session-scoped storage environment
#'
#' Returns the sub-environment for the given session_id. Creates it if
#' it does not exist. Requires a valid session_id.
#'
#' @param session_id Character. Session identifier (UUID).
#' @return An environment for storing session state.
#' @keywords internal
.S <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id is required for all protocol operations", call. = FALSE)
  }
  s <- .mpc_sessions[[session_id]]
  if (is.null(s)) {
    s <- new.env(parent = emptyenv())
    s$.created_at <- Sys.time()
    s$.session_id <- session_id
    .mpc_sessions[[session_id]] <- s
    .reap_expired_sessions()
  }
  s
}

#' Remove a session and all its state
#' @param session_id Character. Session to clean up.
#' @return TRUE (invisible)
#' @keywords internal
.cleanup_session <- function(session_id) {
  if (!is.null(session_id) && nzchar(session_id)) {
    s <- .mpc_sessions[[session_id]]
    if (!is.null(s)) {
      tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
      rm(list = ls(s), envir = s)
    }
    if (exists(session_id, envir = .mpc_sessions))
      rm(list = session_id, envir = .mpc_sessions)
  }
  gc(verbose = FALSE)
  invisible(TRUE)
}

#' Reap sessions older than TTL
#' @keywords internal
.reap_expired_sessions <- function() {
  now <- Sys.time()
  for (sid in ls(.mpc_sessions)) {
    s <- .mpc_sessions[[sid]]
    if (!is.null(s) && !is.null(s$.created_at)) {
      age <- as.numeric(difftime(now, s$.created_at, units = "secs"))
      if (age > .SESSION_TTL_SECONDS) .cleanup_session(sid)
    }
  }
}

#' Force garbage collection on the server
#'
#' Triggers R garbage collection without removing session state.
#' Used periodically during long-running protocol loops.
#'
#' @return TRUE
#' @export
mpcGcDS <- function() {
  gc(verbose = FALSE)
  TRUE
}

#' Clean up session state
#'
#' Removes all cryptographic material from server memory: transport keys,
#' Ring63 shares, DCF keys, and any residual protocol state.
#' Called by the client at the end of each protocol execution.
#'
#' @param session_id Character. Session identifier to clean up.
#' @return TRUE on success
#' @export
mpcCleanupDS <- function(session_id = NULL) {
  if (!is.null(session_id) && nzchar(session_id)) {
    .cleanup_session(session_id)
  }
  gc(verbose = FALSE)
  TRUE
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
