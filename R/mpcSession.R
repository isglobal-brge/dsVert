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
# Used as the FALLBACK storage when the DSLite/Opal eval envir cannot
# be located (defensive). The default storage is host-env-attached
# (see .session_storage()) so that:
#
#   * Real Opal (Rserve, one R process per DSI login): the dsBase
#     eval env for the login is the persistent host across all
#     aggregate calls; `.dsvert_sessions` attaches there, lifetime
#     matches the login.
#
#   * DSLite (multi "server" in one R process): each DSLite server has
#     its own `private$.session(sid)` eval env that DSLite uses as the
#     `envir =` argument for every aggregate/assign call to that
#     server. Distinct envs across DSLite servers => distinct
#     `.dsvert_sessions` attached envs => no cross-server state
#     collision under a shared session_id (the previous package-level
#     keying collapsed all "servers" into a single keyspace and broke
#     multi-step protocols like ds.psiAlign in DSLite).
.mpc_sessions <- new.env(parent = emptyenv())

# Session TTL: 24 hours
.SESSION_TTL_SECONDS <- 86400L

#' Resolve the per-server session-storage env
#'
#' Walks the call stack outwards looking for the OUTERMOST frame that
#' is an environment (the DSI/DSLite/Rserve eval-envir frame for the
#' current aggregate or assign call). Attaches a `.dsvert_sessions`
#' env there on first contact and returns it on subsequent calls.
#'
#' Falls back to the package-level `.mpc_sessions` when the host env
#' is locked or otherwise non-writable (defensive).
#' @keywords internal
.session_storage <- function() {
  ## Locate the DSI eval-envir frame for the current aggregate /
  ## assign call. The DS function (k2ShareInputDS, psiInitDS, ...)
  ## is invoked by the DSI driver via
  ## eval(call("ds_func", ...), envir = host_env). Inside the DS
  ## function body, parent.frame() returns host_env. The DS function
  ## then calls .S(session_id), which calls .session_storage(): from
  ## here, parent.frame(2L) returns host_env (one frame for .S, one
  ## frame for the DS function body). For real Opal/Rserve, host_env
  ## is the per-DSI-session dsBase eval env (persistent for the
  ## login). For DSLite, host_env is per-DSLite-server `private$.session(sid)`
  ## (distinct across servers, persistent across calls within one
  ## server) -- which is the ONLY way to isolate session state in a
  ## single R process serving multiple DSLite "servers" with a shared
  ## client-generated session_id (the previous package-level keying
  ## collapsed all servers into one keyspace).
  ##
  ## Defensive fallback to the package-level `.mpc_sessions` env when
  ## host_env cannot be located, is locked, or assignment fails.
  ##
  ## Frame-walk depth: this helper is called from `.S(session_id)`,
  ## which is itself called from the DS function body. So the call
  ## chain is .session_storage <- .S <- DS_func <- DSI_eval. We need
  ## parent.frame(3L) to reach DSI_eval (the DSLite/Opal eval-envir).
  ## Strategy: walk parent.frame() upwards looking for an already-
  ## tagged persistent frame. If found, return its storage env. If
  ## not (first call from this DSI eval-envir), tag ALL writable
  ## parent.frame()s with a SHARED storage env -- after the current
  ## DS call returns, transient call frames are GC'd but the
  ## persistent DSI eval-envir frame retains the .dsvert_sessions
  ## binding pointing to the shared storage env. The next DS call
  ## finds the binding via the walk-and-lookup phase and uses the
  ## same storage. This auto-discovery handles depth variations
  ## across different ds.* orchestrators (some use .dsAgg wrappers,
  ## some call DSI directly, etc.).
  ## Lookup phase: walk parent.frame() upwards looking for an already-
  ## tagged frame.
  for (i in 2L:20L) {
    pf <- tryCatch(parent.frame(i), error = function(e) NULL)
    if (!is.environment(pf)) next
    if (exists(".dsvert_sessions", envir = pf, inherits = FALSE))
      return(get(".dsvert_sessions", envir = pf, inherits = FALSE))
  }
  ## First contact -- locate the DSI eval-envir frame and tag ONLY
  ## that one. The DSLite eval-envir frame is identifiable by its
  ## `name` attribute set to `"DSLiteEnv_<sid>"` (DSLiteServer$newSession
  ## tags every per-server session env this way). For real Opal /
  ## Rserve, no such attribute exists -- the per-DSI-session eval env
  ## is the global env of the Rserve worker; we tag it directly.
  storage <- new.env(parent = emptyenv())
  tagged_at <- NULL
  for (i in 2L:20L) {
    pf <- tryCatch(parent.frame(i), error = function(e) NULL)
    if (!is.environment(pf)) next
    nm <- attr(pf, "name", exact = TRUE)
    is_dslite <- !is.null(nm) && nzchar(nm) && grepl("^DSLiteEnv_", nm)
    if (is_dslite && !environmentIsLocked(pf)) {
      tryCatch({
        assign(".dsvert_sessions", storage, envir = pf)
        tagged_at <- pf
        break  # tag ONLY the DSLite per-server session env
      }, error = function(e) NULL)
    }
  }
  if (!is.null(tagged_at)) return(storage)
  ## Real Opal / Rserve: no DSLiteEnv_ marker. Fall back to the
  ## package-level `.mpc_sessions` (each DSI session has its own
  ## Rserve worker process, so the package-level env is naturally
  ## per-session and the original semantics apply).
  .mpc_sessions
}

#' Get or create a session-scoped storage environment
#'
#' Returns the sub-environment for the given session_id. Creates it if
#' it does not exist. Requires a valid session_id.
#'
#' Storage anchor: the DSI eval-envir (host frame). DSLite collision
#' avoidance: distinct DSLite servers in one R process use distinct
#' eval envs, so a single client-generated session_id resolves to
#' distinct `[[session_id]]` slots across servers. Real Opal: the
#' dsBase eval env persists for the whole login, so cross-call
#' persistence within a login is unchanged.
#'
#' @param session_id Character. Session identifier (UUID).
#' @return An environment for storing session state.
#' @keywords internal
.S <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id is required for all protocol operations", call. = FALSE)
  }
  storage <- .session_storage()
  ## DSLite per-server disk-path discriminator: when running under
  ## DSLite (multiple "servers" sharing one R process + one tempdir),
  ## several servers share the same client-supplied UUID session_id.
  ## .ensure_session_dir() builds the on-disk blob path from
  ## ss$.session_id, so without disambiguation BOTH servers would
  ## write/read the same file. We snapshot the host DSLiteEnv_<sid>
  ## marker at storage creation and append it to the session_dir
  ## path to keep per-server disk blobs isolated.
  host_marker <- ""
  for (i in 2L:20L) {
    pf <- tryCatch(parent.frame(i), error = function(e) NULL)
    if (!is.environment(pf)) next
    nm <- attr(pf, "name", exact = TRUE)
    if (!is.null(nm) && nzchar(nm) && grepl("^DSLiteEnv_", nm)) {
      host_marker <- paste0("__", nm)
      break
    }
  }
  s <- storage[[session_id]]
  if (is.null(s)) {
    s <- new.env(parent = emptyenv())
    s$.created_at <- Sys.time()
    s$.session_id <- paste0(session_id, host_marker)
    storage[[session_id]] <- s
    .reap_expired_sessions(storage)
  }
  s
}

#' Remove a session and all its state
#' @param session_id Character. Session to clean up.
#' @return TRUE (invisible)
#' @keywords internal
.cleanup_session <- function(session_id) {
  if (!is.null(session_id) && nzchar(session_id)) {
    storage <- .session_storage()
    s <- storage[[session_id]]
    if (!is.null(s)) {
      tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
      rm(list = ls(s), envir = s)
    }
    if (exists(session_id, envir = storage))
      rm(list = session_id, envir = storage)
  }
  gc(verbose = FALSE)
  invisible(TRUE)
}

#' Reap sessions older than TTL
#' @param storage Optional session-storage env override; defaults to
#'   the package-level session env when NULL.
#' @keywords internal
.reap_expired_sessions <- function(storage = NULL) {
  if (is.null(storage)) storage <- .session_storage()
  now <- Sys.time()
  for (sid in ls(storage)) {
    s <- storage[[sid]]
    if (!is.null(s) && !is.null(s$.created_at)) {
      age <- as.numeric(difftime(now, s$.created_at, units = "secs"))
      if (age > .SESSION_TTL_SECONDS) {
        tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
        if (exists(sid, envir = storage)) rm(list = sid, envir = storage)
      }
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
