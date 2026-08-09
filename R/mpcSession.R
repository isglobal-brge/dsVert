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

# Process-wide transport capacity. This is a byte/backpressure guard across
# sessions, never a request counter and never an identity/query penalty list.
# Real Opal deployments normally isolate DSI logins in separate R workers; the
# same mechanism still bounds all sessions that actually share one process
# (including DSLite and multi-session Rserve configurations).
.dsvert_resource_registry <- new.env(parent = emptyenv())
.dsvert_resource_registry$sessions <- list()
.dsvert_resource_registry$external <- list()
.dsvert_resource_registry$next_owner <- 0

.dsvert_global_spool_max_bytes <- function() {
  value <- getOption(
    "dsvert.transport.global_spool_max_bytes", 8 * 1024^3)
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < 1024^2 || value > 256 * 1024^3) {
    stop("Invalid global transport spool policy.", call. = FALSE)
  }
  value
}

.dsvert_resource_register <- function(ss) {
  if (!is.environment(ss)) {
    stop("Invalid transport resource owner.", call. = FALSE)
  }
  owner <- ss$.dsvert_resource_owner
  if (!is.character(owner) || length(owner) != 1L || is.na(owner) ||
      !nzchar(owner)) {
    next_owner <- suppressWarnings(as.numeric(
      .dsvert_resource_registry$next_owner))
    if (length(next_owner) != 1L || is.na(next_owner) ||
        !is.finite(next_owner) || next_owner < 0 || next_owner >= 2^53) {
      stop("Transport resource registry is invalid.", call. = FALSE)
    }
    next_owner <- next_owner + 1
    .dsvert_resource_registry$next_owner <- next_owner
    owner <- paste0(
      "resource-", format(next_owner, scientific = FALSE, trim = TRUE))
    ss$.dsvert_resource_owner <- owner
  }
  sessions <- .dsvert_resource_registry$sessions
  sessions[[owner]] <- ss
  .dsvert_resource_registry$sessions <- sessions
  invisible(owner)
}

.dsvert_resource_unregister <- function(ss) {
  if (!is.environment(ss)) return(invisible(FALSE))
  owner <- ss$.dsvert_resource_owner
  if (is.character(owner) && length(owner) == 1L && !is.na(owner) &&
      nzchar(owner)) {
    sessions <- .dsvert_resource_registry$sessions
    sessions[[owner]] <- NULL
    .dsvert_resource_registry$sessions <- sessions
  }
  ss$.dsvert_resource_owner <- NULL
  invisible(TRUE)
}

# Durable transport stores such as the biomedical capsule-source SQLite spool
# are not session environments.  Register their authenticated byte head under
# a path-derived opaque owner so they participate in the same process-wide
# capacity decision without retaining a ledger key or a query/identity label.
.dsvert_resource_external_owner <- function(kind, path) {
  if (!is.character(kind) || length(kind) != 1L || is.na(kind) ||
      !grepl("^[a-z][a-z0-9_-]{0,63}$", kind) ||
      !is.character(path) || length(path) != 1L || is.na(path) ||
      !nzchar(path)) {
    stop("Invalid durable transport resource owner.", call. = FALSE)
  }
  expanded <- path.expand(path)
  # Resolve the existing parent, not the target. The owner must remain stable
  # across the exact moment a SQLite/spool file is first created (notably on
  # systems where /var and /private/var are aliases).
  parent <- tryCatch(
    normalizePath(dirname(expanded), winslash = "/", mustWork = TRUE),
    error = function(e) NULL)
  if (is.null(parent)) {
    stop("Durable transport resource parent does not exist.", call. = FALSE)
  }
  normalized <- file.path(parent, basename(expanded))
  paste0("external-", digest::digest(
    paste(kind, normalized, sep = "|"), algo = "sha256",
    serialize = FALSE))
}

.dsvert_resource_external_reconcile <- function(owner, retained_bytes,
                                                 kind = "durable-transport") {
  if (!is.character(owner) || length(owner) != 1L || is.na(owner) ||
      !grepl("^external-[0-9a-f]{64}$", owner) ||
      !is.character(kind) || length(kind) != 1L || is.na(kind) ||
      !grepl("^[a-z][a-z0-9_-]{0,63}$", kind)) {
    stop("Invalid durable transport resource owner.", call. = FALSE)
  }
  retained <- suppressWarnings(as.numeric(retained_bytes))
  if (length(retained) != 1L || is.na(retained) || !is.finite(retained) ||
      retained < 0 || retained != floor(retained) || retained > 2^53) {
    stop("Invalid durable transport byte head.", call. = FALSE)
  }
  external <- .dsvert_resource_registry$external
  external[[owner]] <- list(bytes = retained, kind = kind)
  .dsvert_resource_registry$external <- external
  invisible(owner)
}

.dsvert_resource_external_unregister <- function(owner) {
  if (!is.character(owner) || length(owner) != 1L || is.na(owner) ||
      !grepl("^external-[0-9a-f]{64}$", owner)) {
    return(invisible(FALSE))
  }
  external <- .dsvert_resource_registry$external
  external[[owner]] <- NULL
  .dsvert_resource_registry$external <- external
  invisible(TRUE)
}

.dsvert_resource_session_bytes <- function(ss) {
  relay <- 0
  if (is.environment(ss$.dsvert_dsi_relay)) {
    relay <- suppressWarnings(as.numeric(
      ss$.dsvert_dsi_relay$retained_bytes))
  }
  cache <- ss$.typed_blob_retained_head
  authentic_cache <- !is.null(cache) && exists(
    ".dsvert_typed_blob_accounting_authentic", mode = "function",
    inherits = TRUE) && isTRUE(tryCatch(
      .dsvert_typed_blob_accounting_authentic(ss, cache),
      error = function(e) FALSE))
  typed <- if (isTRUE(authentic_cache)) {
    as.numeric(cache$total)
  } else if (exists(
    ".dsvert_typed_blob_retained_bytes", mode = "function",
    inherits = TRUE)) {
    tryCatch(as.numeric(.dsvert_typed_blob_retained_bytes(ss)),
             error = function(e) Inf)
  } else {
    active_typed <- length(ss$.typed_blob_transfers %||% list()) > 0L ||
      length(ss$.typed_blob_outbound %||% list()) > 0L ||
      length(ss$.typed_blob_destinations %||% list()) > 0L
    if (isTRUE(active_typed)) Inf else 0
  }
  legacy <- if (exists(
      ".dsvert_legacy_blob_memory_retained_bytes", mode = "function",
      inherits = TRUE)) {
    tryCatch(
      as.numeric(.dsvert_legacy_blob_memory_retained_bytes(ss)),
      error = function(e) Inf)
  } else {
    active_legacy <- length(ss$blobs %||% list()) > 0L ||
      length(ss$blob_chunks %||% list()) > 0L ||
      length(ss$blob_chunk_receipts %||% list()) > 0L
    if (isTRUE(active_legacy)) Inf else 0
  }
  exact <- 0
  if (is.environment(ss$.exact_gc_ops)) {
    for (operation_id in ls(ss$.exact_gc_ops, all.names = TRUE)) {
      state <- ss$.exact_gc_ops[[operation_id]]
      if (!is.environment(state) || is.null(state$spool) ||
          !dir.exists(state$spool) || identical(state$status, "aborted")) {
        next
      }
      reservation <- suppressWarnings(as.numeric(
        state$resource_reservation_bytes))
      if (length(reservation) != 1L || is.na(reservation) ||
          !is.finite(reservation) || reservation < 0 ||
          reservation > 2^53) {
        return(Inf)
      }
      exact <- exact + reservation
    }
  }
  alignment_mask <- 0
  if (is.environment(ss$.dp_alignment_mask_batches)) {
    for (batch_id in ls(ss$.dp_alignment_mask_batches, all.names = TRUE)) {
      batch <- ss$.dp_alignment_mask_batches[[batch_id]]
      if (!is.environment(batch) ||
          identical(batch$status, "alignment_contract_invalid")) {
        next
      }
      reservation <- suppressWarnings(as.numeric(
        batch$resource_reservation_bytes))
      if (length(reservation) != 1L || is.na(reservation) ||
          !is.finite(reservation) || reservation < 0 ||
          reservation > 2^53) {
        return(Inf)
      }
      alignment_mask <- alignment_mask + reservation
    }
  }
  values <- c(relay, typed, legacy, exact, alignment_mask)
  if (anyNA(values) || any(!is.finite(values)) || any(values < 0)) return(Inf)
  sum(values)
}

.dsvert_resource_retained_bytes <- function() {
  sessions <- .dsvert_resource_registry$sessions
  values <- if (length(sessions)) {
    vapply(sessions, .dsvert_resource_session_bytes, numeric(1L))
  } else {
    numeric()
  }
  external <- .dsvert_resource_registry$external
  if (length(external)) {
    external_values <- vapply(external, function(record) {
      if (!is.list(record) || !identical(sort(names(record)),
                                         c("bytes", "kind")) ||
          !is.numeric(record$bytes) || length(record$bytes) != 1L ||
          is.na(record$bytes) || !is.finite(record$bytes) ||
          record$bytes < 0 || record$bytes != floor(record$bytes) ||
          !is.character(record$kind) || length(record$kind) != 1L ||
          is.na(record$kind) ||
          !grepl("^[a-z][a-z0-9_-]{0,63}$", record$kind)) {
        return(Inf)
      }
      as.numeric(record$bytes)
    }, numeric(1L))
    values <- c(values, external_values)
  }
  if (!length(values)) return(0)
  total <- sum(values)
  if (!is.finite(total) || total < 0 || total > 2^53) return(Inf)
  total
}

.dsvert_resource_admit_external <- function(owner, retained_bytes,
                                             additional_bytes, kind) {
  .dsvert_resource_external_reconcile(owner, retained_bytes, kind)
  additional <- suppressWarnings(as.numeric(additional_bytes))
  if (length(additional) != 1L || is.na(additional) ||
      !is.finite(additional) || additional < 0 ||
      additional != floor(additional) || additional > 2^53) {
    stop("Invalid durable transport resource reservation.", call. = FALSE)
  }
  capacity <- .dsvert_global_spool_max_bytes()
  if (additional > capacity) {
    .dsvert_resource_oversize(
      additional, capacity, "process-wide durable transport reservation")
  }
  retained <- .dsvert_resource_retained_bytes()
  if (!is.finite(retained) || retained > capacity - additional) {
    .dsvert_resource_backpressure(
      retained, additional, capacity, "process-wide durable transport")
  }
  invisible(list(
    admitted = TRUE, code = "ok", retryable = FALSE,
    retained_bytes = retained, requested_bytes = additional,
    capacity_bytes = capacity))
}

.dsvert_resource_backpressure <- function(
    retained, additional, capacity, scope = "global transport") {
  condition <- structure(list(
    message = paste0(
      "[dsvert_resource_backpressure:v1] resource_backpressure: ", scope,
      " capacity is currently full; retry after acknowledged or consumed bytes are reclaimed."),
    call = NULL, code = "resource_backpressure", retryable = TRUE,
    scope = scope,
    retained_bytes = retained, requested_bytes = additional,
    capacity_bytes = capacity),
    class = c("dsvert_resource_backpressure", "error", "condition"))
  stop(condition)
}

.dsvert_resource_oversize <- function(
    requested, capacity, scope = "transport resource") {
  requested <- suppressWarnings(as.numeric(requested))
  capacity <- suppressWarnings(as.numeric(capacity))
  if (length(requested) != 1L || is.na(requested) ||
      !is.finite(requested) || requested < 0 || requested > 2^53 ||
      length(capacity) != 1L || is.na(capacity) || !is.finite(capacity) ||
      capacity < 0 || capacity > 2^53 ||
      !is.character(scope) || length(scope) != 1L || is.na(scope) ||
      !nzchar(scope)) {
    stop("Invalid transport oversize condition.", call. = FALSE)
  }
  condition <- structure(list(
    message = paste0(
      "[dsvert_resource_oversize:v1] resource_oversize: ", scope,
      " cannot fit within its fixed byte/resource policy."),
    call = NULL, code = "resource_oversize", retryable = FALSE,
    scope = scope, requested_bytes = requested, capacity_bytes = capacity),
    class = c("dsvert_resource_oversize", "error", "condition"))
  stop(condition)
}

.dsvert_resource_admit <- function(ss, additional_bytes) {
  .dsvert_resource_register(ss)
  additional <- suppressWarnings(as.numeric(additional_bytes))
  if (length(additional) != 1L || is.na(additional) ||
      !is.finite(additional) || additional < 0 ||
      additional != floor(additional) || additional > 2^53) {
    stop("Invalid transport resource reservation.", call. = FALSE)
  }
  retained <- .dsvert_resource_retained_bytes()
  capacity <- .dsvert_global_spool_max_bytes()
  if (additional > capacity) {
    .dsvert_resource_oversize(
      additional, capacity, "process-wide transport reservation")
  }
  if (!is.finite(retained) || retained > capacity - additional) {
    .dsvert_resource_backpressure(
      retained, additional, capacity, "process-wide transport")
  }
  invisible(list(
    admitted = TRUE, code = "ok", retryable = FALSE,
    retained_bytes = retained, requested_bytes = additional,
    capacity_bytes = capacity))
}

# Session inactivity lease: 24 hours.  Total session age is deliberately not a
# limit: long operations remain valid while a protocol records durable
# progress.  Retries and read-only status polls must not call
# .session_progress().
.SESSION_TTL_SECONDS <- 86400L

#' @keywords internal
.session_now <- function() as.numeric(Sys.time())

#' Record durable progress for a session
#'
#' This is intentionally separate from `.S()`: merely resolving a session,
#' polling it, or retrying an already committed frame must not extend its
#' lifetime.  Protocol implementations call this helper only after committing
#' new state, bytes, or an acknowledgement.
#'
#' @param ss Session environment.
#' @param now Numeric Unix time or a POSIX date-time.
#' @return The monotonic session activity timestamp, invisibly.
#' @keywords internal
.session_progress <- function(ss, now = .session_now()) {
  if (!is.environment(ss)) {
    stop("Invalid session progress target.", call. = FALSE)
  }
  timestamp <- suppressWarnings(as.numeric(now))
  if (length(timestamp) != 1L || is.na(timestamp) || !is.finite(timestamp) ||
      timestamp < 0) {
    stop("Invalid session progress timestamp.", call. = FALSE)
  }
  previous <- suppressWarnings(as.numeric(ss$.last_activity))
  if (length(previous) == 1L && !is.na(previous) && is.finite(previous)) {
    timestamp <- max(previous, timestamp)
  }
  ss$.last_activity <- timestamp
  invisible(timestamp)
}

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
  ## assign call. The DS function (k2ShareInputDS, psiPaddedInitDS, ...)
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

#' Validate a session identifier
#'
#' @param session_id Character. Session identifier (UUID).
#' @return \code{TRUE} invisibly, or an error for an unsafe identifier.
#' @keywords internal
.validate_session_id <- function(session_id) {
  if (is.null(session_id)) {
    stop("session_id is required for all protocol operations", call. = FALSE)
  }
  if (!is.character(session_id) || length(session_id) != 1L) {
    stop("session_id must be a single character string", call. = FALSE)
  }
  if (is.na(session_id) || !nzchar(session_id)) {
    stop("session_id is required for all protocol operations", call. = FALSE)
  }
  if (nchar(session_id, type = "bytes") > 128L ||
      session_id %in% c(".", "..") ||
      !grepl("^[A-Za-z0-9._-]+$", session_id)) {
    stop(
      "Invalid session_id: use 1-128 letters, digits, dots, underscores or hyphens",
      call. = FALSE
    )
  }
  invisible(TRUE)
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
  .dsvert_enforce_release_mode()
  .validate_session_id(session_id)
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
      # The host marker is environment metadata, not a safe path component.
      # Hash it before including it in the per-server disk namespace.
      host_marker <- paste0(
        "__dslite_",
        substr(digest::digest(nm, algo = "sha256", serialize = FALSE), 1L, 16L)
      )
      break
    }
  }
  s <- storage[[session_id]]
  if (is.null(s)) {
    s <- new.env(parent = emptyenv())
    s$.created_at <- .session_now()
    s$.last_activity <- s$.created_at
    s$.session_id <- paste0(session_id, host_marker)
    storage[[session_id]] <- s
    .reap_expired_sessions(storage)
  }
  .dsvert_resource_register(s)
  s
}

#' Remove a session and all its state
#' @param session_id Character. Session to clean up.
#' @return TRUE (invisible)
#' @keywords internal
.cleanup_session <- function(session_id) {
  if (!is.null(session_id)) {
    .validate_session_id(session_id)
    storage <- .session_storage()
    s <- storage[[session_id]]
    if (!is.null(s)) {
      tryCatch(.psi_padded_state_delete(s$.psi_padded_state),
               error = function(e) NULL)
      tryCatch(.exact_gc_abort_all(s), error = function(e) NULL)
      tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
      .dsvert_resource_unregister(s)
      rm(list = ls(s), envir = s)
    }
    if (exists(session_id, envir = storage))
      rm(list = session_id, envir = storage)
  }
  gc(verbose = FALSE)
  invisible(TRUE)
}

#' Reap sessions idle beyond the inactivity lease
#' @param storage Optional session-storage env override; defaults to
#'   the package-level session env when NULL.
#' @keywords internal
.reap_expired_sessions <- function(storage = NULL) {
  if (is.null(storage)) storage <- .session_storage()
  now <- .session_now()
  for (sid in ls(storage)) {
    s <- storage[[sid]]
    if (!is.null(s) && !is.null(s$.created_at)) {
      activity <- suppressWarnings(as.numeric(s$.last_activity))
      if (length(activity) != 1L || is.na(activity) || !is.finite(activity)) {
        activity <- suppressWarnings(as.numeric(s$.created_at))
      }
      expired <- length(activity) != 1L || is.na(activity) ||
        !is.finite(activity) || now - activity > .SESSION_TTL_SECONDS
      if (isTRUE(expired)) {
        tryCatch(.psi_padded_state_delete(s$.psi_padded_state),
                 error = function(e) NULL)
        tryCatch(.exact_gc_abort_all(s), error = function(e) NULL)
        tryCatch(.session_dir_cleanup(s), error = function(e) NULL)
        .dsvert_resource_unregister(s)
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
mpcGcDS <- function() {
  .dsvert_enforce_release_mode()
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
mpcCleanupDS <- function(session_id = NULL) {
  .dsvert_enforce_release_mode()
  if (!is.null(session_id) && nzchar(session_id)) {
    .cleanup_session(session_id)
  }
  gc(verbose = FALSE)
  TRUE
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
