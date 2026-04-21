#' @title Debug-only server reveal of session share slot (task #116 G)
#' @description Returns the FP share stored at \code{slot_key} in the
#'   current session. Used by ds.vertCox diagnostic hook to enable
#'   client-side aggregation + plaintext comparison of Path B intermediate
#'   quantities (μ, S, 1/S, G, μG, residual). NOT intended for production
#'   analysis flows — revealing a session share is a disclosure-trust
#'   decision and only appropriate in diagnostic sessions where the
#'   analyst is the protocol designer.
#'
#'   \strong{SERVER-SIDE GATE (task #113 P3 audit)}: the function is
#'   listed in \code{AggregateMethods}, so any authorized DS analyst
#'   can call it via \code{datashield.aggregate}. By itself a single
#'   share is info-theoretically random, but combining both servers'
#'   shares reconstructs per-observation plaintext. To prevent this in
#'   production deployments, this function refuses to execute unless
#'   the env var \code{DSVERT_DEBUG_REVEAL_ALLOW=1} is set on the
#'   server R session. Default (unset) → the call stops with a clear
#'   error; production deployments therefore remain 0-bit per-obs.
#'
#' @param slot_key Character. Name of the session slot to fetch.
#' @param session_id Character. MPC session id.
#' @return list(share_fp = base64 FP vector, slot_key, length).
#' @keywords internal
#' @export
dsvertDebugRevealDS <- function(slot_key = NULL, session_id = NULL) {
  .require_debug_reveal_allow()
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (is.null(slot_key) || !nzchar(slot_key)) {
    stop("slot_key required", call. = FALSE)
  }
  ss <- .S(session_id)
  share <- ss[[slot_key]]
  if (is.null(share)) {
    stop("slot '", slot_key, "' not in session", call. = FALSE)
  }
  list(share_fp = share, slot_key = slot_key)
}

# Server-side gate for the debug reveal / snapshot functions. Requires
# the server operator to explicitly opt-in via env var. This closes the
# P3 hole identified in task #113 P3 audit: without the gate, any
# authorized DS analyst client could call dsvertDebugRevealDS on both
# servers and client-side reconstruct per-observation plaintext, even
# if the ds.vertCox client-side diagnostic hook is disabled.
.require_debug_reveal_allow <- function() {
  if (!nzchar(Sys.getenv("DSVERT_DEBUG_REVEAL_ALLOW", ""))) {
    stop("dsvertDebug*DS is disabled in production. ",
         "Set env var DSVERT_DEBUG_REVEAL_ALLOW=1 on the SERVER R ",
         "session to enable diagnostic share reveal. See task #113 ",
         "P3 audit / docs/acceptance/p3_audit.md.",
         call. = FALSE)
  }
}

#' @title Snapshot a session slot to another key (task #116 G diagnostic)
#' @param slot_key,snapshot_key,session_id Character.
#' @return list(copied = TRUE).
#' @keywords internal
#' @export
dsvertDebugSnapshotDS <- function(slot_key = NULL, snapshot_key = NULL,
                                    session_id = NULL) {
  .require_debug_reveal_allow()
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  v <- ss[[slot_key]]
  if (is.null(v)) return(list(copied = FALSE))
  ss[[snapshot_key]] <- v
  list(copied = TRUE)
}
