#' @title Debug-only server reveal of session share slot (task #116 G)
#' @description Returns the FP share stored at \code{slot_key} in the
#'   current session. Used by ds.vertCox diagnostic hook to enable
#'   client-side aggregation + plaintext comparison of Path B intermediate
#'   quantities (μ, S, 1/S, G, μG, residual). NOT intended for production
#'   analysis flows — revealing a session share is a disclosure-trust
#'   decision and only appropriate in diagnostic sessions where the
#'   analyst is the protocol designer.
#'
#' @param slot_key Character. Name of the session slot to fetch.
#' @param session_id Character. MPC session id.
#' @return list(share_fp = base64 FP vector, slot_key, length).
#' @keywords internal
#' @export
dsvertDebugRevealDS <- function(slot_key = NULL, session_id = NULL) {
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

#' @title Snapshot a session slot to another key (task #116 G diagnostic)
#' @param slot_key,snapshot_key,session_id Character.
#' @return list(copied = TRUE).
#' @keywords internal
#' @export
dsvertDebugSnapshotDS <- function(slot_key = NULL, snapshot_key = NULL,
                                    session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  v <- ss[[slot_key]]
  if (is.null(v)) return(list(copied = FALSE))
  ss[[snapshot_key]] <- v
  list(copied = TRUE)
}
