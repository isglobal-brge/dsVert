#' @title Beaver K x L contingency counts across DCF parties
#' @description Computes the joint contingency counts
#'   \eqn{n_{kl} = \sum_i X_{ik} Y_{il}} where \eqn{X} is the one-hot
#'   encoding of \code{var1} on this server (held by the caller) and
#'   \eqn{Y} is the one-hot encoding of \code{var2} on the peer server
#'   (retrieved from the peer's session via a transport-encrypted blob
#'   relay). Both matrices are FP-encoded in the session store under
#'   \code{k2_onehot_<var>_fp} (see \code{dsvertOneHotDS}). Returns the
#'   K*L cells as a single aggregate vector; the analyst client never
#'   sees any \eqn{n}-length indicator vector.
#'
#'   Delegates the bilinear form to the Go binary via
#'   \code{k2-beaver-matrix-bilinear} which generates a single
#'   \eqn{K \times L} Beaver triple batch and returns the reconstructed
#'   counts as non-negative integers rounded from the Ring63 result.
#'
#' @param var1 character -- the variable held on this server.
#' @param var2 character -- the variable on the peer.
#' @param peer_name character -- server name of the peer (used for
#'   session blob key disambiguation).
#' @param peer_pk base64 X25519 pk of the peer.
#' @param session_id MPC session.
#' @return list(counts = integer K*L vector row-major,
#'              K, L, row_levels, col_levels).
#' @export
k2CrossOneHotCountsDS <- function(var1, var2,
                                   peer_name = NULL,
                                   peer_pk = NULL,
                                   session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  X_key <- paste0("k2_onehot_", var1, "_fp")
  if (is.null(ss[[X_key]])) {
    stop("one-hot matrix for var1='", var1,
         "' not in session (call dsvertOneHotDS first)", call. = FALSE)
  }
  K <- ss[[paste0("k2_onehot_", var1, "_K")]]
  n <- ss[[paste0("k2_onehot_", var1, "_n")]]
  row_levels <- ss[[paste0("k2_onehot_", var1, "_levels")]]
  peer_blob_key <- paste0("k2_peer_onehot_", var2)
  blob <- .blob_consume(peer_blob_key, ss)
  if (is.null(blob)) {
    stop("peer one-hot blob not relayed for var2='", var2,
         "'; client must relay dsvertOneHotDS output from peer server",
         call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport secret key missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  Y_fp <- payload$Y_fp
  L <- payload$L
  col_levels <- payload$levels
  res <- .callMpcTool("k2-beaver-matrix-bilinear", list(
    x_fp = ss[[X_key]], y_fp = Y_fp,
    n = as.integer(n), k = as.integer(K), l = as.integer(L),
    frac_bits = 20L))
  counts <- as.integer(round(res$counts))

  # Server-authoritative disclosure control — the cross-server joint counts are
  # released to the calling (data-owning) server, which knows its own var1 per
  # record. Without suppression a singleton/small var1 category lets it read a
  # peer's per-observation var2 value off the surviving row. Suppress cells and
  # margins below max(privacyLevel, dsvert.min_release_n), suppress + relabel
  # small var1 rows / var2 columns, fail closed by default (as dsvertContingencyDS).
  cmat <- matrix(counts, nrow = as.integer(K), ncol = as.integer(L), byrow = TRUE)
  row_margins <- as.integer(rowSums(cmat))
  col_margins <- as.integer(colSums(cmat))
  suppress_effective <- !isTRUE(getOption("dsvert.allow_small_cell_release", FALSE))
  fail_effective <- isTRUE(getOption("dsvert.fail_on_small_cells", TRUE)) ||
    !isTRUE(getOption("dsvert.allow_silent_small_cells", FALSE))
  if (suppress_effective) {
    privacy_min <- max(as.integer(getOption("datashield.privacyLevel", 5L)),
                       as.integer(getOption("dsvert.min_release_n", 1L)))
    if (is.numeric(privacy_min) && privacy_min > 0L) {
      small_row <- row_margins > 0L & row_margins < privacy_min
      small_col <- col_margins > 0L & col_margins < privacy_min
      cell_mask <- cmat > 0L & cmat < privacy_min
      if ((any(cell_mask) || any(small_row) || any(small_col)) && fail_effective) {
        stop("Cross-server contingency has a positive cell or margin below ",
             "datashield.privacyLevel; refusing to release counts", call. = FALSE)
      }
      cmat[cell_mask] <- 0L
      if (any(small_row)) { cmat[small_row, ] <- 0L; row_levels[small_row] <- "<suppressed>" }
      if (any(small_col)) { cmat[, small_col] <- 0L; col_levels[small_col] <- "<suppressed>" }
      counts <- as.integer(t(cmat))
    }
  }
  list(counts = counts, K = K, L = L,
       row_levels = row_levels, col_levels = col_levels,
       small_cell_policy = if (suppress_effective) {
         if (fail_effective) "fail" else "zero"
       } else "none")
}
