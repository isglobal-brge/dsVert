#' @title Share a session FP vector with the peer (additive 2-party split)
#' @description Reads an FP vector stored under \code{source_key} in the
#'   MPC session, splits it into two additive Ring63 shares, overwrites
#'   \code{source_key} with this party's share (so downstream helpers
#'   see a share rather than the plaintext), and returns a
#'   transport-encrypted blob carrying the peer's share for relay via
#'   \code{mpcStoreBlobDS} under \code{relay_key}.
#'
#'   Used by \code{ds.vertChisqCross} to share each one-hot indicator
#'   matrix between the DCF parties before the per-cell Beaver product.
#' @param source_key Character. Session slot holding the plaintext FP
#'   vector (e.g. \code{"k2_onehot_<var>_fp"}).
#' @param peer_pk Transport pk of the peer (base64url).
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20).
#' @return list(peer_blob) — sealed payload for relay.
#' @export
k2BeaverShareVectorDS <- function(source_key, peer_pk,
                                   session_id = NULL,
                                   frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) {
    stop("source_key '", source_key, "' not in session", call. = FALSE)
  }
  split_res <- .callMpcTool("k2-split-fp-share",
    list(data_fp = fp))
  ss[[source_key]] <- split_res$own_share
  # Transport-seal the peer's share for relay.
  sealed <- .callMpcTool("transport-encrypt",
    list(data = split_res$peer_share,
         recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed))
}

#' @title Receive a shared FP vector and store under a session key
#' @description Consume the peer-relayed blob previously delivered via
#'   \code{mpcStoreBlobDS} under \code{blob_key}, decrypt with this
#'   party's transport secret key, and store under \code{output_key}.
#' @export
k2BeaverReceiveVectorDS <- function(blob_key, output_key,
                                     session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume(blob_key, ss)
  if (is.null(blob)) {
    stop("No blob '", blob_key, "' in session", call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  ss[[output_key]] <- dec$data
  list(stored = TRUE, output_key = output_key)
}

#' @title Extract a single column from a row-major n-by-K FP vector
#' @description Given a session slot holding an \eqn{n\times K}
#'   row-major flat FP vector (e.g. a one-hot indicator matrix share),
#'   copy the k-th column into \code{output_key} as a length-n share.
#'   Because additive sharing is linear, extracting a column of the
#'   share equals extracting the corresponding column of the (logical)
#'   plaintext once both parties' shares are summed.
#' @param source_key Session slot holding the n*K flat FP vector.
#' @param n,K Matrix dimensions.
#' @param col_index 1-based column index (R convention) or 0-based.
#' @param output_key Destination session slot for the n-length column share.
#' @export
k2BeaverExtractColumnDS <- function(source_key, n, K, col_index,
                                    output_key, session_id = NULL,
                                    frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) {
    stop("source_key '", source_key, "' missing", call. = FALSE)
  }
  ci <- as.integer(col_index)
  if (ci >= 1L && ci <= K) ci <- ci - 1L  # R -> 0-based
  if (ci < 0L || ci >= K) {
    stop("col_index out of range", call. = FALSE)
  }
  res <- .callMpcTool("k2-fp-extract-column", list(
    fp_data = fp, n = as.integer(n), k = as.integer(K),
    col = as.integer(ci), frac_bits = as.integer(frac_bits)))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key)
}

#' @title Sum an FP share vector to a scalar share
#' @description Local sum (shares are linear): returns the scalar FP
#'   representation of \eqn{\sum_i v_i^{share}} as a double.
#' @export
k2BeaverSumShareDS <- function(source_key, session_id = NULL,
                                frac_bits = 20L, ring = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) stop("source_key missing", call. = FALSE)
  # Determine ring from session (set by k2ShareInputDS) if caller didn't
  # pass one. k2-fp-sum expects "ring127" for 16-byte Uint128 records;
  # Ring63 is the 8-byte default. Getting this wrong silently truncates
  # the per-element parse and returns garbage (see multinom joint bug #9
  # intercept-grad NA: Ring127 residual shares were being parsed as
  # Ring63 → 8-byte scalar out → subsequent Ring127 aggregate saw 0
  # Uint128 values → list() with empty $values).
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  }
  s <- .callMpcTool("k2-fp-sum", list(fp_data = fp, ring = ring))
  list(sum_share_fp = s$sum_fp, ring = ring)
}
