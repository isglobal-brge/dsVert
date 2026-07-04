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
#' @return list(peer_blob) -- sealed payload for relay.
#' @export
k2BeaverShareVectorDS <- function(source_key, peer_pk,
                                   session_id = NULL,
                                   frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  # Pin the recipient to an identity-verified peer: the peer share is sealed to
  # `peer_pk`, so an unverified recipient would let a caller supply its own key
  # and decrypt the "sealed" share (its complement is the retained own_share).
  .dsvert_validate_peer_pk(peer_pk, ss, "peer")
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
#' @param blob_key Character. Session blob slot to consume the sealed share from.
#' @param output_key Character. Session-state key under which the output share is written.
#' @param session_id Character. Active MPC session identifier.
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
#' @param session_id Character. Active MPC session identifier.
#' @param frac_bits Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50 for Ring127).
#' @param ring Integer (63 or 127). MPC ring selector; controls fixed-point precision.
#' @export
k2BeaverExtractColumnDS <- function(source_key, n, K, col_index,
                                    output_key, session_id = NULL,
                                    frac_bits = 20L, ring = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) {
    stop("source_key '", source_key, "' missing", call. = FALSE)
  }
  # The extracted column becomes a length-n share that downstream helpers sum
  # into a released aggregate; require it to span the minimum releasable number
  # of observations so a caller cannot reshape the source to pluck (and later
  # reveal) a single record.
  .dsvert_guard_min_agg_count(n, "column extraction")
  ci <- as.integer(col_index)
  if (ci >= 1L && ci <= K) ci <- ci - 1L  # R -> 0-based
  if (ci < 0L || ci >= K) {
    stop("col_index out of range", call. = FALSE)
  }
  # Ring inference: caller may pass "ring63"/"ring127" explicitly; else
  # fall back to session-state ring tag set by k2ShareInputDS. Without
  # this, Ring127 16-byte Uint128 records get mis-parsed as Ring63
  # 8-byte FixedPoint -> length mismatch (silent in extract output if
  # lengths happen to align modulo 2; loud when they don't).
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  }
  res <- .callMpcTool("k2-fp-extract-column", list(
    fp_data = fp, n = as.integer(n), k = as.integer(K),
    col = as.integer(ci), frac_bits = as.integer(frac_bits),
    ring = ring))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key)
}

#' @title Sum an FP share vector to a scalar share
#' @description Local sum (shares are linear): returns the scalar FP
#'   representation of \eqn{\sum_i v_i^{share}} as a double.
#' @param source_key Character. Session-state key under which the source share is stored.
#' @param session_id Character. Active MPC session identifier.
#' @param frac_bits Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50 for Ring127).
#' @param ring Integer (63 or 127). MPC ring selector; controls fixed-point precision.
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
  # Ring63 -> 8-byte scalar out -> subsequent Ring127 aggregate saw 0
  # Uint128 values -> list() with empty $values).
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  }
  s <- .callMpcTool("k2-fp-sum", list(fp_data = fp, ring = ring))
  list(sum_share_fp = s$sum_fp, ring = ring)
}

#' @title Store a scalar sum share without returning it to the client
#' @description Local linear reduction of a session-stored FP share vector.
#'   Unlike \code{k2BeaverSumShareDS}, this helper keeps the scalar share in
#'   the server session. With \code{append = TRUE}, successive scalar sums are
#'   concatenated into one FP share vector. This supports pre-release MPC
#'   threshold checks where the analyst must not receive both parties' scalar
#'   shares before the disclosure guard passes.
#' @param source_key Session key containing the FP share vector to sum.
#' @param output_key Session key where the scalar share or concatenated scalar
#'   share vector is stored.
#' @param append Logical. Append this scalar to an existing FP vector.
#' @param session_id Active MPC session identifier.
#' @param ring Optional ring selector ("ring63"/"ring127"); defaults from the
#'   session when available.
#' @return list(stored, output_key, length).
#' @export
k2StoreSumShareDS <- function(source_key, output_key, append = FALSE,
                              session_id = NULL, ring = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.character(output_key) || length(output_key) != 1L ||
      !nzchar(output_key)) {
    stop("output_key must be a non-empty string", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) stop("source_key missing", call. = FALSE)
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  }
  s <- .callMpcTool("k2-fp-sum", list(fp_data = fp, ring = ring))$sum_fp
  new_raw <- jsonlite::base64_dec(s)
  if (isTRUE(append) && !is.null(ss[[output_key]])) {
    old_raw <- jsonlite::base64_dec(.base64url_to_base64(ss[[output_key]]))
    out_raw <- c(old_raw, new_raw)
  } else {
    out_raw <- new_raw
  }
  ss[[output_key]] <- jsonlite::base64_enc(out_raw)
  bytes_per_elem <- if (identical(ring, "ring127")) 16L else 8L
  list(stored = TRUE, output_key = output_key,
       length = as.integer(length(out_raw) / bytes_per_elem))
}

#' @title Return a stored FP share after a disclosure precheck has passed
#' @param source_key Session key containing the FP share vector.
#' @param session_id Active MPC session identifier.
#' @return list(share_fp).
#' @export
k2GetStoredShareDS <- function(source_key, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  # Server-authoritative raw-share release guard. This returns a raw additive
  # share to the caller; calling it on BOTH servers with the same key and
  # summing the complementary shares reconstructs the plaintext. Default-deny:
  # only authorised AGGREGATE output slots may be released (the cross-chisq K*L
  # count), never a per-observation input/intermediate share
  # (feature/label/eta/weight/offset/one-hot).
  if (!.dsvert_releasable_share_key(source_key)) {
    stop("DSVERT_NOT_RELEASABLE: source_key '", source_key, "' is not an ",
         "authorised releasable aggregate output; refusing to return a raw ",
         "share", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) stop("source_key missing", call. = FALSE)
  list(share_fp = fp)
}

#' @title Store the element-wise difference of two FP share vectors
#' @param a_key,b_key Session keys containing FP share vectors.
#' @param output_key Destination session key.
#' @param session_id Active MPC session identifier.
#' @param frac_bits Fixed-point fractional bits.
#' @param ring Optional ring selector ("ring63"/"ring127").
#' @return list(stored, output_key).
#' @export
k2FPSubStoreDS <- function(a_key, b_key, output_key, session_id = NULL,
                           frac_bits = 20L, ring = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  a <- ss[[a_key]]
  b <- ss[[b_key]]
  if (is.null(a) || is.null(b)) {
    stop("a_key / b_key missing", call. = FALSE)
  }
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  }
  res <- .callMpcTool("k2-fp-sub", list(
    a = .base64url_to_base64(a),
    b = .base64url_to_base64(b),
    frac_bits = as.integer(frac_bits),
    ring = ring))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key)
}

#' @title Sum a row-major share matrix by strided event index
#' @description Linear share operation: stores \eqn{\sum_i A_{ij}} for each
#'   event-time/bin index \eqn{j} without reconstructing the per-bin sums at
#'   the client. Used by non-disclosive Cox profile-score primitives.
#' @param source_key Session key containing a row-major n_obs-by-J FP share.
#' @param output_key Session key for the length-J FP share result.
#' @param n_obs Integer number of subjects.
#' @param J Integer number of event-time/bin columns.
#' @param session_id Character. Active MPC session identifier.
#' @param frac_bits Integer fixed-point fractional bits.
#' @param ring Integer 63 or 127.
#' @export
k2BeaverStridedSumShareDS <- function(source_key, output_key, n_obs, J,
                                      session_id = NULL,
                                      frac_bits = 20L, ring = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  fp <- ss[[source_key]]
  if (is.null(fp)) stop("source_key missing", call. = FALSE)
  # Each output index folds n_obs rows (row-major stride over J columns), so
  # n_obs is the per-index aggregation size. Enforce the releasable-aggregate
  # floor to block an isolating shape (n_obs = 1) that would emit one output
  # value per observation.
  .dsvert_guard_min_agg_count(n_obs, "strided share-sum")
  if (is.null(ring) || !nzchar(ring)) {
    ss_ring <- as.integer(ss$k2_ring %||% 63L)
    ring <- if (ss_ring == 127L) "ring127" else "ring63"
  } else {
    ring <- as.integer(ring)
    ring <- if (ring == 127L) "ring127" else "ring63"
  }
  if (identical(ring, "ring127")) frac_bits <- 50L
  res <- .callMpcTool("k2-fp-strided-sum", list(
    fp_data = fp,
    n = as.integer(n_obs),
    j = as.integer(J),
    frac_bits = as.integer(frac_bits),
    ring = ring))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key,
       n_obs = as.integer(n_obs), J = as.integer(J), ring = ring)
}
