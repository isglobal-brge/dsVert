#' @title Generate n-length Beaver triples for element-wise Ring63 product
#' @description Dealer-only aggregate. Samples n element-wise Beaver
#'   triples \eqn{(a_i, b_i, c_i = a_i b_i)} in Ring63, splits each into
#'   two additive shares, and emits two self-contained payloads sealed
#'   (transport-encrypted) to the two DCF parties' transport public keys.
#'   The client relays each blob to the corresponding party via
#'   \code{mpcStoreBlobDS} under the key \code{"k2_beaver_vecmul_triple"};
#'   each party then consumes it via
#'   \code{\link{k2BeaverVecmulConsumeTripleDS}}.
#'
#'   Inter-party leakage: none. The triple is a standard MPC randomness
#'   commitment; both parties learn only their own shares.
#'
#' @param dcf0_pk,dcf1_pk Base64url transport public keys of the two DCF
#'   parties.
#' @param n Vector length.
#' @param session_id MPC session id (used only to drive the RNG seed).
#' @param frac_bits Ring63 fractional bits (default 20). At ring=127 the
#'   handler defaults to fracBits=50 regardless of this argument.
#' @param ring Integer 63 (default) or 127. Routes through the Uint128
#'   Ring127 handler when 127 (task #116 Cox/LMM STRICT migration).
#' @return list(triple_blob_0, triple_blob_1) -- both base64url sealed
#'   payloads for relay to party 0 and party 1.
#' @export
k2BeaverVecmulGenTriplesDS <- function(dcf0_pk, dcf1_pk, n,
                                       session_id = NULL,
                                       frac_bits = 20L,
                                       ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.numeric(n) || length(n) != 1L || n < 1) {
    stop("n must be a positive scalar", call. = FALSE)
  }
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  res <- .callMpcTool("k2-beaver-vecmul-gen-triples",
    list(n = as.integer(n), frac_bits = as.integer(frac_bits),
         ring = ring_tag))
  # Seal each triple blob to the target party's transport pk.
  seal0 <- .callMpcTool("transport-encrypt",
    list(data = res$triple_0,
         recipient_pk = .base64url_to_base64(dcf0_pk)))
  seal1 <- .callMpcTool("transport-encrypt",
    list(data = res$triple_1,
         recipient_pk = .base64url_to_base64(dcf1_pk)))
  list(triple_blob_0 = base64_to_base64url(seal0$sealed),
       triple_blob_1 = base64_to_base64url(seal1$sealed),
       n = as.integer(n))
}

#' @title Consume a relayed Beaver vecmul triple
#' @description Per-party aggregate. Decrypts the session blob
#'   \code{"k2_beaver_vecmul_triple"} (relayed by the client from the
#'   dealer's \code{\link{k2BeaverVecmulGenTriplesDS}}) using this
#'   server's transport secret key and stores the base64 triple payload
#'   under \code{ss$k2_beaver_vecmul_triple} for subsequent round-1 /
#'   round-2 calls.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
#' @export
k2BeaverVecmulConsumeTripleDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("k2_beaver_vecmul_triple", ss)
  if (is.null(blob)) {
    stop("No k2_beaver_vecmul_triple blob in session; client must ",
         "relay it from the dealer.", call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport secret key missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob),
         recipient_sk = tsk))
  ss$k2_beaver_vecmul_triple <- dec$data
  list(stored = TRUE)
}

#' @title Beaver vecmul round 1
#' @description Per-party aggregate. Reads the own x- and y-share FP
#'   vectors from the session (under \code{x_key} and \code{y_key}) and
#'   the own triple share, computes the masked
#'     \eqn{d^{own} = x^{own} - a^{own}},
#'     \eqn{e^{own} = y^{own} - b^{own}},
#'   and transport-encrypts \code{(d^{own}, e^{own})} to the peer's
#'   public key. The client relays the returned \code{peer_blob} to the
#'   other party via \code{mpcStoreBlobDS} under
#'   \code{"k2_beaver_vecmul_peer_masked"}, ready for round 2.
#' @param peer_pk Base64url transport pk of the peer.
#' @param x_key,y_key Session keys containing this party's FP shares.
#' @param n Vector length.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20). At ring=127 the
#'   handler defaults to fracBits=50 regardless of this argument.
#' @param ring Integer 63 (default) or 127.
#' @return list(peer_blob) -- base64url sealed payload for peer relay.
#' @export
k2BeaverVecmulR1DS <- function(peer_pk, x_key, y_key, n,
                               session_id = NULL, frac_bits = 20L,
                               ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  x_share <- ss[[x_key]]
  y_share <- ss[[y_key]]
  if (is.null(x_share) || is.null(y_share)) {
    stop("Session slots ", x_key, " / ", y_key, " are not populated",
         call. = FALSE)
  }
  if (is.null(ss$k2_beaver_vecmul_triple)) {
    stop("Beaver vecmul triple not consumed; call ",
         "k2BeaverVecmulConsumeTripleDS first.", call. = FALSE)
  }
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  r1 <- .callMpcTool("k2-beaver-vecmul-round1", list(
    x_fp = x_share, y_fp = y_share,
    triple_blob = ss$k2_beaver_vecmul_triple,
    n = as.integer(n), frac_bits = as.integer(frac_bits),
    ring = ring_tag))
  # Stash own state for round 2 (we just need to pass x, y, triple, and
  # peer d/e back into the round-2 handler; the handler reconstructs
  # state internally).
  # Seal to peer:
  payload <- jsonlite::toJSON(list(d_fp = r1$d_fp, e_fp = r1$e_fp),
                              auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(as.character(payload)))
  sealed <- .callMpcTool("transport-encrypt",
    list(data = payload_b64,
         recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed))
}

#' @title Beaver vecmul round 2
#' @description Per-party aggregate. Decrypts the peer's masked shares
#'   (relayed under \code{"k2_beaver_vecmul_peer_masked"}), combines with
#'   own triple + own (x, y) shares, and produces this party's share of
#'   \eqn{z = x \odot y} with post-truncation to keep \code{frac_bits}
#'   consistent. Stores the result under \code{output_key} in the session.
#' @param is_party0 Logical. TRUE for the DCF party designated as
#'   "party 0" (by convention, the outcome server for Cox).
#' @param x_key,y_key Session keys with own FP shares (same as round 1).
#' @param output_key Session key to receive the FP share of z.
#' @param n Vector length.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20). At ring=127 the
#'   handler defaults to fracBits=50 regardless of this argument.
#' @param ring Integer 63 (default) or 127.
#' @return list(stored = TRUE, output_key).
#' @export
k2BeaverVecmulR2DS <- function(is_party0, x_key, y_key, output_key, n,
                               session_id = NULL, frac_bits = 20L,
                               ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  x_share <- ss[[x_key]]
  y_share <- ss[[y_key]]
  if (is.null(x_share) || is.null(y_share)) {
    stop("Session slots ", x_key, " / ", y_key, " are not populated",
         call. = FALSE)
  }
  if (is.null(ss$k2_beaver_vecmul_triple)) {
    stop("Beaver vecmul triple missing in session", call. = FALSE)
  }
  blob <- .blob_consume("k2_beaver_vecmul_peer_masked", ss)
  if (is.null(blob)) {
    stop("Peer masked-share blob missing; client must relay after R1.",
         call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport secret key missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  res <- .callMpcTool("k2-beaver-vecmul-round2", list(
    x_fp = x_share, y_fp = y_share,
    triple_blob = ss$k2_beaver_vecmul_triple,
    peer_d_fp = payload$d_fp, peer_e_fp = payload$e_fp,
    is_party0 = isTRUE(is_party0),
    n = as.integer(n), frac_bits = as.integer(frac_bits),
    ring = ring_tag))
  ss[[output_key]] <- res$z_fp
  list(stored = TRUE, output_key = output_key)
}
