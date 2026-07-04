#' @title Generate DCF threshold-comparison keys
#' @description Dealer-side helper for comparing additive FP shares with a
#'   public threshold without reconstructing the shared value. The dealer
#'   returns only transport-encrypted key blobs for the two comparison parties.
#' @param dcf0_pk,dcf1_pk Base64url transport public keys of parties 0 and 1.
#' @param n Number of shared values to compare.
#' @param threshold Public threshold. The comparison bit is
#'   \code{value < threshold}.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits.
#' @return list(cmp_blob_0, cmp_blob_1).
#' @export
k2CmpGenKeysDS <- function(dcf0_pk, dcf1_pk, n, threshold,
                           session_id = NULL, frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.numeric(n) || length(n) != 1L || n < 1) {
    stop("n must be a positive scalar", call. = FALSE)
  }
  if (!is.numeric(threshold) || length(threshold) != 1L ||
      !is.finite(threshold)) {
    stop("threshold must be a finite scalar", call. = FALSE)
  }
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(dcf0_pk, ss, "party0")
  .dsvert_validate_recipient_pk(dcf1_pk, ss, "party1")
  cmp <- .callMpcTool("k2-cmp-gen", list(
    n = as.integer(n),
    threshold = as.numeric(threshold),
    frac_bits = as.integer(frac_bits)))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)
  sealed0 <- .callMpcTool("transport-encrypt", list(
    data = cmp$party0_keys, recipient_pk = pk0))
  sealed1 <- .callMpcTool("transport-encrypt", list(
    data = cmp$party1_keys, recipient_pk = pk1))
  list(
    cmp_blob_0 = base64_to_base64url(sealed0$sealed),
    cmp_blob_1 = base64_to_base64url(sealed1$sealed))
}

#' @title Store encrypted threshold-comparison keys
#' @param blob_key Session blob key containing this party's encrypted DCF keys.
#' @param output_key Session key for decrypted DCF keys.
#' @param session_id MPC session id.
#' @return list(stored, output_key).
#' @export
k2CmpStoreKeysDS <- function(blob_key = "k2_cmp_keys",
                             output_key = "k2_cmp_keys",
                             session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume(blob_key, ss)
  if (is.null(blob)) stop("No comparison key blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport secret key missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  ss[[output_key]] <- dec$data
  list(stored = TRUE, output_key = output_key)
}

.k2_cmp_source_n <- function(source_fp) {
  as.integer(length(jsonlite::base64_dec(
    .base64url_to_base64(source_fp))) / 8L)
}

#' @title Threshold comparison round 1
#' @description Returns a one-time-masked DCF value for client relay to the
#'   peer. The returned masked value is not a share of the underlying count:
#'   with the fresh per-\code{k2CmpGenKeysDS} mask it is an information-theoretic
#'   one-time pad, so a passive relay learns nothing from it in isolation. When
#'   \code{peer_pk} is supplied the masked value is additionally sealed to the
#'   consuming peer's transport key (defence-in-depth: the analyst relay then
#'   only ever forwards an opaque blob, closing any residual exposure should a
#'   mask ever be reused).
#' @param source_key Session key containing the FP share vector.
#' @param party_id 0 or 1.
#' @param keys_key Session key containing decrypted comparison keys.
#' @param peer_pk Optional base64url transport public key of the peer that will
#'   consume this masked value in \code{k2CmpRound2DS}. If given, the masked
#'   value is transport-sealed to that peer before relay.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits.
#' @return list(cmp_masked). Sealed iff \code{peer_pk} was supplied.
#' @export
k2CmpRound1DS <- function(source_key, party_id,
                          keys_key = "k2_cmp_keys",
                          peer_pk = NULL,
                          session_id = NULL,
                          frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  source <- ss[[source_key]]
  keys <- ss[[keys_key]]
  if (is.null(source) || is.null(keys)) {
    stop("source_key / keys_key missing", call. = FALSE)
  }
  n <- .k2_cmp_source_n(source)
  res <- .callMpcTool("k2-cmp-round1", list(
    share_fp = .base64url_to_base64(source),
    dcf_keys = keys,
    party_id = as.integer(party_id),
    n = as.integer(n),
    frac_bits = as.integer(frac_bits)))
  masked <- res$masked
  if (!is.null(peer_pk) && nzchar(peer_pk)) {
    sealed <- .callMpcTool("transport-encrypt", list(
      data = masked, recipient_pk = .base64url_to_base64(peer_pk)))
    masked <- sealed$sealed
  }
  list(cmp_masked = base64_to_base64url(masked))
}

#' @title Threshold comparison round 2
#' @description Consumes the peer's masked DCF value and stores this party's
#'   FP-scaled comparison-bit share. The two parties' outputs sum to 1.0 iff
#'   the hidden shared value is below the public threshold, otherwise 0.0.
#' @param source_key Session key containing the FP share vector.
#' @param party_id 0 or 1.
#' @param output_key Session key for the comparison-bit FP share vector.
#' @param keys_key Session key containing decrypted comparison keys.
#' @param peer_blob_key Session blob key containing the peer masked value.
#' @param peer_sealed Logical. If TRUE, the relayed peer masked value was
#'   transport-sealed by \code{k2CmpRound1DS(peer_pk=...)} and is decrypted here
#'   with this party's transport secret key before use.
#' @param return_share Logical. If TRUE, return this party's output share.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits.
#' @return list(stored, output_key) and optionally \code{indicator_fp}.
#' @export
k2CmpRound2DS <- function(source_key, party_id, output_key,
                          keys_key = "k2_cmp_keys",
                          peer_blob_key = "k2_cmp_peer_masked",
                          peer_sealed = FALSE,
                          return_share = FALSE,
                          session_id = NULL,
                          frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  source <- ss[[source_key]]
  keys <- ss[[keys_key]]
  if (is.null(source) || is.null(keys)) {
    stop("source_key / keys_key missing", call. = FALSE)
  }
  peer <- .blob_consume(peer_blob_key, ss)
  if (is.null(peer)) stop("peer masked comparison blob missing", call. = FALSE)
  if (isTRUE(peer_sealed)) {
    tsk <- .key_get("transport_sk", ss)
    if (is.null(tsk)) stop("Transport secret key missing", call. = FALSE)
    dec <- .callMpcTool("transport-decrypt", list(
      sealed = .base64url_to_base64(peer),
      recipient_sk = tsk))
    peer_masked_b64 <- dec$data
  } else {
    peer_masked_b64 <- .base64url_to_base64(peer)
  }
  n <- .k2_cmp_source_n(source)
  res <- .callMpcTool("k2-cmp-round2", list(
    share_fp = .base64url_to_base64(source),
    dcf_keys = keys,
    peer_masked = peer_masked_b64,
    party_id = as.integer(party_id),
    n = as.integer(n),
    frac_bits = as.integer(frac_bits)))
  ss[[output_key]] <- res$indicator_fp
  out <- list(stored = TRUE, output_key = output_key)
  if (isTRUE(return_share)) out$indicator_fp <- res$indicator_fp
  out
}
