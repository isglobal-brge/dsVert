# Server-side attack-surface guards for the registered aggregate/assign methods.
#
# In DataSHIELD the analyst can call ANY registered aggregate/assign method
# directly, out of the intended orchestration, with arbitrary arguments, and on
# BOTH data servers. Two root-cause classes let a malicious caller reconstruct
# original per-observation data; these two guards close them uniformly.
#
#  (1) SEAL-TO-ATTACKER-KEY. A primitive that transport-seals a share to an
#      analyst-supplied `peer_pk` must PIN that recipient to the identity-
#      verified peer set (`ss$peer_transport_pks`, populated by
#      mpcStoreTransportKeysDS). Otherwise the analyst passes its OWN transport
#      key, the "seal" gives no confidentiality, and it decrypts the share.
#
#  (2) RAW-SHARE RELEASE. A primitive that returns a raw additive share to the
#      caller must only ever release a key holding an AUTHORISED AGGREGATE
#      output, never a per-observation input/intermediate slot — whose
#      complementary share on the peer reconstructs the plaintext.
#
# Both guards are NON-BREAKING for legitimate flows: real orchestration always
# establishes transport keys first (so the true peer pk is in the verified set)
# and only ever reads authorised aggregate slots.

#' @keywords internal
.dsvert_validate_peer_pk <- function(peer_pk, ss, what = "recipient") {
  if (is.null(peer_pk) || !nzchar(peer_pk)) {
    stop("DSVERT_MISSING_PEER_PK: no ", what, " transport key supplied",
         call. = FALSE)
  }
  peers <- ss$peer_transport_pks
  if (is.null(peers) || !length(peers)) {
    stop("DSVERT_NO_PEER_SET: transport keys not established (call ",
         "mpcStoreTransportKeysDS first); refusing to seal to an unverified ",
         "key", call. = FALSE)
  }
  pk_b64 <- tryCatch(.base64url_to_base64(peer_pk), error = function(e) peer_pk)
  ok <- any(vapply(peers, function(p) identical(as.character(p), pk_b64),
                   logical(1L)))
  if (!ok) {
    stop("DSVERT_UNVERIFIED_RECIPIENT: the supplied ", what, " transport key ",
         "is not a registered/identity-verified peer (anti seal-to-self); ",
         "refusing to seal", call. = FALSE)
  }
  invisible(TRUE)
}

#' @keywords internal
# Recipient pin allowing a verified peer OR this server's own transport key
# (some primitives legitimately seal a share to a fixed party role that may be
# self). Anything else — notably an analyst-supplied key — is rejected.
.dsvert_validate_recipient_pk <- function(peer_pk, ss, what = "recipient") {
  if (is.null(peer_pk) || !nzchar(peer_pk)) {
    stop("DSVERT_MISSING_PEER_PK: no ", what, " transport key supplied",
         call. = FALSE)
  }
  own <- .key_get("transport_pk", ss)
  pk_b64 <- tryCatch(.base64url_to_base64(peer_pk), error = function(e) peer_pk)
  if (!is.null(own) && identical(as.character(own), pk_b64)) {
    return(invisible(TRUE))
  }
  .dsvert_validate_peer_pk(peer_pk, ss, what)
}

#' @keywords internal
# Default-deny allowlist for raw-share release (k2GetStoredShareDS). Only keys
# holding an AGGREGATE output (K*L contingency counts — not a per-observation
# value) may be returned as a raw share. The sole legitimate caller is
# ds.vertChisqCross. Everything else — feature/label/eta/weight/offset/one-hot
# per-observation slots — is refused, closing the arbitrary-share-exfiltration
# reconstruction chain.
.dsvert_releasable_share_key <- function(key) {
  as.character(key)[1L] %in% c("k2_chisq_cross_count_shares")
}
