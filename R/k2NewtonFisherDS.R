# k2NewtonFisherDS.R: Server-side functions for real diagonal Fisher Newton-IRLS.
# 3-phase protocol: w R1 → w close + w*x² R1 → w*x² close + d_j
# Gaussian: single-phase d_j = sum(x²_j), no Beaver needed (w=1 constant)

#' Identity link: set mu = eta (for Gaussian GLM)
#' @export
k2IdentityLinkDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) stop("No eta share")
  ss$secure_mu_share <- eta_fp
  list(ok = TRUE)
}

#' Gaussian Fisher: d_j = sum(x²_j) — no Beaver, w=1 constant
#' @export
k2GaussianFisherDS <- function(p_total = 6L, frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)
  xsq_fp <- ss$k2_xsq_fp
  if (is.null(xsq_fp)) stop("No x² shares. Run k2PrecomputeXSqPhase2DS first.")
  n <- ss$k2_x_n
  result <- .callMheTool("k2-gaussian-fisher", list(
    p = as.integer(p_total), n = as.integer(n), frac_bits = as.integer(frac_bits),
    xsq_fp = xsq_fp))
  list(fisher_diag_fp = result$fisher_diag_fp)
}

#' Gaussian one-shot Phase 1: local X^T X + X^T y + Beaver R1 for cross terms
#' @export
k2GaussianOneshotPhase1DS <- function(party_id = 0L, p_total = 6L,
                                       frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)
  x_fp <- ss$k2_x_full_fp
  y_fp <- ss$k2_y_share_fp
  if (is.null(x_fp)) stop("No X_full share")
  if (is.null(y_fp)) stop("No y share")
  n <- ss$k2_x_n

  # Consume Beaver triple from blob
  blob <- .blob_consume("k2_oneshot_triples", ss)
  if (is.null(blob)) stop("No oneshot triple blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-gaussian-oneshot", list(
    phase = 1L, party_id = party_id, frac_bits = frac_bits,
    n = as.integer(n), p = as.integer(p_total),
    x_full_fp = x_fp, y_share_fp = y_fp,
    triple_a = triple$a, triple_b = triple$b))

  # Store triple for phase 2
  ss$k2_oneshot_triple <- triple
  list(local_xtx_fp = result$local_xtx_fp,
       local_xty_fp = result$local_xty_fp,
       xma = result$xma, ymb = result$ymb)
}

#' Gaussian one-shot Phase 2: Beaver close → cross X^T X and X^T y shares
#' @export
k2GaussianOneshotPhase2DS <- function(party_id = 0L, p_total = 6L,
                                       frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)
  x_fp <- ss$k2_x_full_fp
  y_fp <- ss$k2_y_share_fp
  triple <- ss$k2_oneshot_triple
  n <- ss$k2_x_n

  # Consume peer R1
  peer_blob <- .blob_consume("k2_oneshot_peer_r1", ss)
  if (is.null(peer_blob)) stop("No peer oneshot R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-gaussian-oneshot", list(
    phase = 2L, party_id = party_id, frac_bits = frac_bits,
    n = as.integer(n), p = as.integer(p_total),
    x_full_fp = x_fp, y_share_fp = y_fp,
    triple_a = triple$a, triple_b = triple$b, triple_c = triple$c,
    peer_xma = peer_r1$xma, peer_ymb = peer_r1$ymb))

  ss$k2_oneshot_triple <- NULL
  list(cross_xtx_fp = result$cross_xtx_fp,
       cross_xty_fp = result$cross_xty_fp)
}

#' Fisher Phase 1: Beaver R1 for w = mu*(1-mu)
#' @export
k2RealFisherPhase1DS <- function(party_id = 0L, family = "binomial", frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- ss$secure_mu_share
  if (is.null(mu_fp)) stop("No mu share")

  # Consume w Beaver triple from blob
  w_blob <- .blob_consume("k2_fisher_w_triple", ss)
  if (is.null(w_blob)) stop("No w triple blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(w_blob), recipient_sk = tsk))
  triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(mu_fp)) * 3 / 4 / 8)
  result <- .callMheTool("k2-newton-fisher-real", list(
    phase = 1L, party_id = party_id, family = family, frac_bits = frac_bits,
    n = n, p = 0L,
    mu_share_fp = .base64url_to_base64(mu_fp),
    w_a = triple$a, w_b = triple$b))

  # Store triple for phases 2-3
  ss$k2_fisher_w_triple <- triple
  list(w_xma = result$w_xma, w_ymb = result$w_ymb)
}

#' Fisher Phase 2: w close + Beaver R1 for w*x²_j
#' @export
k2RealFisherPhase2DS <- function(party_id = 0L, family = "binomial", frac_bits = 20L,
                                  p_total = 6L, session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- ss$secure_mu_share
  x_fp <- ss$k2_x_full_fp
  xsq_fp <- ss$k2_xsq_fp
  w_triple <- ss$k2_fisher_w_triple
  if (is.null(xsq_fp)) stop("No x² shares. Run k2PrecomputeXSqPhase2DS first.")

  # Consume peer w R1
  peer_blob <- .blob_consume("k2_fisher_w_peer_r1", ss)
  if (is.null(peer_blob)) stop("No peer w R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  # Consume w*x² Beaver triple
  wx_blob <- .blob_consume("k2_fisher_wx_triple", ss)
  if (is.null(wx_blob)) stop("No w*x² triple blob")
  dec2 <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(wx_blob), recipient_sk = tsk))
  wx_triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec2$data)))

  n <- as.integer(nchar(.base64url_to_base64(mu_fp)) * 3 / 4 / 8)
  result <- .callMheTool("k2-newton-fisher-real", list(
    phase = 2L, party_id = party_id, family = family, frac_bits = frac_bits,
    n = n, p = as.integer(p_total),
    mu_share_fp = .base64url_to_base64(mu_fp),
    xsq_fp = xsq_fp,
    w_a = w_triple$a, w_b = w_triple$b, w_c = w_triple$c,
    peer_w_xma = peer_r1$w_xma, peer_w_ymb = peer_r1$w_ymb,
    wx_a = wx_triple$a, wx_b = wx_triple$b))

  # Store wx triple for phase 3
  ss$k2_fisher_wx_triple <- wx_triple
  ss$k2_fisher_peer_w <- peer_r1
  list(wx_xma = result$wx_xma, wx_ymb = result$wx_ymb)
}

#' Fisher Phase 3: w*x² close → d_j = sum(w*x²_j)
#' @export
k2RealFisherPhase3DS <- function(party_id = 0L, family = "binomial", frac_bits = 20L,
                                  p_total = 6L, session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- ss$secure_mu_share
  xsq_fp <- ss$k2_xsq_fp
  w_triple <- ss$k2_fisher_w_triple
  wx_triple <- ss$k2_fisher_wx_triple
  peer_w <- ss$k2_fisher_peer_w

  # Consume peer w*x² R1
  peer_blob <- .blob_consume("k2_fisher_wx_peer_r1", ss)
  if (is.null(peer_blob)) stop("No peer w*x² R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_wx_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(mu_fp)) * 3 / 4 / 8)
  result <- .callMheTool("k2-newton-fisher-real", list(
    phase = 3L, party_id = party_id, family = family, frac_bits = frac_bits,
    n = n, p = as.integer(p_total),
    mu_share_fp = .base64url_to_base64(mu_fp),
    xsq_fp = xsq_fp,
    w_a = w_triple$a, w_b = w_triple$b, w_c = w_triple$c,
    peer_w_xma = peer_w$w_xma, peer_w_ymb = peer_w$w_ymb,
    wx_a = wx_triple$a, wx_b = wx_triple$b, wx_c = wx_triple$c,
    peer_wx_xma = peer_wx_r1$wx_xma, peer_wx_ymb = peer_wx_r1$wx_ymb))

  # Cleanup
  ss$k2_fisher_w_triple <- NULL
  ss$k2_fisher_wx_triple <- NULL
  ss$k2_fisher_peer_w <- NULL

  list(fisher_diag_fp = result$fisher_diag_fp)
}
