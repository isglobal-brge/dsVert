# k2WideSplineFullDS.R: 4-phase wide spline sigmoid + Newton-IRLS diagonal Fisher.

#' Pre-compute x² Phase 1: Beaver R1 for x_j*x_j
#' @export
k2PrecomputeXSqPhase1DS <- function(party_id = 0L, frac_bits = 20L,
                                     p_total = 6L, session_id = NULL) {
  ss <- .S(session_id)
  x_fp <- ss$k2_x_full_fp
  if (is.null(x_fp)) stop("No X shares in session")

  # Consume Beaver triples for x² (p features)
  xsq_blob <- .blob_consume("k2_xsq_triples", ss)
  if (is.null(xsq_blob)) stop("No x² triples blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(xsq_blob), recipient_sk = tsk))
  triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- ss$k2_x_n
  result <- .callMheTool("k2-precompute-xsq", list(
    phase = 1L, party_id = party_id, frac_bits = frac_bits,
    x_full_fp = .base64url_to_base64(x_fp),
    n = as.integer(n), p = as.integer(p_total),
    triple_a = triple$a, triple_b = triple$b, triple_c = ""))

  ss$k2_xsq_triple <- triple
  list(xma = result$xma, ymb = result$ymb)
}

#' Pre-compute x² Phase 2: Beaver close → x² shares stored
#' @export
k2PrecomputeXSqPhase2DS <- function(party_id = 0L, frac_bits = 20L,
                                     p_total = 6L, session_id = NULL) {
  ss <- .S(session_id)
  x_fp <- ss$k2_x_full_fp
  triple <- ss$k2_xsq_triple

  peer_blob <- .blob_consume("k2_xsq_peer_r1", ss)
  if (is.null(peer_blob)) stop("No x² peer R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- ss$k2_x_n
  result <- .callMheTool("k2-precompute-xsq", list(
    phase = 2L, party_id = party_id, frac_bits = frac_bits,
    x_full_fp = .base64url_to_base64(x_fp),
    n = as.integer(n), p = as.integer(p_total),
    triple_a = triple$a, triple_b = triple$b, triple_c = triple$c,
    peer_xma = peer_r1$xma, peer_ymb = peer_r1$ymb))

  # Store x² shares persistently (reused every iteration)
  ss$k2_xsq_fp <- result$xsq_fp
  ss$k2_xsq_triple <- NULL
  list(status = "ok")
}

#' Newton Fisher Phase 1: Beaver R1 for w = mu*(1-mu)
#' @export
k2NewtonFisherPhase1DS <- function(party_id = 0L, frac_bits = 20L,
                                    session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- ss$secure_mu_share
  if (is.null(mu_fp)) stop("No mu share. Run sigmoid first.")

  # Consume Beaver triple for w
  w_blob <- .blob_consume("k2_fisher_triple", ss)
  if (is.null(w_blob)) stop("No Fisher Beaver triple blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(w_blob), recipient_sk = tsk))
  triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(mu_fp)) * 3 / 4 / 8)

  result <- .callMheTool("k2-newton-fisher", list(
    phase = 1L, party_id = party_id, frac_bits = frac_bits,
    mu_share_fp = .base64url_to_base64(mu_fp),
    x_full_fp = "", n = n, p = 0L,
    beaver_w_a = triple$a, beaver_w_b = triple$b, beaver_w_c = triple$c))

  # Store triple for phase 2
  ss$k2_fisher_triple <- triple

  list(w_xma = result$w_xma, w_ymb = result$w_ymb)
}

#' Newton Fisher Phase 2: compute d_j = sum(w*x²_j) shares (disclosed aggregate)
#' @export
k2NewtonFisherPhase2DS <- function(party_id = 0L, frac_bits = 20L,
                                    p_total = 6L, session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- ss$secure_mu_share
  triple <- ss$k2_fisher_triple
  x_fp <- ss$k2_x_full_fp

  # Consume peer's Beaver R1 for w from blob
  peer_blob <- .blob_consume("k2_fisher_peer_r1", ss)
  if (is.null(peer_blob)) stop("No Fisher peer R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(mu_fp)) * 3 / 4 / 8)

  # For now, use scalar curvature proxy (sum(w)) until w*x² 3-phase protocol is implemented.
  # The x² shares are pre-computed and ready in session, but the w*x² Beaver relay
  # requires additional communication rounds not yet implemented.
  xsq_fp <- NULL  # TODO: enable real Fisher when w*x² relay is implemented

  # Consume w*x² triples + peer messages (if doing real Fisher)
  wxsq_blob <- .blob_consume("k2_wxsq_triples", ss)
  wxsq_peer_blob <- .blob_consume("k2_wxsq_peer_r1", ss)

  # Prepare w*x² triple data
  wxsq_a <- ""; wxsq_b <- ""; wxsq_c <- ""
  peer_wxsq_xma <- ""; peer_wxsq_ymb <- ""
  if (!is.null(wxsq_blob)) {
    dec2 <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(wxsq_blob), recipient_sk = tsk))
    wxsq_triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec2$data)))
    wxsq_a <- wxsq_triple$a; wxsq_b <- wxsq_triple$b; wxsq_c <- wxsq_triple$c
  }
  if (!is.null(wxsq_peer_blob)) {
    dec3 <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(wxsq_peer_blob), recipient_sk = tsk))
    wxsq_peer <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec3$data)))
    peer_wxsq_xma <- wxsq_peer$xma; peer_wxsq_ymb <- wxsq_peer$ymb
  }

  result <- .callMheTool("k2-newton-fisher", list(
    phase = 2L, party_id = party_id, frac_bits = frac_bits,
    mu_share_fp = .base64url_to_base64(mu_fp),
    x_full_fp = .base64url_to_base64(x_fp),
    n = n, p = as.integer(p_total),
    beaver_w_a = triple$a, beaver_w_b = triple$b, beaver_w_c = triple$c,
    peer_w_xma = peer_r1$w_xma, peer_w_ymb = peer_r1$w_ymb,
    xsq_fp = if (!is.null(xsq_fp)) xsq_fp else "",
    wxsq_triple_a = wxsq_a, wxsq_triple_b = wxsq_b, wxsq_triple_c = wxsq_c,
    peer_wxsq_xma = peer_wxsq_xma, peer_wxsq_ymb = peer_wxsq_ymb))

  ss$k2_fisher_triple <- NULL
  list(fisher_diag_fp = result$fisher_diag_fp)
}

#' Store DCF keys persistently (not consumed after first use)
#' @export
k2StoreDcfKeysPersistentDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume("k2_dcf_keys_persistent", ss)
  if (is.null(blob)) stop("No persistent DCF keys blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  ss$k2_dcf_keys_persistent <- dec$data  # base64 standard, reused across iterations
  list(status = "ok")
}

# k2WideSplineFullDS.R: 4-phase wide spline sigmoid via k2-wide-spline-full Go command.
# All spline logic runs in Go — R only handles blob I/O and session management.

#' @export
k2WideSplinePhase1DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) eta_fp <- ss$secure_eta_share
  if (is.null(eta_fp)) stop("No eta share in session")

  # Use persistent DCF keys (pre-generated, reused across iterations)
  dcf_keys <- ss$k2_dcf_keys_persistent
  if (is.null(dcf_keys)) {
    # Fallback: consume from blob (single-use)
    dcf_blob <- .blob_consume("k2_dcf_keys", ss)
    if (is.null(dcf_blob)) stop("No DCF keys (persistent or blob)")
    tsk <- .key_get("transport_sk", ss)
    dcf_dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(dcf_blob), recipient_sk = tsk))
    dcf_keys <- dcf_dec$data
  }

  n <- as.integer(nchar(.base64url_to_base64(eta_fp)) * 3 / 4 / 8)

  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 1L, party_id = party_id, family = family,
    eta_share_fp = .base64url_to_base64(eta_fp),
    dcf_keys = dcf_keys, n = n, frac_bits = frac_bits,
    num_intervals = num_intervals))

  # Store for later phases
  ss$k2_ws_dcf_keys <- dcf_keys
  ss$k2_ws_eta_fp <- .base64url_to_base64(eta_fp)
  ss$k2_ws_n <- n

  list(dcf_masked = base64_to_base64url(result$dcf_masked))
}

#' @export
k2WideSplinePhase2DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  # Consume peer DCF masked from blob
  peer_dcf <- .blob_consume("k2_peer_dcf_masked", ss)
  if (is.null(peer_dcf)) stop("No peer DCF masked blob")

  # Consume + decrypt triples blob
  triple_blob <- .blob_consume("k2_spline_triples", ss)
  if (is.null(triple_blob)) stop("No spline triples blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(triple_blob), recipient_sk = tsk))
  triples <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 2L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = .base64url_to_base64(peer_dcf),
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    t_and_a = triples$and_a, t_and_b = triples$and_b, t_and_c = triples$and_c,
    t_had1_a = triples$had1_a, t_had1_b = triples$had1_b, t_had1_c = triples$had1_c,
    t_had2_a = triples$had2_a, t_had2_b = triples$had2_b, t_had2_c = triples$had2_c))

  # Store triples + peer DCF for phases 3-4
  ss$k2_ws_triples <- triples
  ss$k2_ws_peer_dcf <- .base64url_to_base64(peer_dcf)

  list(and_xma = result$and_xma, and_ymb = result$and_ymb,
       had1_xma = result$had1_xma, had1_ymb = result$had1_ymb)
}

#' @export
k2WideSplinePhase3DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  # Consume peer AND+Had1 R1 from blob
  peer_blob <- .blob_consume("k2_peer_beaver_r1", ss)
  if (is.null(peer_blob)) stop("No peer Beaver R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  tr <- ss$k2_ws_triples
  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 3L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = ss$k2_ws_peer_dcf,
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    t_and_a = tr$and_a, t_and_b = tr$and_b, t_and_c = tr$and_c,
    t_had1_a = tr$had1_a, t_had1_b = tr$had1_b, t_had1_c = tr$had1_c,
    t_had2_a = tr$had2_a, t_had2_b = tr$had2_b, t_had2_c = tr$had2_c,
    p_and_xma = peer_r1$and_xma, p_and_ymb = peer_r1$and_ymb,
    p_had1_xma = peer_r1$had1_xma, p_had1_ymb = peer_r1$had1_ymb))

  # Store peer R1 for phase 4 (needed for Go recomputation)
  ss$k2_ws_peer_and_had1_r1 <- peer_r1

  list(had2_xma = result$had2_xma, had2_ymb = result$had2_ymb)
}

#' @export
k2WideSplinePhase4DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  # Consume peer Had2 R1 from blob
  peer_blob <- .blob_consume("k2_peer_had2_r1", ss)
  if (is.null(peer_blob)) stop("No peer Had2 R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  # Also need peer AND+Had1 R1 (already consumed in phase 3, need to re-read from session)
  # Phase 3 stored the peer R1 implicitly via the Go command recomputation.
  # We need to pass them again for phase 4.
  # Solution: Phase 3 already consumed the blob, so we can't re-read.
  # But phase 4 Go command recomputes everything from scratch.
  # It needs: peer AND/Had1 R1 messages, which were consumed in phase 3.
  # We must store them in the session during phase 3!
  #
  # Actually, the Go phase 4 recomputes AND and Had1 internally and only needs
  # the Had2 peer messages + the original peer messages from phase 3.
  # Since the Go recomputes from DCF keys + eta, it just needs the peer messages.
  #
  # Let me store peer_r1 from phase 3 in session:
  ph3_peer <- ss$k2_ws_peer_and_had1_r1
  if (is.null(ph3_peer)) stop("No stored peer AND/Had1 R1 from phase 3")

  tr <- ss$k2_ws_triples
  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 4L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = ss$k2_ws_peer_dcf,
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    t_and_a = tr$and_a, t_and_b = tr$and_b, t_and_c = tr$and_c,
    t_had1_a = tr$had1_a, t_had1_b = tr$had1_b, t_had1_c = tr$had1_c,
    t_had2_a = tr$had2_a, t_had2_b = tr$had2_b, t_had2_c = tr$had2_c,
    p_and_xma = ph3_peer$and_xma, p_and_ymb = ph3_peer$and_ymb,
    p_had1_xma = ph3_peer$had1_xma, p_had1_ymb = ph3_peer$had1_ymb,
    p_had2_xma = peer_r1$had2_xma, p_had2_ymb = peer_r1$had2_ymb))

  # Store mu in session for gradient
  ss$secure_mu_share <- result$mu_share_fp

  # Cleanup
  ss$k2_ws_dcf_keys <- NULL; ss$k2_ws_eta_fp <- NULL
  ss$k2_ws_triples <- NULL; ss$k2_ws_peer_dcf <- NULL
  ss$k2_ws_peer_and_had1_r1 <- NULL; ss$k2_ws_n <- NULL
  gc()

  list(status = "ok", mu_computed = TRUE)
}
