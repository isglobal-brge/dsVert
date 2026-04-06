# k2WideSplineFullDS.R: 3-phase wide spline sigmoid evaluation via single Go command.
# Minimizes R intermediation to avoid base64 format corruption.
#
# Phase 1: DCF masked values (needs: eta share + DCF keys)
# Phase 2: DCF close + indicators + Beaver R1 (needs: peer DCF masked + triples)
# Phase 3: Beaver close → mu share (needs: peer Beaver R1 messages)

#' @export
k2WideSplinePhase1DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) eta_fp <- ss$secure_eta_share
  if (is.null(eta_fp)) stop("No eta share in session")

  dcf_keys <- .blob_consume("k2_dcf_keys", ss)
  if (is.null(dcf_keys)) stop("No DCF keys blob")

  n <- as.integer(nchar(.base64url_to_base64(eta_fp)) * 3 / 4 / 8)

  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 1L, party_id = party_id, family = family,
    eta_share_fp = .base64url_to_base64(eta_fp),
    dcf_keys = .base64url_to_base64(dcf_keys),
    n = n, frac_bits = frac_bits, num_intervals = num_intervals
  ))

  # Store DCF keys and eta for phase 2
  ss$k2_wsfull_dcf_keys <- dcf_keys
  ss$k2_wsfull_eta_fp <- eta_fp

  list(dcf_masked = base64_to_base64url(result$dcf_masked))
}

#' @export
k2WideSplinePhase2DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  eta_fp <- ss$k2_wsfull_eta_fp
  dcf_keys <- ss$k2_wsfull_dcf_keys

  # Consume peer DCF masked from blob
  peer_dcf <- .blob_consume("k2_peer_dcf_masked", ss)
  if (is.null(peer_dcf)) stop("No peer DCF masked blob")

  # Consume Beaver triple blobs (3 triples: AND + 2 Hadamard)
  triple_blob <- .blob_consume("k2_spline_triples", ss)
  if (is.null(triple_blob)) stop("No spline triples blob")

  # Decrypt triple blob
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(triple_blob), recipient_sk = tsk))
  triples <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(eta_fp)) * 3 / 4 / 8)

  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 2L, party_id = party_id, family = family,
    eta_share_fp = .base64url_to_base64(eta_fp),
    dcf_keys = .base64url_to_base64(dcf_keys),
    peer_masked = .base64url_to_base64(peer_dcf),
    n = n, frac_bits = frac_bits, num_intervals = num_intervals,
    beaver_and_a = triples$and_a, beaver_and_b = triples$and_b, beaver_and_c = triples$and_c,
    beaver_had1_a = triples$had1_a, beaver_had1_b = triples$had1_b, beaver_had1_c = triples$had1_c,
    beaver_had2_a = triples$had2_a, beaver_had2_b = triples$had2_b, beaver_had2_c = triples$had2_c
  ))

  # Store intermediate state for phase 3
  ss$k2_wsfull_ph2 <- result

  # Return Beaver R1 messages for relay
  list(
    and_xma = base64_to_base64url(result$and_xma),
    and_ymb = base64_to_base64url(result$and_ymb),
    had1_xma = base64_to_base64url(result$had1_xma),
    had1_ymb = base64_to_base64url(result$had1_ymb),
    had2_xma = base64_to_base64url(result$had2_xma),
    had2_ymb = base64_to_base64url(result$had2_ymb)
  )
}

#' @export
k2WideSplinePhase3DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else 50L

  eta_fp <- ss$k2_wsfull_eta_fp
  dcf_keys <- ss$k2_wsfull_dcf_keys
  ph2 <- ss$k2_wsfull_ph2

  # Consume peer Beaver R1 messages from blob
  peer_blob <- .blob_consume("k2_peer_beaver_r1", ss)
  if (is.null(peer_blob)) stop("No peer Beaver R1 blob")
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  n <- as.integer(nchar(.base64url_to_base64(eta_fp)) * 3 / 4 / 8)

  # Call phase 3: Beaver close + assembly
  result <- .callMheTool("k2-wide-spline-full", list(
    phase = 3L, party_id = party_id, family = family,
    eta_share_fp = .base64url_to_base64(eta_fp),
    dcf_keys = .base64url_to_base64(dcf_keys),
    peer_masked = .base64url_to_base64(ss$k2_wsfull_peer_dcf %||% ""),
    n = n, frac_bits = frac_bits, num_intervals = num_intervals,
    beaver_and_a = ph2$beaver_and_a %||% "", beaver_and_b = ph2$beaver_and_b %||% "",
    beaver_and_c = ph2$beaver_and_c %||% "",
    beaver_had1_a = ph2$beaver_had1_a %||% "", beaver_had1_b = ph2$beaver_had1_b %||% "",
    beaver_had1_c = ph2$beaver_had1_c %||% "",
    beaver_had2_a = ph2$beaver_had2_a %||% "", beaver_had2_b = ph2$beaver_had2_b %||% "",
    beaver_had2_c = ph2$beaver_had2_c %||% "",
    peer_and_xma = peer_r1$and_xma, peer_and_ymb = peer_r1$and_ymb,
    peer_had1_xma = peer_r1$had1_xma, peer_had1_ymb = peer_r1$had1_ymb,
    peer_had2_xma = peer_r1$had2_xma, peer_had2_ymb = peer_r1$had2_ymb
  ))

  # Store mu share
  ss$secure_mu_share <- result$mu_share_fp

  # Cleanup
  ss$k2_wsfull_dcf_keys <- NULL
  ss$k2_wsfull_eta_fp <- NULL
  ss$k2_wsfull_ph2 <- NULL
  gc()

  list(status = "ok", mu_computed = TRUE)
}
