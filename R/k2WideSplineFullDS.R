#' @title K=2 DCF Wide Spline (4-Phase Sigmoid/Exp)
#' @description Piecewise-linear sigmoid/exp evaluation using Distributed
#'   Comparison Functions (DCF) and Beaver triples. All computation in
#'   Ring63 fixed-point.
#' @name k2-wide-spline
NULL

#' Store DCF keys persistently (reused across iterations)
#'
#' Decrypts transport-encrypted DCF keys and stores them in session.
#' Keys are generated server-side by glmRing63GenDcfKeysDS.
#'
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
k2StoreDcfKeysPersistentDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume("k2_dcf_keys_persistent", ss)
  if (is.null(blob)) stop("No persistent DCF keys blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  ss$k2_dcf_keys_persistent <- dec$data
  list(status = "ok")
}

#' Wide spline Phase 1: DCF masked values
#'
#' Computes DCF comparison challenges from eta shares. The masked values
#' are exchanged between DCF parties for phase 2.
#'
#' @param party_id Integer. 0 (fusion) or 1 (coordinator).
#' @param family Character. "binomial" or "poisson".
#' @param num_intervals Integer. Spline intervals (50 sigmoid, 100 exp).
#' @param frac_bits Integer. Fractional bits (default 20 for Ring63;
#'   up to 126 for Ring127, though typically 50).
#' @param ring Integer 63 (default) or 127. Selects the MPC secret-share
#'   ring. Ring127 is selected by the Cox/LMM STRICT closure path (task
#'   #116). When ring == 127, per-element records are 16 bytes (Uint128)
#'   instead of 8 bytes (int64); the downstream Go handler branches on
#'   `ring = "ring127"` in the JSON input.
#' @param session_id Character or NULL.
#' @return List with dcf_masked (base64url).
#' @export
k2WideSplinePhase1DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  ring = 63L, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else if (family == "softplus") 80L else 50L
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  bytes_per_elem <- if (ring == 127L) 16L else 8L
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) eta_fp <- ss$secure_eta_share
  if (is.null(eta_fp)) stop("No eta share in session", call. = FALSE)

  dcf_keys <- ss$k2_dcf_keys_persistent
  if (is.null(dcf_keys)) stop("No DCF keys in session", call. = FALSE)

  n <- as.integer(nchar(.base64url_to_base64(eta_fp)) * 3 / 4 / bytes_per_elem)

  result <- .callMpcTool("k2-wide-spline-full", list(
    phase = 1L, party_id = party_id, family = family,
    eta_share_fp = .base64url_to_base64(eta_fp),
    dcf_keys = dcf_keys, n = n, frac_bits = frac_bits,
    num_intervals = num_intervals, ring = ring_tag))

  ss$k2_ws_dcf_keys <- dcf_keys
  ss$k2_ws_eta_fp <- .base64url_to_base64(eta_fp)
  ss$k2_ws_n <- n
  ss$k2_ws_ring <- ring

  list(dcf_masked = base64_to_base64url(result$dcf_masked))
}

#' Wide spline Phase 2: DCF close + Beaver R1 for AND and Hadamard-1
#' @inheritParams k2WideSplinePhase1DS
#' @return List with and_xma, and_ymb, had1_xma, had1_ymb.
#' @export
k2WideSplinePhase2DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  ring = 63L, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else if (family == "softplus") 80L else 50L
  # Ring defaults to session ring (set by Phase 1); explicit arg overrides.
  if (missing(ring) && !is.null(ss$k2_ws_ring)) ring <- ss$k2_ws_ring
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  peer_dcf <- .blob_consume("k2_peer_dcf_masked", ss)
  if (is.null(peer_dcf)) stop("No peer DCF masked blob", call. = FALSE)

  triple_blob <- .blob_consume("k2_spline_triples", ss)
  if (is.null(triple_blob)) stop("No spline triples blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(triple_blob), recipient_sk = tsk))
  triples <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMpcTool("k2-wide-spline-full", list(
    phase = 2L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = .base64url_to_base64(peer_dcf),
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    ring = ring_tag,
    t_and_a = triples$and_a, t_and_b = triples$and_b, t_and_c = triples$and_c,
    t_had1_a = triples$had1_a, t_had1_b = triples$had1_b, t_had1_c = triples$had1_c,
    t_had2_a = triples$had2_a, t_had2_b = triples$had2_b, t_had2_c = triples$had2_c))

  ss$k2_ws_triples <- triples
  ss$k2_ws_peer_dcf <- .base64url_to_base64(peer_dcf)

  list(and_xma = result$and_xma, and_ymb = result$and_ymb,
       had1_xma = result$had1_xma, had1_ymb = result$had1_ymb)
}

#' Wide spline Phase 3: Close AND+Had1, generate Had2 R1
#' @inheritParams k2WideSplinePhase1DS
#' @return List with had2_xma, had2_ymb.
#' @export
k2WideSplinePhase3DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  ring = 63L, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else if (family == "softplus") 80L else 50L
  if (missing(ring) && !is.null(ss$k2_ws_ring)) ring <- ss$k2_ws_ring
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  peer_blob <- .blob_consume("k2_peer_beaver_r1", ss)
  if (is.null(peer_blob)) stop("No peer Beaver R1 blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  tr <- ss$k2_ws_triples
  result <- .callMpcTool("k2-wide-spline-full", list(
    phase = 3L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = ss$k2_ws_peer_dcf,
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    ring = ring_tag,
    t_and_a = tr$and_a, t_and_b = tr$and_b, t_and_c = tr$and_c,
    t_had1_a = tr$had1_a, t_had1_b = tr$had1_b, t_had1_c = tr$had1_c,
    t_had2_a = tr$had2_a, t_had2_b = tr$had2_b, t_had2_c = tr$had2_c,
    p_and_xma = peer_r1$and_xma, p_and_ymb = peer_r1$and_ymb,
    p_had1_xma = peer_r1$had1_xma, p_had1_ymb = peer_r1$had1_ymb))

  ss$k2_ws_peer_and_had1_r1 <- peer_r1

  list(had2_xma = result$had2_xma, had2_ymb = result$had2_ymb)
}

#' Wide spline Phase 4: Close Had2 + assemble mu shares
#' @inheritParams k2WideSplinePhase1DS
#' @return List with status and mu_computed flag.
#' @export
k2WideSplinePhase4DS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  ring = 63L, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(num_intervals)) num_intervals <- if (family == "poisson") 100L else if (family == "softplus") 80L else 50L
  if (missing(ring) && !is.null(ss$k2_ws_ring)) ring <- ss$k2_ws_ring
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  peer_blob <- .blob_consume("k2_peer_had2_r1", ss)
  if (is.null(peer_blob)) stop("No peer Had2 R1 blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  ph3_peer <- ss$k2_ws_peer_and_had1_r1
  if (is.null(ph3_peer)) stop("No stored peer AND/Had1 R1 from phase 3", call. = FALSE)

  tr <- ss$k2_ws_triples
  result <- .callMpcTool("k2-wide-spline-full", list(
    phase = 4L, party_id = party_id, family = family,
    eta_share_fp = ss$k2_ws_eta_fp, dcf_keys = ss$k2_ws_dcf_keys,
    peer_dcf_masked = ss$k2_ws_peer_dcf,
    n = ss$k2_ws_n, frac_bits = frac_bits, num_intervals = num_intervals,
    ring = ring_tag,
    t_and_a = tr$and_a, t_and_b = tr$and_b, t_and_c = tr$and_c,
    t_had1_a = tr$had1_a, t_had1_b = tr$had1_b, t_had1_c = tr$had1_c,
    t_had2_a = tr$had2_a, t_had2_b = tr$had2_b, t_had2_c = tr$had2_c,
    p_and_xma = ph3_peer$and_xma, p_and_ymb = ph3_peer$and_ymb,
    p_had1_xma = ph3_peer$had1_xma, p_had1_ymb = ph3_peer$had1_ymb,
    p_had2_xma = peer_r1$had2_xma, p_had2_ymb = peer_r1$had2_ymb))

  # Store result: mu share for gradient, or softplus share for deviance
  if (family == "softplus") {
    ss$softplus_share_fp <- result$mu_share_fp
  } else {
    ss$secure_mu_share <- result$mu_share_fp
  }

  # Cleanup intermediate state
  ss$k2_ws_dcf_keys <- NULL; ss$k2_ws_eta_fp <- NULL
  ss$k2_ws_triples <- NULL; ss$k2_ws_peer_dcf <- NULL
  ss$k2_ws_peer_and_had1_r1 <- NULL; ss$k2_ws_n <- NULL

  list(status = "ok", mu_computed = TRUE)
}
