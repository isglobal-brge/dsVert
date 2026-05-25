#' OT-Beaver preprocessing helpers
#'
#' These aggregate methods implement the server-side half of the dealer-free
#' Beaver preprocessing protocol. They are intentionally low-level: the client
#' package orchestrates the two OT directions and then calls the existing
#' Beaver online rounds unchanged.
#'
#' @keywords internal
NULL

.otb_key <- function(beaver_key, suffix) paste0(beaver_key, "_", suffix)

.otb_b64u <- function(x) base64_to_base64url(x)

.otb_b64 <- function(x) .base64url_to_base64(x)

.otb_blob_or_arg <- function(arg, blob_key, ss) {
  if (!is.null(blob_key) && nzchar(blob_key)) {
    val <- .blob_consume(blob_key, ss)
    if (is.null(val)) {
      stop("Missing OT-Beaver blob '", blob_key, "'", call. = FALSE)
    }
    return(.otb_b64(val))
  }
  if (is.null(arg) || !nzchar(arg)) {
    stop("OT-Beaver payload argument or blob key required", call. = FALSE)
  }
  .otb_b64(arg)
}

#' Sample local random OT-Beaver operands
#'
#' @param kind Either \code{"vecmul"} or \code{"matvec"}.
#' @param n Number of rows/elements.
#' @param p Number of columns for \code{"matvec"}.
#' @param ring Integer ring selector, 63 or 127.
#' @param beaver_key Session prefix for this triple batch.
#' @param session_id MPC session id.
#' @return Metadata only; sampled operands remain server-side.
#' @export
k2OtBeaverSampleDS <- function(kind = "vecmul", n, p = 0L, ring = 63L,
                               beaver_key = "k2_ot_beaver",
                               session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-ot-beaver-sample", list(
    kind = as.character(kind), n = as.integer(n), p = as.integer(p),
    ring = ring_tag))
  ss[[.otb_key(beaver_key, "kind")]] <- as.character(kind)
  ss[[.otb_key(beaver_key, "n")]] <- as.integer(n)
  ss[[.otb_key(beaver_key, "p")]] <- as.integer(p)
  ss[[.otb_key(beaver_key, "ring")]] <- ring
  ss[[.otb_key(beaver_key, "a")]] <- res$a
  ss[[.otb_key(beaver_key, "b")]] <- res$b
  if (!is.null(res$b_expanded)) {
    ss[[.otb_key(beaver_key, "b_expanded")]] <- res$b_expanded
  }
  list(stored = TRUE, beaver_key = beaver_key, kind = as.character(kind),
       n = as.integer(n), p = as.integer(p), ring = ring)
}

#' Start an OT multiplication sender transcript
#'
#' @param ot_key Session key prefix for one cross-term direction.
#' @param session_id MPC session id.
#' @return Public sender setup to relay to the receiver.
#' @export
k2OtMulSenderSetupDS <- function(ot_key, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  res <- .callMpcTool("k2-ot-mul-sender-setup", list())
  ss[[.otb_key(ot_key, "secret_setup")]] <- res$secret_setup
  list(public_setup = .otb_b64u(res$public_setup), ot_key = ot_key)
}

#' Prepare OT receiver choices from a stored ring operand
#'
#' @param public_setup Public sender setup, base64url encoded.
#' @param y_key Session key containing the receiver ring operand.
#' @param ot_key Session key prefix for one cross-term direction.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param points_blob_key Optional blob key where points should be stored
#'   instead of returned directly.
#' @param session_id MPC session id.
#' @return Public receiver points to relay to the sender, unless stored as a blob.
#' @export
k2OtMulReceiverChoicesDS <- function(public_setup, y_key, ot_key, n,
                                     ring = 63L, points_blob_key = NULL,
                                     session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  y <- ss[[y_key]]
  if (is.null(y)) stop("Missing OT receiver operand key ", y_key, call. = FALSE)
  ring <- as.integer(ring)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-ot-mul-receiver-choices", list(
    public_setup = .otb_b64(public_setup), y = y,
    n = as.integer(n), ring = ring_tag))
  ss[[.otb_key(ot_key, "choice_bundle")]] <- res$choice_bundle
  points <- .otb_b64u(res$points)
  if (!is.null(points_blob_key) && nzchar(points_blob_key)) {
    .blob_put(points_blob_key, points, ss)
    return(list(stored = TRUE, points_blob_key = points_blob_key))
  }
  list(points = points, ot_key = ot_key)
}

#' Encrypt OT multiplication messages as sender
#'
#' @param points Public receiver points, base64url encoded.
#' @param points_blob_key Optional blob key containing receiver points.
#' @param x_key Session key containing the sender ring operand.
#' @param ot_key Session key prefix for one cross-term direction.
#' @param output_key Session key for this party's sender cross-term share.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param ciphertexts_blob_key Optional blob key where ciphertexts should be
#'   stored instead of returned directly.
#' @param session_id MPC session id.
#' @return Public ciphertexts to relay to the receiver, unless stored as a blob.
#' @export
k2OtMulSenderEncryptDS <- function(points = NULL, points_blob_key = NULL,
                                   x_key, ot_key, output_key, n, ring = 63L,
                                   ciphertexts_blob_key = NULL,
                                   session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  x <- ss[[x_key]]
  if (is.null(x)) stop("Missing OT sender operand key ", x_key, call. = FALSE)
  secret <- ss[[.otb_key(ot_key, "secret_setup")]]
  if (is.null(secret)) stop("Missing OT sender setup for ", ot_key, call. = FALSE)
  ring <- as.integer(ring)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-ot-mul-sender-encrypt", list(
    secret_setup = secret,
    points = .otb_blob_or_arg(points, points_blob_key, ss),
    x = x, n = as.integer(n), ring = ring_tag))
  ss[[output_key]] <- res$sender_share
  cts <- .otb_b64u(res$ciphertexts)
  if (!is.null(ciphertexts_blob_key) && nzchar(ciphertexts_blob_key)) {
    .blob_put(ciphertexts_blob_key, cts, ss)
    return(list(stored = TRUE, ciphertexts_blob_key = ciphertexts_blob_key))
  }
  list(ciphertexts = cts, output_key = output_key)
}

#' Decrypt OT multiplication messages as receiver
#'
#' @param ciphertexts Public sender ciphertexts, base64url encoded.
#' @param ciphertexts_blob_key Optional blob key containing ciphertexts.
#' @param ot_key Session key prefix for one cross-term direction.
#' @param output_key Session key for this party's receiver cross-term share.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
#' @export
k2OtMulReceiverDecryptDS <- function(ciphertexts = NULL,
                                     ciphertexts_blob_key = NULL,
                                     ot_key, output_key, n, ring = 63L,
                                     session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  bundle <- ss[[.otb_key(ot_key, "choice_bundle")]]
  if (is.null(bundle)) stop("Missing OT receiver bundle for ", ot_key, call. = FALSE)
  ring <- as.integer(ring)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-ot-mul-receiver-decrypt", list(
    choice_bundle = bundle,
    ciphertexts = .otb_blob_or_arg(ciphertexts, ciphertexts_blob_key, ss),
    n = as.integer(n), ring = ring_tag))
  ss[[output_key]] <- res$receiver_share
  list(stored = TRUE, output_key = output_key)
}

#' Finalise OT-Beaver shares into the existing online triple slots
#'
#' @param beaver_key Session key prefix produced by
#'   \code{k2OtBeaverSampleDS}.
#' @param target Either \code{"vecmul"} or \code{"grad"}.
#' @param cross_send_key,cross_receive_key Session keys produced by the two OT
#'   directions.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
#' @export
k2OtBeaverFinalizeDS <- function(beaver_key = "k2_ot_beaver",
                                 target = c("vecmul", "grad",
                                            "spline_and", "spline_had1",
                                            "spline_had2"),
                                 cross_send_key = .otb_key(beaver_key, "cross_send"),
                                 cross_receive_key = .otb_key(beaver_key, "cross_receive"),
                                 session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  target <- match.arg(target)
  ss <- .S(session_id)
  kind <- ss[[.otb_key(beaver_key, "kind")]]
  n <- ss[[.otb_key(beaver_key, "n")]]
  p <- ss[[.otb_key(beaver_key, "p")]]
  ring <- ss[[.otb_key(beaver_key, "ring")]]
  a <- ss[[.otb_key(beaver_key, "a")]]
  b <- ss[[.otb_key(beaver_key, "b")]]
  cs <- ss[[cross_send_key]]
  cr <- ss[[cross_receive_key]]
  if (is.null(a) || is.null(b) || is.null(cs) || is.null(cr)) {
    stop("OT-Beaver finalise missing sampled operands or cross shares",
         call. = FALSE)
  }
  ring_tag <- if (as.integer(ring) == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-ot-beaver-finalize", list(
    kind = kind, n = as.integer(n), p = as.integer(p),
    ring = ring_tag, a = a, b = b,
    cross_send = cs, cross_receive = cr))
  if (target == "vecmul") {
    ss$k2_beaver_vecmul_triple <- res$triple_blob
  } else if (target == "grad") {
    ss$k2_grad_a_fp <- res$a
    ss$k2_grad_b_fp <- res$b
    ss$k2_grad_c_fp <- res$c
  } else {
    if (is.null(ss$k2_ws_triples)) ss$k2_ws_triples <- list()
    op <- sub("^spline_", "", target)
    ss$k2_ws_triples[[paste0(op, "_a")]] <- res$a
    ss$k2_ws_triples[[paste0(op, "_b")]] <- res$b
    ss$k2_ws_triples[[paste0(op, "_c")]] <- res$c
  }
  list(stored = TRUE, target = target, beaver_key = beaver_key)
}
