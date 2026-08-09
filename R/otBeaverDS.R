#' OT-Beaver preprocessing helpers
#'
#' These aggregate methods implement the server-side half of the IKNP
#' Beaver-preprocessing profile. They are intentionally low-level: the client
#' package orchestrates the two IKNP directions and then calls the existing
#' Beaver online rounds unchanged.
#'
#' @name otBeaverDS
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
k2OtBeaverSampleDS <- function(kind = "vecmul", n, p = 0L, ring = 63L,
                               beaver_key = "k2_ot_beaver",
                               session_id = NULL) {
  .dsvert_require_beaver_mode("iknp")
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
#' @keywords internal
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
#' @keywords internal
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
#' @keywords internal
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
#' @keywords internal
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

#' Start an IKNP base-OT receiver transcript
#'
#' @param iknp_key Session key prefix for the reusable IKNP base-OT state.
#' @param session_id MPC session id.
#' @return Public base setup to relay to the IKNP sender.
k2IknpBaseReceiverSetupDS <- function(iknp_key, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  res <- .callMpcTool("k2-iknp-base-receiver-setup", list())
  ss[[.otb_key(iknp_key, "receiver_state")]] <- res$receiver_state
  list(public_setup = .otb_b64u(res$public_setup), iknp_key = iknp_key)
}

#' Prepare IKNP base-OT sender choices
#'
#' @param public_setup Public setup from \code{k2IknpBaseReceiverSetupDS}.
#' @param iknp_key Session key prefix.
#' @param recipient_pk Verified base64url transport public key of the IKNP
#'   base receiver.
#' @param ring Integer ring selector, 63 or 127.
#' @param session_id MPC session id.
#' @return Public base points to relay to the IKNP receiver.
k2IknpBaseSenderChoicesDS <- function(public_setup, iknp_key, recipient_pk,
                                      ring = 63L, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(recipient_pk, ss, "IKNP base receiver")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  request <- list(
    public_setup = public_setup, iknp_key = iknp_key,
    recipient_pk = recipient_pk, ring = as.integer(ring))
  replay <- .dsvert_typed_blob_operation_replay(
    ss, "k2IknpBaseSenderChoicesDS", request)
  if (isTRUE(replay$hit)) return(replay$result)
  res <- .callMpcTool("k2-iknp-base-sender-choices", list(
    public_setup = .otb_b64(public_setup)))
  ss[[.otb_key(iknp_key, "sender_state")]] <- res$sender_state
  points <- .otb_b64u(res$points)
  result <- list(
    points = points, iknp_key = iknp_key,
    points_transfer = .dsvert_typed_blob_mint(
      ss, session_id, "blob.iknp.base-points.v1", recipient_pk, points,
      list(operation = iknp_key, n = 128L, ring = as.integer(ring)),
      producer = "k2IknpBaseSenderChoicesDS"))
  .dsvert_typed_blob_operation_commit(
    ss, "k2IknpBaseSenderChoicesDS", request, result)
}

#' Encrypt IKNP base-OT receiver labels
#'
#' @param points Public base points.
#' @param points_blob_key Optional blob key containing the points.
#' @param iknp_key Session key prefix.
#' @param producer_name Verified logical name of the peer that sent the typed
#'   base-points transfer.
#' @param recipient_pk Verified base64url transport public key of the IKNP
#'   base sender.
#' @param ring Integer ring selector, 63 or 127.
#' @param ciphertexts_blob_key Optional blob key where ciphertexts should be
#'   stored instead of returned directly.
#' @param session_id MPC session id.
#' @return Public base ciphertexts to relay to the IKNP sender.
k2IknpBaseReceiverEncryptDS <- function(points = NULL,
                                        points_blob_key = NULL,
                                        iknp_key,
                                        producer_name = NULL,
                                        recipient_pk,
                                        ring = 63L,
                                        ciphertexts_blob_key = NULL,
                                        session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(recipient_pk, ss, "IKNP base sender")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  if (!is.null(points_blob_key)) {
    stop("Legacy IKNP points blob keys are retired", call. = FALSE)
  }
  request <- NULL
  if (is.null(ciphertexts_blob_key) || !nzchar(ciphertexts_blob_key)) {
    request <- list(
      points = points, iknp_key = iknp_key,
      producer_name = producer_name, recipient_pk = recipient_pk,
      ring = as.integer(ring))
    replay <- .dsvert_typed_blob_operation_replay(
      ss, "k2IknpBaseReceiverEncryptDS", request)
    if (isTRUE(replay$hit)) return(replay$result)
  }
  if (is.null(points)) {
    points <- .dsvert_typed_blob_consume(
      ss, "blob.iknp.base-points.v1",
      list(operation = iknp_key, n = 128L, ring = as.integer(ring)),
      sender_name = producer_name)
  }
  state <- ss[[.otb_key(iknp_key, "receiver_state")]]
  if (is.null(state)) stop("Missing IKNP receiver state for ", iknp_key,
                           call. = FALSE)
  res <- .callMpcTool("k2-iknp-base-receiver-encrypt", list(
    receiver_state = state,
    points = .otb_b64(points)))
  cts <- .otb_b64u(res$ciphertexts)
  if (!is.null(ciphertexts_blob_key) && nzchar(ciphertexts_blob_key)) {
    .blob_put(ciphertexts_blob_key, cts, ss)
    return(list(stored = TRUE, ciphertexts_blob_key = ciphertexts_blob_key))
  }
  result <- list(
    ciphertexts = cts, iknp_key = iknp_key,
    ciphertexts_transfer = .dsvert_typed_blob_mint(
      ss, session_id, "blob.iknp.base-ciphertexts.v1", recipient_pk, cts,
      list(operation = iknp_key, n = 128L, ring = as.integer(ring)),
      producer = "k2IknpBaseReceiverEncryptDS"))
  .dsvert_typed_blob_operation_commit(
    ss, "k2IknpBaseReceiverEncryptDS", request, result)
}

#' Finalise IKNP base-OT sender state
#'
#' @param ciphertexts Public base ciphertexts.
#' @param ciphertexts_blob_key Optional blob key containing ciphertexts.
#' @param iknp_key Session key prefix.
#' @param producer_name Verified logical name of the peer that sent the typed
#'   base-ciphertexts transfer.
#' @param ring Integer ring selector, 63 or 127.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
k2IknpBaseSenderFinalizeDS <- function(ciphertexts = NULL,
                                       ciphertexts_blob_key = NULL,
                                       iknp_key,
                                       producer_name = NULL,
                                       ring = 63L,
                                       session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (!is.null(ciphertexts_blob_key)) {
    stop("Legacy IKNP base-ciphertext blob keys are retired", call. = FALSE)
  }
  if (is.null(ciphertexts)) {
    ciphertexts <- .dsvert_typed_blob_consume(
      ss, "blob.iknp.base-ciphertexts.v1",
      list(operation = iknp_key, n = 128L, ring = as.integer(ring)),
      sender_name = producer_name)
  }
  state <- ss[[.otb_key(iknp_key, "sender_state")]]
  if (is.null(state)) stop("Missing IKNP sender state for ", iknp_key,
                           call. = FALSE)
  res <- .callMpcTool("k2-iknp-base-sender-finalize", list(
    sender_state = state,
    ciphertexts = .otb_b64(ciphertexts)))
  ss[[.otb_key(iknp_key, "sender_state")]] <- res$sender_state
  list(stored = TRUE, iknp_key = iknp_key)
}

#' Extend IKNP receiver choices from a stored ring operand
#'
#' @param y_key Session key containing the receiver ring operand.
#' @param iknp_key Session key prefix for this extension transcript.
#' @param base_key Session key prefix for the reusable IKNP base-OT state.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param recipient_pk Verified base64url transport public key of the IKNP
#'   extension sender.
#' @param u_matrix_blob_key Optional blob key where the public U matrix should
#'   be stored instead of returned directly.
#' @param session_id MPC session id.
#' @return Public U matrix to relay to the IKNP sender.
k2IknpReceiverExtendDS <- function(y_key, iknp_key, n, ring = 63L,
                                   base_key = iknp_key,
                                   recipient_pk,
                                   u_matrix_blob_key = NULL,
                                   session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(recipient_pk, ss, "IKNP extension sender")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  request <- NULL
  if (is.null(u_matrix_blob_key) || !nzchar(u_matrix_blob_key)) {
    request <- list(
      y_key = y_key, iknp_key = iknp_key, n = as.integer(n),
      ring = as.integer(ring), base_key = base_key,
      recipient_pk = recipient_pk)
    replay <- .dsvert_typed_blob_operation_replay(
      ss, "k2IknpReceiverExtendDS", request)
    if (isTRUE(replay$hit)) return(replay$result)
  }
  state <- ss[[.otb_key(base_key, "receiver_state")]]
  if (is.null(state)) stop("Missing IKNP receiver state for ", base_key,
                           call. = FALSE)
  y <- ss[[y_key]]
  if (is.null(y)) stop("Missing IKNP receiver operand key ", y_key,
                       call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-iknp-receiver-extend", list(
    receiver_state = state, y = y, n = as.integer(n), ring = ring_tag,
    domain = iknp_key))
  ss[[.otb_key(iknp_key, "receiver_extend_state")]] <-
    res$receiver_extend_state
  u <- .otb_b64u(res$u_matrix)
  # KOS15/SoftSpoken consistency-check opener (see k2_iknp_kos.go); relayed to
  # the sender alongside the U matrix so no extra round is needed.
  kos_check <- if (!is.null(res$kos_check) && nzchar(res$kos_check)) {
    .otb_b64u(res$kos_check)
  } else {
    NULL
  }
  if (!is.null(u_matrix_blob_key) && nzchar(u_matrix_blob_key)) {
    .blob_put(u_matrix_blob_key, u, ss)
    return(list(stored = TRUE, u_matrix_blob_key = u_matrix_blob_key,
                kos_check = kos_check))
  }
  result <- list(
    u_matrix = u, iknp_key = iknp_key, kos_check = kos_check,
    u_matrix_transfer = .dsvert_typed_blob_mint(
      ss, session_id, "blob.iknp.u-matrix.v1", recipient_pk, u,
      list(operation = iknp_key, n = as.integer(n), ring = ring),
      producer = "k2IknpReceiverExtendDS"))
  .dsvert_typed_blob_operation_commit(
    ss, "k2IknpReceiverExtendDS", request, result)
}

#' Encrypt IKNP multiplication messages as sender
#'
#' @param u_matrix Public receiver U matrix.
#' @param u_matrix_blob_key Optional blob key containing the U matrix.
#' @param x_key Session key containing the sender ring operand.
#' @param iknp_key Session key prefix for this extension transcript.
#' @param base_key Session key prefix for the reusable IKNP base-OT state.
#' @param output_key Session key for this party's sender cross-term share.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param producer_name Verified logical name of the peer that sent the typed
#'   U-matrix transfer.
#' @param recipient_pk Verified base64url transport public key of the IKNP
#'   extension receiver.
#' @param ciphertexts_blob_key Optional blob key where ciphertexts should be
#'   stored instead of returned directly.
#' @param kos_check Required base64url KOS15/SoftSpoken consistency-check opener
#'   produced by \code{k2IknpReceiverExtendDS}. The OT extension aborts if the
#'   opener is absent or the receiver used inconsistent choice bits.
#' @param session_id MPC session id.
#' @return Public ciphertexts to relay to the receiver.
k2IknpSenderEncryptDS <- function(u_matrix = NULL, u_matrix_blob_key = NULL,
                                  x_key, iknp_key, output_key, n,
                                  ring = 63L,
                                  base_key = iknp_key,
                                  producer_name = NULL,
                                  recipient_pk,
                                  ciphertexts_blob_key = NULL,
                                  kos_check = NULL,
                                  session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(recipient_pk, ss, "IKNP extension receiver")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  if (!is.null(u_matrix_blob_key)) {
    stop("Legacy IKNP U-matrix blob keys are retired", call. = FALSE)
  }
  request <- NULL
  if (is.null(ciphertexts_blob_key) || !nzchar(ciphertexts_blob_key)) {
    request <- list(
      u_matrix = u_matrix, x_key = x_key, iknp_key = iknp_key,
      output_key = output_key, n = as.integer(n), ring = as.integer(ring),
      base_key = base_key, producer_name = producer_name,
      recipient_pk = recipient_pk, kos_check = kos_check)
    replay <- .dsvert_typed_blob_operation_replay(
      ss, "k2IknpSenderEncryptDS", request)
    if (isTRUE(replay$hit)) return(replay$result)
  }
  if (is.null(u_matrix)) {
    u_matrix <- .dsvert_typed_blob_consume(
      ss, "blob.iknp.u-matrix.v1",
      list(operation = iknp_key, n = as.integer(n), ring = as.integer(ring)),
      sender_name = producer_name)
  }
  state <- ss[[.otb_key(base_key, "sender_state")]]
  if (is.null(state)) stop("Missing IKNP sender state for ", base_key,
                           call. = FALSE)
  x <- ss[[x_key]]
  if (is.null(x)) stop("Missing IKNP sender operand key ", x_key,
                       call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  # KOS15 opener: convert the relayed base64url opener back to std base64 for
  # the Go kernel, which aborts if the receiver's choice bits were inconsistent.
  # SERVER-AUTHORITATIVE anti-downgrade: the opener is mandatory. A receiver or
  # relay cannot select an unchecked legacy OT path.
  have_kos <- !is.null(kos_check) && nzchar(kos_check)
  if (!have_kos) {
    stop("DSVERT_KOS_REQUIRED: IKNP KOS consistency-check opener missing; ",
         "unchecked OT is not supported.", call. = FALSE)
  }
  kos_arg <- .otb_b64(kos_check)
  res <- .callMpcTool("k2-iknp-sender-encrypt", list(
    sender_state = state,
    u_matrix = .otb_b64(u_matrix),
    x = x, n = as.integer(n), ring = ring_tag, domain = iknp_key,
    kos_check = kos_arg))
  ss[[output_key]] <- res$sender_share
  cts <- .otb_b64u(res$ciphertexts)
  if (!is.null(ciphertexts_blob_key) && nzchar(ciphertexts_blob_key)) {
    .blob_put(ciphertexts_blob_key, cts, ss)
    return(list(stored = TRUE, ciphertexts_blob_key = ciphertexts_blob_key))
  }
  result <- list(
    ciphertexts = cts, output_key = output_key,
    ciphertexts_transfer = .dsvert_typed_blob_mint(
      ss, session_id, "blob.iknp.ciphertexts.v1", recipient_pk, cts,
      list(operation = iknp_key, n = as.integer(n), ring = ring),
      producer = "k2IknpSenderEncryptDS"))
  .dsvert_typed_blob_operation_commit(
    ss, "k2IknpSenderEncryptDS", request, result)
}

#' Decrypt IKNP multiplication messages as receiver
#'
#' @param ciphertexts Public sender ciphertexts.
#' @param ciphertexts_blob_key Optional blob key containing ciphertexts.
#' @param iknp_key Session key prefix.
#' @param output_key Session key for this party's receiver cross-term share.
#' @param n Operand length.
#' @param ring Integer ring selector, 63 or 127.
#' @param producer_name Verified logical name of the peer that sent the typed
#'   ciphertext transfer.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
k2IknpReceiverDecryptDS <- function(ciphertexts = NULL,
                                    ciphertexts_blob_key = NULL,
                                    iknp_key, output_key, n,
                                    ring = 63L,
                                    producer_name = NULL,
                                    session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (!is.null(ciphertexts_blob_key)) {
    stop("Legacy IKNP ciphertext blob keys are retired", call. = FALSE)
  }
  if (is.null(ciphertexts)) {
    ciphertexts <- .dsvert_typed_blob_consume(
      ss, "blob.iknp.ciphertexts.v1",
      list(operation = iknp_key, n = as.integer(n), ring = as.integer(ring)),
      sender_name = producer_name)
  }
  state <- ss[[.otb_key(iknp_key, "receiver_extend_state")]]
  if (is.null(state)) {
    stop("Missing IKNP receiver extension state for ", iknp_key,
         call. = FALSE)
  }
  ring <- as.integer(ring)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  res <- .callMpcTool("k2-iknp-receiver-decrypt", list(
    receiver_extend_state = state,
    ciphertexts = .otb_b64(ciphertexts),
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
