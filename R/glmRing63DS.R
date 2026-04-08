#' @title Ring63 DCF + Beaver Gradient Server Functions for K>=3
#' @description Server-side functions for K>=3 pure Ring63 protocol.
#'   All computation in Ring63 fixed-point with DCF and Beaver. No CKKS.
#' @name glm-ring63-protocol
NULL

# Utility: concatenate Ring63 FP arrays (standard base64)
.concat_fp <- function(...) {
  arrays <- list(...)
  raw_data <- do.call(c, lapply(arrays, function(x) {
    jsonlite::base64_dec(x)
  }))
  gsub("\n", "", jsonlite::base64_enc(raw_data))
}

#' Export own share (complement) to second DCF party
#'
#' After k2ShareInputDS splits features into (own_share, peer_share),
#' this function transport-encrypts the own_share for a different recipient.
#' Used by non-DCF servers to send the complement half to the second DCF party,
#' ensuring both DCF parties together hold additive shares that sum to X_k.
#'
#' @param peer_pk Character. Transport PK of the second DCF party (base64url).
#' @param session_id Character or NULL.
#' @return List with encrypted_own_share (base64url).
#' @export
glmRing63ExportOwnShareDS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  own_fp <- ss$k2_x_share_fp
  if (is.null(own_fp)) stop("No own share in session. Call k2ShareInputDS first.", call. = FALSE)

  pk <- .base64url_to_base64(peer_pk)
  sealed <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(own_fp)),
    recipient_pk = pk))

  list(encrypted_own_share = base64_to_base64url(sealed$sealed))
}

#' Reorder X_full columns to canonical order on fusion party
#'
#' After k2ComputeEtaShareDS, the fusion party's X_full has column order
#' [coord | extras | fusion]. This reorders to canonical [coord | fusion | extras]
#' to match the coordinator's order, ensuring Beaver gradient works correctly.
#'
#' @param p_coord Integer. Number of coordinator features.
#' @param p_fusion Integer. Number of fusion features.
#' @param p_extras Integer. Number of extra (non-DCF) features.
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
glmRing63ReorderXFullDS <- function(p_coord, p_fusion, p_extras, session_id = NULL) {
  ss <- .S(session_id)
  x_full_fp <- ss$k2_x_full_fp
  if (is.null(x_full_fp)) stop("No X_full in session", call. = FALSE)

  p_total <- as.integer(p_coord + p_fusion + p_extras)
  n <- ss$k2_x_n

  # Current order on fusion: [coord(pc) | extras(pe) | fusion(pf)]
  # Target order: [coord(pc) | fusion(pf) | extras(pe)]
  # Build row-major permutation: for each row, reorder columns
  perm <- integer(0)
  for (i in 0:(n - 1)) {
    row_offset <- i * p_total
    # coord columns: stay
    perm <- c(perm, row_offset + (0:(p_coord - 1)))
    # fusion columns: from end of row
    perm <- c(perm, row_offset + (p_coord + p_extras) + (0:(p_fusion - 1)))
    # extras columns: from middle
    if (p_extras > 0)
      perm <- c(perm, row_offset + p_coord + (0:(p_extras - 1)))
  }

  result <- .callMheTool("k2-fp-permute", list(
    fp_data = x_full_fp, perm = as.integer(perm)))

  ss$k2_x_full_fp <- result$fp_data
  list(status = "ok")
}

#' Receive and assemble extra feature shares from non-DCF servers
#'
#' Called on DCF parties to receive feature shares from non-DCF servers.
#' Appends the shares to the peer X matrix for gradient computation.
#'
#' @param extra_key Character. Blob key for the encrypted extra feature share.
#' @param extra_p Integer. Number of features in this share.
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
glmRing63ReceiveExtraShareDS <- function(extra_key, extra_p, session_id = NULL) {
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport SK not stored", call. = FALSE)

  blob <- .blob_consume(extra_key, ss)
  if (is.null(blob)) stop("No blob for key: ", extra_key, call. = FALSE)

  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  extra_fp <- rawToChar(jsonlite::base64_dec(dec$data))

  # Column-concatenate: interleave extra features into peer FP matrix (row-major)
  n <- ss$k2_x_n
  if (!is.null(ss$k2_peer_x_share_fp) && !is.null(ss$k2_peer_p) && ss$k2_peer_p > 0) {
    result <- .callMheTool("k2-fp-column-concat", list(
      a = ss$k2_peer_x_share_fp,
      b = extra_fp,
      n = as.integer(n),
      p_a = as.integer(ss$k2_peer_p),
      p_b = as.integer(extra_p)))
    ss$k2_peer_x_share_fp <- result$result
  } else {
    ss$k2_peer_x_share_fp <- extra_fp
  }

  # Update peer feature count
  if (is.null(ss$k2_peer_p)) ss$k2_peer_p <- 0L
  ss$k2_peer_p <- ss$k2_peer_p + as.integer(extra_p)

  list(stored = TRUE, total_peer_p = ss$k2_peer_p)
}
