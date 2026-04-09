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

#' Initialize transport keys only (no CKKS)
#'
#' Lightweight alternative to mheInitDS for Ring63 protocols.
#' Only generates X25519 transport keypair. No CKCS secret key,
#' no CRP, no Galois key generation.
#'
#' @param session_id Character or NULL.
#' @return List with transport_pk (base64url).
#' @export
glmRing63TransportInitDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  transport <- .callMheTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)
  list(transport_pk = base64_to_base64url(transport$public_key))
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

#' Generate DCF keys on server and distribute to DCF parties
#'
#' Called on a NON-DCF server to generate DCF keys securely.
#' The client never sees the key values — only opaque transport-encrypted blobs.
#' This prevents a malicious client from crafting DCF keys to leak information.
#'
#' @param dcf0_pk,dcf1_pk Character. Transport PKs of DCF parties (base64url).
#' @param family Character. "sigmoid" or "poisson".
#' @param n Integer. Number of observations.
#' @param frac_bits Integer. Fractional bits for Ring63 FP.
#' @param num_intervals Integer. Number of spline intervals.
#' @param session_id Character or NULL.
#' @return List with encrypted blobs for each DCF party.
#' @export
glmRing63GenDcfKeysDS <- function(dcf0_pk, dcf1_pk, family, n, frac_bits,
                                   num_intervals, session_id = NULL) {
  dcf <- .callMheTool("k2-dcf-gen-batch", list(
    family = family, n = as.integer(n),
    frac_bits = as.integer(frac_bits),
    num_intervals = as.integer(num_intervals)))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  sealed0 <- .callMheTool("transport-encrypt", list(
    data = dcf$party0_keys, recipient_pk = pk0))
  sealed1 <- .callMheTool("transport-encrypt", list(
    data = dcf$party1_keys, recipient_pk = pk1))

  list(
    dcf_blob_0 = base64_to_base64url(sealed0$sealed),
    dcf_blob_1 = base64_to_base64url(sealed1$sealed)
  )
}

#' Generate spline Beaver triples on server and distribute to DCF parties
#'
#' Generates 3 sets of Beaver triples (AND, Hadamard1, Hadamard2) for the
#' DCF wide spline protocol. Transport-encrypts each party's shares.
#' The client never sees the triple values.
#'
#' @param dcf0_pk,dcf1_pk Character. Transport PKs of DCF parties (base64url).
#' @param n Integer. Number of observations.
#' @param frac_bits Integer. Fractional bits.
#' @param session_id Character or NULL.
#' @return List with encrypted blobs for each DCF party.
#' @export
glmRing63GenSplineTriplesDS <- function(dcf0_pk, dcf1_pk, n, frac_bits,
                                         session_id = NULL) {
  triples <- lapply(1:3, function(i)
    .callMheTool("k2-gen-beaver-triples",
      list(n = as.integer(n), frac_bits = as.integer(frac_bits))))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  # Pack party 0's shares
  td0 <- list()
  td1 <- list()
  for (op in c("and", "had1", "had2")) {
    ti <- switch(op, and = 1, had1 = 2, had2 = 3)
    td0[[paste0(op, "_a")]] <- triples[[ti]]$party0_u
    td0[[paste0(op, "_b")]] <- triples[[ti]]$party0_v
    td0[[paste0(op, "_c")]] <- triples[[ti]]$party0_w
    td1[[paste0(op, "_a")]] <- triples[[ti]]$party1_u
    td1[[paste0(op, "_b")]] <- triples[[ti]]$party1_v
    td1[[paste0(op, "_c")]] <- triples[[ti]]$party1_w
  }

  sealed0 <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(
      jsonlite::toJSON(td0, auto_unbox = TRUE))),
    recipient_pk = pk0))
  sealed1 <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(
      jsonlite::toJSON(td1, auto_unbox = TRUE))),
    recipient_pk = pk1))

  list(
    spline_blob_0 = base64_to_base64url(sealed0$sealed),
    spline_blob_1 = base64_to_base64url(sealed1$sealed)
  )
}

#' Generate gradient matvec Beaver triples on server and distribute
#'
#' Generates Beaver triples for the gradient matrix-vector multiplication.
#' Transport-encrypts each party's shares. Client never sees the values.
#'
#' @param dcf0_pk,dcf1_pk Character. Transport PKs of DCF parties (base64url).
#' @param n Integer. Number of observations.
#' @param p Integer. Total number of features.
#' @param session_id Character or NULL.
#' @return List with encrypted blobs for each DCF party.
#' @export
glmRing63GenGradTriplesDS <- function(dcf0_pk, dcf1_pk, n, p,
                                       session_id = NULL) {
  mvt <- .callMheTool("k2-gen-matvec-triples", list(
    n = as.integer(n), p = as.integer(p)))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  sealed0 <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
      a = mvt$party0_a, b = mvt$party0_b, c = mvt$party0_c),
      auto_unbox = TRUE))),
    recipient_pk = pk0))
  sealed1 <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
      a = mvt$party1_a, b = mvt$party1_b, c = mvt$party1_c),
      auto_unbox = TRUE))),
    recipient_pk = pk1))

  list(
    grad_blob_0 = base64_to_base64url(sealed0$sealed),
    grad_blob_1 = base64_to_base64url(sealed1$sealed)
  )
}

#' Secure deviance Phase 1: compute Beaver-masked residual
#'
#' Computes d = r_share - a (masked residual for Beaver dot-product)
#' and local sum Σ r_share_i². The cross-term is computed in Phase 2.
#' Total deviance D = Σ r² = Σ r_0² + 2·cross + Σ r_1² (1 scalar).
#'
#' @param party_id Integer. 0 or 1.
#' @param session_id Character or NULL.
#' @return List with dma_fp and local_sum_fp.
#' @export
glmRing63DevianceR1DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- .base64url_to_base64(ss$secure_mu_share)
  y_fp <- .base64url_to_base64(ss$k2_y_share_fp)
  if (is.null(mu_fp) || is.null(y_fp)) stop("No mu/y shares for deviance", call. = FALSE)

  blob <- .blob_consume("k2_deviance_triple", ss)
  if (is.null(blob)) stop("No deviance triple", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-secure-deviance", list(
    mu_share_fp = mu_fp, y_share_fp = y_fp,
    a_share_fp = triple$a, b_share_fp = triple$b,
    c_share_fp = "", peer_dma_fp = "",
    party_id = as.integer(party_id), phase = 1L))

  ss$k2_dev_triple <- triple  # store for phase 2
  list(dma_fp = result$dma_fp, local_sum_fp = result$local_sum_fp)
}

#' Secure deviance Phase 2: Beaver close for cross-term
#' @param party_id Integer. 0 or 1.
#' @param session_id Character or NULL.
#' @return List with cross_sum_fp.
#' @export
glmRing63DevianceR2DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)
  mu_fp <- .base64url_to_base64(ss$secure_mu_share)
  y_fp <- .base64url_to_base64(ss$k2_y_share_fp)
  triple <- ss$k2_dev_triple

  peer_blob <- .blob_consume("k2_dev_peer_dma", ss)
  if (is.null(peer_blob)) stop("No peer deviance R1", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_blob), recipient_sk = tsk))
  peer_dma <- dec$data  # base64 FP data (not string — binary)

  result <- .callMheTool("k2-secure-deviance", list(
    mu_share_fp = mu_fp, y_share_fp = y_fp,
    a_share_fp = triple$a, b_share_fp = triple$b,
    c_share_fp = triple$c, peer_dma_fp = peer_dma,
    party_id = as.integer(party_id), phase = 2L))

  ss$k2_dev_triple <- NULL
  list(cross_sum_fp = result$cross_sum_fp)
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
