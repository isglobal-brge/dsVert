#' @title Ring63 DCF + Beaver Gradient Server Functions for K>=3
#' @description Server-side functions for K>=3 pure Ring63 protocol.
#'   All computation in Ring63 fixed-point with DCF and Beaver.
#' @name glm-ring63-protocol
NULL

#' Initialize transport keys with Ed25519 identity
#'
#' Generates X25519 transport keypair + signs it with the server's
#' persistent Ed25519 identity key for pinned peer verification.
#'
#' @param session_id Character or NULL.
#' @return List with transport_pk, identity_pk, signature (all base64url).
#' @export
glmRing63TransportInitDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  transport <- .callMpcTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)

  # Ed25519 identity: derive keypair, sign transport PK
  identity <- .get_identity_keypair()
  .key_put("identity_pk", identity$identity_pk, ss)
  signature <- .sign_transport_pk(transport$public_key, identity$identity_sk)

  list(
    transport_pk = base64_to_base64url(transport$public_key),
    identity_pk  = base64_to_base64url(identity$identity_pk),
    signature    = base64_to_base64url(signature)
  )
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
  sealed <- .callMpcTool("transport-encrypt", list(
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
    if (p_coord > 0)
      perm <- c(perm, row_offset + (0:(p_coord - 1)))
    # fusion columns: from end of row
    if (p_fusion > 0)
      perm <- c(perm, row_offset + (p_coord + p_extras) + (0:(p_fusion - 1)))
    # extras columns: from middle
    if (p_extras > 0)
      perm <- c(perm, row_offset + p_coord + (0:(p_extras - 1)))
  }

  result <- .callMpcTool("k2-fp-permute", list(
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
#' @param ring Integer 63 (default) or 127. Selects secret-share ring
#'   (task #116 Cox/LMM STRICT migration). Ring127 emits 16-byte DCF
#'   key records for the Uint128 pipeline; Ring63 keeps the 8-byte records.
#' @param session_id Character or NULL.
#' @return List with encrypted blobs for each DCF party.
#' @export
glmRing63GenDcfKeysDS <- function(dcf0_pk, dcf1_pk, family, n, frac_bits,
                                   num_intervals, ring = 63L,
                                   session_id = NULL) {
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  dcf <- .callMpcTool("k2-dcf-gen-batch", list(
    family = family, n = as.integer(n),
    frac_bits = as.integer(frac_bits),
    num_intervals = as.integer(num_intervals),
    ring = ring_tag))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  sealed0 <- .callMpcTool("transport-encrypt", list(
    data = dcf$party0_keys, recipient_pk = pk0))
  sealed1 <- .callMpcTool("transport-encrypt", list(
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
#' @param ring Integer 63 (default) or 127. Ring127 emits 16-byte Uint128
#'   triple shares (task #116 Cox/LMM).
#' @param session_id Character or NULL.
#' @return List with encrypted blobs for each DCF party.
#' @export
glmRing63GenSplineTriplesDS <- function(dcf0_pk, dcf1_pk, n, frac_bits,
                                         ring = 63L, session_id = NULL) {
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  triples <- lapply(1:3, function(i)
    .callMpcTool("k2-gen-beaver-triples",
      list(n = as.integer(n), frac_bits = as.integer(frac_bits),
           ring = ring_tag)))

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

  sealed0 <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(
      jsonlite::toJSON(td0, auto_unbox = TRUE))),
    recipient_pk = pk0))
  sealed1 <- .callMpcTool("transport-encrypt", list(
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
                                       ring = 63L, session_id = NULL) {
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  mvt <- .callMpcTool("k2-gen-matvec-triples", list(
    n = as.integer(n), p = as.integer(p),
    ring = ring_tag))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  sealed0 <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
      a = mvt$party0_a, b = mvt$party0_b, c = mvt$party0_c),
      auto_unbox = TRUE))),
    recipient_pk = pk0))
  sealed1 <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
      a = mvt$party1_a, b = mvt$party1_b, c = mvt$party1_c),
      auto_unbox = TRUE))),
    recipient_pk = pk1))

  list(
    grad_blob_0 = base64_to_base64url(sealed0$sealed),
    grad_blob_1 = base64_to_base64url(sealed1$sealed)
  )
}

#' Prepare deviance: store residual as 1-column X matrix for Beaver Σr²
#'
#' After convergence, computes r = mu_share - y_share in Ring63 and stores
#' as k2_x_full_fp (n×1 "matrix"). Then the standard k2GradientR1DS/R2DS
#' with p=1 triples computes "gradient" = r^T × r = Σ r_i² (deviance).
#'
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
glmRing63PrepDevianceDS <- function(mode = "rss", session_id = NULL) {
  ss <- .S(session_id)

  if (mode == "canonical") {
    # Canonical deviance: Beaver computes eta^T * y
    # gradient uses residual = mu_share - y_share
    # We set: x_full = eta, mu_share = y, y_share = 0 → residual = y - 0 = y
    eta_fp <- ss$k2_eta_share_fp
    if (is.null(eta_fp)) stop("No eta shares for canonical deviance", call. = FALSE)
    ss$k2_x_full_fp <- eta_fp
    ss$k2_x_p <- 1L
    ss$k2_peer_p <- 0L
    # Save and replace: mu = y, y = 0
    n <- ss$k2_x_n
    zero <- .callMpcTool("k2-float-to-fp", list(values = rep(0, n), frac_bits = 20L))
    ss$secure_mu_share <- ss$k2_y_share_fp  # mu = y
    ss$k2_y_share_fp <- zero$fp_data        # y = 0
    list(status = "ok")
  } else {
    # RSS deviance (default): store r = mu - y as x_full
    mu_fp <- .base64url_to_base64(ss$secure_mu_share)
    y_fp <- .base64url_to_base64(ss$k2_y_share_fp)
    if (is.null(mu_fp) || is.null(y_fp))
      stop("No mu/y shares for deviance", call. = FALSE)
    r <- .callMpcTool("k2-fp-sub", list(a = mu_fp, b = y_fp, frac_bits = 20L))
    ss$k2_x_full_fp <- r$result
    ss$k2_x_p <- 1L
    ss$k2_peer_p <- 0L
    list(status = "ok")
  }
}

#' Compute scalar sums for canonical deviance
#'
#' Returns Ring63 scalar sums needed by the client to assemble canonical deviance.
#' Uses the Go binary for Ring63 summation (avoids R integer overflow).
#'
#' @param family Character. "binomial" or "poisson".
#' @param session_id Character or NULL.
#' @return List with sum_fp (Ring63 scalar as base64) and optionally
#'   null_term (plaintext constant for Poisson).
#' @export
glmRing63DevianceSumsDS <- function(family, session_id = NULL) {
  ss <- .S(session_id)

  if (family == "binomial") {
    # Sum of softplus(eta) shares — spline must have been evaluated already
    sp_fp <- ss$softplus_share_fp
    if (is.null(sp_fp))
      stop("Softplus shares not computed. Run softplus spline first.", call. = FALSE)
    r <- .callMpcTool("k2-fp-sum", list(fp_data = sp_fp))
    list(sum_fp = r$sum_fp)

  } else if (family == "poisson") {
    # Sum of mu shares (from last exp spline evaluation)
    mu_fp <- .base64url_to_base64(ss$secure_mu_share)
    r <- .callMpcTool("k2-fp-sum", list(fp_data = mu_fp))

    # Null term: label server computes Σ(y*log(y) - y) in plaintext
    null_term <- 0
    if (!is.null(ss$k2_y_raw)) {
      y <- ss$k2_y_raw
      valid <- y > 0
      null_term <- sum(y[valid] * log(y[valid])) - sum(y)
    }
    list(sum_fp = r$sum_fp, null_term = null_term)

  } else {
    list(sum_fp = NULL)
  }
}

#' Set y_share to zeros (for correlation: no response variable)
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
glmRing63CorSetZeroYDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  zero <- .callMpcTool("k2-float-to-fp", list(values = rep(0, n), frac_bits = 20L))
  ss$k2_y_share_fp <- zero$fp_data
  list(status = "ok")
}

#' Set column j of X_full as "mu" for Beaver correlation
#' Extracts column col_idx from k2_x_full_fp, stores as secure_mu_share.
#' Combined with zero y, the "residual" = col_j, and Beaver computes X^T × col_j.
#' @param col_idx Integer (0-indexed). Column to extract.
#' @param p_total Integer. Total number of columns.
#' @param session_id Character or NULL.
#' @return List with status.
#' @export
glmRing63CorSetColDS <- function(col_idx = NULL, p_total = NULL,
                                  from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  if (isTRUE(from_storage)) {
    params <- .blob_consume("cor_col_params", ss)
    if (!is.null(params)) {
      parts <- strsplit(params, ",")[[1]]
      col_idx <- as.integer(parts[1])
      p_total <- as.integer(parts[2])
    }
  }
  n <- ss$k2_x_n
  x_full <- ss$k2_x_full_fp
  if (is.null(x_full)) stop("No X_full in session", call. = FALSE)

  col_perm <- as.integer(seq(col_idx, n * p_total - 1L, by = p_total))
  col_fp <- .callMpcTool("k2-fp-permute", list(fp_data = x_full, perm = col_perm))

  ss$secure_mu_share <- col_fp$fp_data
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

  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  extra_fp <- rawToChar(jsonlite::base64_dec(dec$data))

  # Column-concatenate: interleave extra features into peer FP matrix (row-major)
  n <- ss$k2_x_n
  if (!is.null(ss$k2_peer_x_share_fp) && !is.null(ss$k2_peer_p) && ss$k2_peer_p > 0) {
    result <- .callMpcTool("k2-fp-column-concat", list(
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

# ===========================================================================
# Core storage functions
# ===========================================================================

#' Store a blob on server (adaptive chunking support)
#' @param key Character. Blob key.
#' @param chunk Character. Blob data (or chunk if multi-part).
#' @param chunk_index Integer. Chunk index (1-based).
#' @param n_chunks Integer. Total chunks.
#' @param session_id Character or NULL.
#' @return TRUE on success.
#' @export
mpcStoreBlobDS <- function(key, chunk, chunk_index = 1L, n_chunks = 1L,
                           session_id = NULL) {
  ss <- .S(session_id)
  if (n_chunks == 1L) {
    .blob_put(key, chunk, ss)
  } else {
    if (is.null(ss$blob_chunks)) ss$blob_chunks <- list()
    if (!is.null(ss$blob_chunks[[key]]) &&
        length(ss$blob_chunks[[key]]) != n_chunks) {
      ss$blob_chunks[[key]] <- NULL
    }
    if (is.null(ss$blob_chunks[[key]])) {
      ss$blob_chunks[[key]] <- character(n_chunks)
    }
    ss$blob_chunks[[key]][chunk_index] <- chunk
    if (all(nzchar(ss$blob_chunks[[key]]))) {
      .blob_put(key, paste0(ss$blob_chunks[[key]], collapse = ""), ss)
      ss$blob_chunks[[key]] <- NULL
    }
  }
  TRUE
}

#' Store peer transport public keys (with identity verification)
#' @param transport_keys Named list of base64url transport PKs.
#' @param identity_info Named list: server -> list(identity_pk, signature). NULL to skip.
#' @param session_id Character or NULL.
#' @return TRUE on success.
#' @export
mpcStoreTransportKeysDS <- function(transport_keys = NULL,
                                     transport_keys_b64 = NULL,
                                     identity_info = NULL,
                                     identity_info_b64 = NULL,
                                     session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("transport_sk", ss)) {
    stop("Not initialized. Call glmRing63TransportInitDS first.", call. = FALSE)
  }

  # Accept list args as base64url-encoded JSON (avoids Opal parser issues)
  .from_b64url <- function(x) {
    x <- gsub("-","+",gsub("_","/",x,fixed=TRUE),fixed=TRUE)
    pad <- nchar(x)%%4; if(pad==2) x<-paste0(x,"=="); if(pad==3) x<-paste0(x,"="); x
  }
  if (is.null(transport_keys) && !is.null(transport_keys_b64) && nzchar(transport_keys_b64))
    transport_keys <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(.from_b64url(transport_keys_b64))), simplifyVector = FALSE)
  if (is.null(identity_info) && !is.null(identity_info_b64) && nzchar(identity_info_b64))
    identity_info <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(.from_b64url(identity_info_b64))), simplifyVector = FALSE)

  if (!is.null(identity_info)) {
    own_pk <- .key_get("identity_pk", ss)
    .verify_all_peer_identities(identity_info, transport_keys, own_pk)
  } else {
    require_tp <- getOption("dsvert.require_trusted_peers")
    if (is.null(require_tp)) require_tp <- getOption("default.dsvert.require_trusted_peers")
    if (is.null(require_tp)) require_tp <- TRUE
    if (isTRUE(as.logical(require_tp)))
      stop("Trusted peers required but no identity_info provided by client.",
           call. = FALSE)
  }

  ss$peer_transport_pks <- lapply(transport_keys, .base64url_to_base64)
  TRUE
}
