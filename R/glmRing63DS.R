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
glmRing63TransportInitDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  # Cross the persistent-identity bootstrap barrier before creating any
  # ephemeral transport state.
  identity <- .get_identity_keypair()
  transport <- .callMpcTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)

  # Ed25519 identity: derive keypair, sign transport PK
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
glmRing63ExportOwnShareDS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  # Pin the recipient to an identity-verified peer. Otherwise a caller supplies
  # its own transport key, "sealing" gives no confidentiality, and it recovers
  # own_share of the raw features X (its complement is retrievable on the peer).
  .dsvert_validate_peer_pk(peer_pk, ss, "peer")
  request <- list(peer_pk = peer_pk)
  replay <- .dsvert_typed_blob_operation_replay(
    ss, "glmRing63ExportOwnShareDS", request)
  if (isTRUE(replay$hit)) return(replay$result)
  own_fp <- ss$k2_x_share_fp
  if (is.null(own_fp)) stop("No own share in session. Call k2ShareInputDS first.", call. = FALSE)

  pk <- .base64url_to_base64(peer_pk)
  sealed <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(own_fp)),
    recipient_pk = pk))
  payload <- base64_to_base64url(sealed$sealed)

  result <- list(
    encrypted_own_share = payload,
    encrypted_own_transfer = .dsvert_typed_blob_mint(
      ss, session_id, "blob.input.extra-x.v1", peer_pk, payload,
      list(n = ss$k2_x_n, p = ss$k2_x_p,
           ring = as.integer(ss$k2_ring %||% 63L)),
      producer = "glmRing63ExportOwnShareDS"))
  .dsvert_typed_blob_operation_commit(
    ss, "glmRing63ExportOwnShareDS", request, result)
}

#' Reorder X_full columns to canonical order on fusion party
#'
#' After k2ComputeEtaShareDS, the fusion party's X_full has column order
#' \code{(coord | extras | fusion)}. This reorders to canonical
#' \code{(coord | fusion | extras)} to match the coordinator's order,
#' ensuring Beaver gradient works correctly.
#'
#' @param p_coord Integer. Number of coordinator features.
#' @param p_fusion Integer. Number of fusion features.
#' @param p_extras Integer. Number of extra (non-DCF) features.
#' @param session_id Character or NULL.
#' @return List with status.
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

  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  result <- .callMpcTool("k2-fp-permute", list(
    fp_data = x_full_fp, perm = as.integer(perm), ring = ring_tag))

  ss$k2_x_full_fp <- result$fp_data
  list(status = "ok")
}

#' Generate DCF keys on server and distribute to DCF parties
#'
#' Called on a NON-DCF server to generate DCF keys securely.
#' The client never sees the key values -- only opaque transport-encrypted blobs.
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
#' @keywords internal
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
#' @param dealer_party Optional integer 0/1. When this dealer is also one of
#'   the two DCF parties, store that party's triples directly in the current
#'   session and only return the encrypted blob for the peer.
#' @return List with encrypted blobs for each DCF party.
#' @keywords internal
glmRing63GenSplineTriplesDS <- function(dcf0_pk, dcf1_pk, n, frac_bits,
                                         ring = 63L, session_id = NULL,
                                         dealer_party = NULL) {
  .dsvert_require_beaver_mode("dealer")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  n <- as.integer(n)
  triples <- .callMpcTool("k2-gen-beaver-triples",
    list(n = as.integer(3L * n), frac_bits = as.integer(frac_bits),
         ring = ring_tag))

  split_b64 <- function(x) {
    raw <- jsonlite::base64_dec(x)
    bytes_per_value <- if (ring == 127L) 16L else 8L
    chunk <- n * bytes_per_value
    if (length(raw) != 3L * chunk) {
      stop("unexpected batched spline triple payload length", call. = FALSE)
    }
    lapply(0:2, function(i) {
      idx <- (i * chunk + 1L):((i + 1L) * chunk)
      jsonlite::base64_enc(raw[idx])
    })
  }

  p0_a <- split_b64(triples$party0_u)
  p0_b <- split_b64(triples$party0_v)
  p0_c <- split_b64(triples$party0_w)
  p1_a <- split_b64(triples$party1_u)
  p1_b <- split_b64(triples$party1_v)
  p1_c <- split_b64(triples$party1_w)

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  # Pack party 0's shares
  td0 <- list()
  td1 <- list()
  for (op in c("and", "had1", "had2")) {
    ti <- switch(op, and = 1, had1 = 2, had2 = 3)
    td0[[paste0(op, "_a")]] <- p0_a[[ti]]
    td0[[paste0(op, "_b")]] <- p0_b[[ti]]
    td0[[paste0(op, "_c")]] <- p0_c[[ti]]
    td1[[paste0(op, "_a")]] <- p1_a[[ti]]
    td1[[paste0(op, "_b")]] <- p1_b[[ti]]
    td1[[paste0(op, "_c")]] <- p1_c[[ti]]
  }

  dealer_party <- if (is.null(dealer_party)) NA_integer_ else
    as.integer(dealer_party)
  if (!is.na(dealer_party) && !dealer_party %in% c(0L, 1L)) {
    stop("dealer_party must be NULL, 0 or 1", call. = FALSE)
  }
  if (!is.na(dealer_party)) {
    if (is.null(session_id) || !nzchar(session_id)) {
      stop("session_id required when dealer_party is set", call. = FALSE)
    }
    ss <- .S(session_id)
    if (identical(dealer_party, 0L)) {
      ss$k2_ws_triples <- td0
    } else if (identical(dealer_party, 1L)) {
      ss$k2_ws_triples <- td1
    }
  }

  blob0 <- ""
  blob1 <- ""
  if (!identical(dealer_party, 0L)) {
    sealed0 <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(
        jsonlite::toJSON(td0, auto_unbox = TRUE))),
      recipient_pk = pk0))
    blob0 <- base64_to_base64url(sealed0$sealed)
  }
  if (!identical(dealer_party, 1L)) {
    sealed1 <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(
        jsonlite::toJSON(td1, auto_unbox = TRUE))),
      recipient_pk = pk1))
    blob1 <- base64_to_base64url(sealed1$sealed)
  }

  list(
    spline_blob_0 = blob0,
    spline_blob_1 = blob1,
    dealer_self_stored = !is.na(dealer_party)
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
#' @param ring Integer (63 or 127). MPC ring selector; controls fixed-point precision.
#' @param dealer_party Optional integer 0/1. When this dealer is also one of
#'   the two DCF parties, store that party's gradient triple share directly in
#'   the current session and only return the encrypted blob for the peer.
#' @return List with encrypted blobs for each DCF party.
#' @keywords internal
glmRing63GenGradTriplesDS <- function(dcf0_pk, dcf1_pk, n, p,
                                       ring = 63L, session_id = NULL,
                                       dealer_party = NULL) {
  .dsvert_require_beaver_mode("dealer")
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  mvt <- .callMpcTool("k2-gen-matvec-triples", list(
    n = as.integer(n), p = as.integer(p),
    ring = ring_tag))

  pk0 <- .base64url_to_base64(dcf0_pk)
  pk1 <- .base64url_to_base64(dcf1_pk)

  dealer_party <- if (is.null(dealer_party)) NA_integer_ else
    as.integer(dealer_party)
  if (!is.na(dealer_party) && !dealer_party %in% c(0L, 1L)) {
    stop("dealer_party must be NULL, 0 or 1", call. = FALSE)
  }
  if (!is.na(dealer_party)) {
    if (is.null(session_id) || !nzchar(session_id)) {
      stop("session_id required when dealer_party is set", call. = FALSE)
    }
    ss <- .S(session_id)
    if (identical(dealer_party, 0L)) {
      ss$k2_grad_a_fp <- mvt$party0_a
      ss$k2_grad_b_fp <- mvt$party0_b
      ss$k2_grad_c_fp <- mvt$party0_c
    } else if (identical(dealer_party, 1L)) {
      ss$k2_grad_a_fp <- mvt$party1_a
      ss$k2_grad_b_fp <- mvt$party1_b
      ss$k2_grad_c_fp <- mvt$party1_c
    }
  }

  blob0 <- ""
  blob1 <- ""
  if (!identical(dealer_party, 0L)) {
    sealed0 <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
        a = mvt$party0_a, b = mvt$party0_b, c = mvt$party0_c),
        auto_unbox = TRUE))),
      recipient_pk = pk0))
    blob0 <- base64_to_base64url(sealed0$sealed)
  }
  if (!identical(dealer_party, 1L)) {
    sealed1 <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(jsonlite::toJSON(list(
        a = mvt$party1_a, b = mvt$party1_b, c = mvt$party1_c),
        auto_unbox = TRUE))),
      recipient_pk = pk1))
    blob1 <- base64_to_base64url(sealed1$sealed)
  }

  list(
    grad_blob_0 = blob0,
    grad_blob_1 = blob1,
    dealer_self_stored = !is.na(dealer_party)
  )
}

#' Prepare deviance: store residual as 1-column X matrix for Beaver Sumr^2
#'
#' After convergence, computes r = mu_share - y_share in Ring63 and stores
#' as k2_x_full_fp (nx1 "matrix"). Then the standard k2GradientR1DS/R2DS
#' with p=1 triples computes "gradient" = r^T x r = Sum r_i^2 (deviance).
#'
#' @param session_id Character or NULL.
#' @param mode Character. Operation mode (e.g. \code{"rss"} or \code{"canonical"}).
#' @return List with status.
glmRing63PrepDevianceDS <- function(mode = "rss", session_id = NULL) {
  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L

  if (mode == "canonical") {
    # Canonical deviance: Beaver computes eta^T * y
    # gradient uses residual = mu_share - y_share
    # We set: x_full = eta, mu_share = y, y_share = 0 -> residual = y - 0 = y
    eta_fp <- ss$k2_eta_share_fp
    if (is.null(eta_fp)) stop("No eta shares for canonical deviance", call. = FALSE)
    ss$k2_x_full_fp <- eta_fp
    ss$k2_x_p <- 1L
    ss$k2_peer_p <- 0L
    # Save and replace: mu = y, y = 0
    n <- ss$k2_x_n
    if (is.null(ss$k2_y_share_fp_original)) {
      ss$k2_y_share_fp_original <- ss$k2_y_share_fp
    }
    zero <- .callMpcTool("k2-float-to-fp", list(
      values = rep(0, n), frac_bits = frac_bits, ring = ring_tag))
    ss$secure_mu_share <- ss$k2_y_share_fp  # mu = y
    ss$k2_y_share_fp <- zero$fp_data        # y = 0
    list(status = "ok")
  } else {
    # RSS deviance (default): store r = mu - y as x_full
    mu_fp <- .base64url_to_base64(ss$secure_mu_share)
    y_fp <- .base64url_to_base64(ss$k2_y_share_fp)
    if (is.null(mu_fp) || is.null(y_fp))
      stop("No mu/y shares for deviance", call. = FALSE)
    r <- .callMpcTool("k2-fp-sub", list(
      a = mu_fp, b = y_fp, frac_bits = frac_bits, ring = ring_tag))
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
glmRing63DevianceSumsDS <- function(family, session_id = NULL) {
  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"

  if (family == "binomial") {
    # Sum of softplus(eta) shares -- spline must have been evaluated already
    sp_fp <- ss$softplus_share_fp
    if (is.null(sp_fp))
      stop("Softplus shares not computed. Run softplus spline first.", call. = FALSE)
    r <- .callMpcTool("k2-fp-sum", list(fp_data = sp_fp, ring = ring_tag))
    list(sum_fp = r$sum_fp)

  } else if (family == "poisson") {
    # Sum of mu shares (from last exp spline evaluation)
    mu_fp <- .base64url_to_base64(ss$secure_mu_share)
    r <- .callMpcTool("k2-fp-sum", list(fp_data = mu_fp, ring = ring_tag))

    # Null term: label server computes Sum(y*log(y) - y) in plaintext
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

# Retired correlation control-plane compatibility helper. It remains internal
# for source-level tests and cannot be invoked through DataSHIELD.
glmRing63CorSetZeroYDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  zero <- .callMpcTool("k2-float-to-fp", list(values = rep(0, n), frac_bits = 20L))
  ss$k2_y_share_fp <- zero$fp_data
  list(status = "ok")
}

# Retired correlation control-plane compatibility helper. The promoted
# correlation path uses a joint DP capsule and has no caller for this mutating
# session endpoint.
glmRing63CorSetColDS <- function(col_idx = NULL, p_total = NULL,
                                  from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  if (isTRUE(from_storage)) {
    stop("Blob-encoded correlation column parameters are retired; pass ",
         "col_idx and p_total as bounded scalars.", call. = FALSE)
  }
  if (!is.numeric(col_idx) || length(col_idx) != 1L || is.na(col_idx) ||
      !is.finite(col_idx) || col_idx != floor(col_idx) || col_idx < 0) {
    stop("col_idx must be one non-negative integer", call. = FALSE)
  }
  if (!is.numeric(p_total) || length(p_total) != 1L || is.na(p_total) ||
      !is.finite(p_total) || p_total != floor(p_total) || p_total < 1L ||
      p_total > .Machine$integer.max || col_idx >= p_total) {
    stop("p_total must be positive and col_idx must be in range", call. = FALSE)
  }
  col_idx <- as.integer(col_idx)
  p_total <- as.integer(p_total)
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
#' @param source_name Authenticated logical name of the feature producer.
#' @param extra_p Integer. Number of features in this share.
#' @param session_id Character or NULL.
#' @return List with status.
glmRing63ReceiveExtraShareDS <- function(source_name, extra_p,
                                         session_id = NULL) {
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("Transport SK not stored", call. = FALSE)

  ring <- as.integer(ss$k2_ring %||% 63L)
  blob <- .dsvert_typed_blob_consume(
    ss, "blob.input.extra-x.v1",
    list(n = ss$k2_x_n, p = as.integer(extra_p), ring = ring),
    sender_name = source_name)

  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  extra_fp <- rawToChar(jsonlite::base64_dec(dec$data))

  # Column-concatenate: interleave extra features into peer FP matrix (row-major)
  n <- ss$k2_x_n
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (!is.null(ss$k2_peer_x_share_fp) && !is.null(ss$k2_peer_p) && ss$k2_peer_p > 0) {
    result <- .callMpcTool("k2-fp-column-concat", list(
      a = ss$k2_peer_x_share_fp,
      b = extra_fp,
      n = as.integer(n),
      p_a = as.integer(ss$k2_peer_p),
      p_b = as.integer(extra_p),
      ring = ring_tag))
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

.DSVERT_LEGACY_BLOB_MAX_FRAME_BYTES <- 8L * 1024L^2

.dsvert_store_blob_chunks <- function(ss, key, chunk, chunk_index, n_chunks,
                                      purpose = c("generic", "psi")) {
  purpose <- match.arg(purpose)
  .validate_storage_component(key, "blob key")
  if (!is.character(chunk) || length(chunk) != 1L || is.na(chunk) ||
      !nzchar(chunk)) {
    stop("chunk must be one non-empty character string", call. = FALSE)
  }
  validate_integer <- function(value, name, lower, upper) {
    if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
        !is.finite(value) || value != floor(value) || value < lower ||
        value > upper) {
      stop(name, " must be one integer between ", lower, " and ", upper,
           call. = FALSE)
    }
    as.integer(value)
  }
  # These are per-payload resource bounds, not a request/rate limit. They
  # prevent a single unauthenticated relay frame from exhausting the R worker.
  # Matches the absolute data-free probe ceiling. The route must prove a
  # smaller connector-wide geometry before sending; this remains the server's
  # hard per-request availability bound even if a client claims more.
  max_chunk_bytes <- .DSVERT_LEGACY_BLOB_MAX_FRAME_BYTES
  max_chunks <- 4096L
  max_blob_bytes <- .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES
  n_chunks_candidate <- suppressWarnings(as.numeric(n_chunks))
  if (length(n_chunks_candidate) == 1L && !is.na(n_chunks_candidate) &&
      is.finite(n_chunks_candidate) &&
      n_chunks_candidate == floor(n_chunks_candidate) &&
      n_chunks_candidate > max_chunks) {
    .dsvert_resource_oversize(
      n_chunks_candidate, max_chunks, "legacy blob frame metadata")
  }
  n_chunks <- validate_integer(n_chunks, "n_chunks", 1L, max_chunks)
  chunk_index <- validate_integer(
    chunk_index, "chunk_index", 1L, n_chunks)
  chunk_bytes <- as.numeric(nchar(chunk, type = "bytes"))
  if (chunk_bytes > max_chunk_bytes) {
    .dsvert_resource_oversize(
      chunk_bytes, max_chunk_bytes, "legacy blob immutable frame")
  }

  if (is.null(ss$blob_chunk_receipts)) ss$blob_chunk_receipts <- list()
  receipt <- ss$blob_chunk_receipts[[key]]
  chunk_digest <- digest::digest(
    chunk, algo = "sha256", serialize = FALSE)
  if (!is.null(receipt)) {
    existing <- .blob_snapshot(ss)[[key]]
    receipt_matches <-
      identical(receipt$purpose, purpose) &&
      identical(receipt$n_chunks, n_chunks) &&
      length(receipt$chunk_digests) == n_chunks &&
      identical(receipt$chunk_digests[[chunk_index]], chunk_digest) &&
      !is.null(existing) &&
      identical(
        receipt$blob_digest,
        digest::digest(existing, algo = "sha256", serialize = FALSE))
    if (!receipt_matches) {
      stop("Conflicting retry for a completed blob", call. = FALSE)
    }
    return(TRUE)
  }

  if (identical(purpose, "psi")) {
    fixed_psi_keys <- c(
      "ref_encrypted_blob", "target_encrypted_blob", "dm_encrypted_blob",
      "common_indices_encrypted")
    matched_peer <- sub("^matched_indices_", "", key)
    is_matched <- startsWith(key, "matched_indices_") &&
      nzchar(matched_peer) && !identical(matched_peer, key)
    if (is_matched) {
      trusted <- .get_trusted_peers()
      is_matched <- !is.null(names(trusted)) && matched_peer %in% names(trusted)
    }
    if (!key %in% fixed_psi_keys && !is_matched) {
      stop("This is not a permitted typed PSI transport slot",
           call. = FALSE)
    }
  }

  if (n_chunks == 1L) {
    existing <- .blob_snapshot(ss)[[key]]
    if (!is.null(existing)) {
      if (!identical(existing, chunk)) {
        stop("Conflicting retry for an existing blob", call. = FALSE)
      }
    } else {
      .dsvert_resource_admit(
        ss, chunk_bytes + .DSVERT_LEGACY_BLOB_OBJECT_METADATA_BYTES +
          .DSVERT_LEGACY_BLOB_FRAME_METADATA_BYTES)
      .blob_put(key, chunk, ss)
    }
    ss$blob_chunk_receipts[[key]] <- list(
      purpose = purpose,
      n_chunks = n_chunks,
      chunk_digests = chunk_digest,
      blob_digest = chunk_digest)
  } else {
    if (is.null(ss$blob_chunks)) ss$blob_chunks <- list()
    state <- ss$blob_chunks[[key]]
    state_was_new <- is.null(state)
    if (is.character(state)) {
      # One-time compatibility migration for an in-progress state created by
      # the former character-vector implementation during a package upgrade.
      if (length(state) != n_chunks) {
        stop("Conflicting n_chunks for an in-progress blob", call. = FALSE)
      }
      migrated <- new.env(parent = emptyenv())
      migrated$purpose <- purpose
      migrated$n_chunks <- n_chunks
      migrated$chunks <- new.env(parent = emptyenv())
      migrated$digests <- new.env(parent = emptyenv())
      present <- which(nzchar(state))
      for (index in present) {
        index_key <- as.character(index)
        migrated$chunks[[index_key]] <- state[[index]]
        migrated$digests[[index_key]] <- digest::digest(
          state[[index]], algo = "sha256", serialize = FALSE)
      }
      migrated$received_count <- length(present)
      migrated$received_bytes <- sum(nchar(
        state[present], type = "bytes"))
      state <- migrated
      ss$blob_chunks[[key]] <- state
    }
    if (!is.null(state) && !is.environment(state)) {
      stop("Malformed in-progress blob state", call. = FALSE)
    }
    if (is.null(state)) {
      if (!is.null(.blob_snapshot(ss)[[key]])) {
        stop("Conflicting retry for an existing blob", call. = FALSE)
      }
      .dsvert_resource_admit(
        ss, chunk_bytes + .DSVERT_LEGACY_BLOB_OBJECT_METADATA_BYTES +
          as.numeric(n_chunks) * .DSVERT_LEGACY_BLOB_FRAME_METADATA_BYTES)
      state <- new.env(parent = emptyenv())
      state$purpose <- purpose
      state$n_chunks <- n_chunks
      state$chunks <- new.env(parent = emptyenv())
      state$digests <- new.env(parent = emptyenv())
      state$received_count <- 0L
      state$received_bytes <- 0
      ss$blob_chunks[[key]] <- state
    }
    valid_state <- identical(state$purpose, purpose) &&
      identical(state$n_chunks, n_chunks) &&
      is.environment(state$chunks) && is.environment(state$digests) &&
      is.numeric(state$received_count) &&
      length(state$received_count) == 1L &&
      !is.na(state$received_count) && is.finite(state$received_count) &&
      state$received_count == floor(state$received_count) &&
      state$received_count >= 0 && state$received_count <= n_chunks &&
      is.numeric(state$received_bytes) &&
      length(state$received_bytes) == 1L &&
      !is.na(state$received_bytes) && is.finite(state$received_bytes) &&
      state$received_bytes >= 0 && state$received_bytes <= max_blob_bytes
    if (!valid_state) {
      stop("Conflicting or malformed in-progress blob state", call. = FALSE)
    }
    index_key <- as.character(chunk_index)
    prior <- state$chunks[[index_key]]
    if (!is.null(prior)) {
      if (!identical(prior, chunk) ||
          !identical(state$digests[[index_key]], chunk_digest)) {
        stop("Conflicting retry for an existing blob chunk", call. = FALSE)
      }
      return(TRUE)
    }
    next_bytes <- state$received_bytes + nchar(chunk, type = "bytes")
    if (!is.finite(next_bytes) || next_bytes > max_blob_bytes) {
      .dsvert_resource_oversize(
        next_bytes, max_blob_bytes, "legacy blob object")
    }
    if (!is.null(state$chunks[[index_key]])) {
      stop("Conflicting legacy blob frame state", call. = FALSE)
    }
    if (!isTRUE(state_was_new)) {
      .dsvert_resource_admit(ss, chunk_bytes)
    }
    state$chunks[[index_key]] <- chunk
    state$digests[[index_key]] <- chunk_digest
    state$received_count <- state$received_count + 1L
    state$received_bytes <- next_bytes
    if (identical(state$received_count, n_chunks)) {
      indices <- as.character(seq_len(n_chunks))
      completed_chunks <- vapply(
        indices, function(index) state$chunks[[index]], character(1L),
        USE.NAMES = FALSE)
      completed_digests <- vapply(
        indices, function(index) state$digests[[index]], character(1L),
        USE.NAMES = FALSE)
      assembled <- paste0(completed_chunks, collapse = "")
      existing <- .blob_snapshot(ss)[[key]]
      if (!is.null(existing) && !identical(existing, assembled)) {
        stop("Conflicting retry for an existing blob", call. = FALSE)
      }
      if (is.null(existing)) .blob_put(key, assembled, ss)
      ss$blob_chunk_receipts[[key]] <- list(
        purpose = purpose,
        n_chunks = n_chunks,
        chunk_digests = completed_digests,
        blob_digest = digest::digest(
          assembled, algo = "sha256", serialize = FALSE))
      ss$blob_chunks[[key]] <- NULL
    }
  }
  TRUE
}

#' Store a generic legacy MPC blob (adaptive chunking support)
#'
#' This compatibility endpoint is disabled by the disclosure-safe gate. New
#' protocols must expose a purpose-bound transport method instead of allowing
#' the caller to choose an arbitrary session key.
#' @param key Character. Blob key.
#' @param chunk Character. Blob data (or chunk if multi-part).
#' @param chunk_index Integer. Chunk index (1-based).
#' @param n_chunks Integer. Total chunks.
#' @param session_id Character or NULL.
#' @return TRUE on success.
mpcStoreBlobDS <- function(key, chunk, chunk_index = 1L, n_chunks = 1L,
                           session_id = NULL) {
  ss <- .S(session_id)
  .dsvert_store_blob_chunks(
    ss, key, chunk, chunk_index, n_chunks, purpose = "generic")
}

#' Store peer transport public keys (with identity verification)
#'
#' Only transport keys that pass Ed25519 signature and exact name-bound pin
#' verification are installed in the session peer set. Identity information is
#' mandatory; an extra unverified key riding along in \code{transport_keys} is
#' dropped. The local logical role must be persisted by the server administrator
#' as `dsvert.peer_name`; it is never learned from a client connection alias.
#' @param transport_keys Named list of base64url transport PKs.
#' @param identity_info Named list: server -> list(identity_pk, signature).
#' @param session_id Character or NULL.
#' @param transport_keys_b64 Character (base64url). JSON-encoded peer transport public keys.
#' @param identity_info_b64 Character (base64url). JSON-encoded identity info / Ed25519 signatures.
#' @return TRUE on success.
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

  if (is.null(identity_info) || length(identity_info) == 0L) {
    stop(
      "Name-bound pinned peers require signed identity_info for every ",
      "transport-key handshake.", call. = FALSE)
  }
  own_pk <- .key_get("identity_pk", ss)
  verified_peers <- .verify_all_peer_identities(
    identity_info, transport_keys, own_pk)

  # The client builds `transport_keys` by iterating every server in the
  # federation (ds.vertGLM.setup.R Phase 0), so the dict received here
  # also contains this server's own transport_pk. Filter self out so
  # `peer_transport_pks` truly contains peers only -- required by
  # `.k2_enforce_K` whose contract is `length + 1 == K`.
  own_tp_plain <- .key_get("transport_pk", ss)
  peer_pks <- lapply(transport_keys, .base64url_to_base64)
  peer_pks <- peer_pks[vapply(peer_pks, function(v) !identical(v, own_tp_plain),
                              logical(1))]
  # Pin exactly the transport keys that passed Ed25519 + exact name-bound
  # verification, so an extra unverified key cannot poison the peer set.
  peer_pks <- peer_pks[vapply(names(peer_pks), function(srv) {
      srv %in% names(verified_peers) &&
        identical(peer_pks[[srv]], verified_peers[[srv]])
    }, logical(1L))]
  # Install the same verified, name-bound identity manifest for producer-minted
  # typed blob tickets.
  .dsvert_typed_blob_install_peer_manifest(ss, identity_info, transport_keys)
  ss$peer_transport_pks <- peer_pks
  TRUE
}
