#' @title LMM closed-form GLS: local Gram blocks + share transformed columns
#' @description Per-server aggregate. Computes the Laird-Ware cluster-mean-
#'   centred transformed design columns in-place:
#'       tilde_v_j = v_j - lambda_{c(j)} * mean(v[cluster == c(j)])
#'   and returns:
#'     - XtX_local: p_local x p_local matrix of local inner products
#'     - Xty_local: p_local vector (only if this server owns y_var)
#'     - yty: scalar (only if this server owns y_var)
#'     - n
#'   Also generates Ring63 FP shares of EACH transformed column,
#'   storing own share under \code{ss$lmm_gram_col_<name>} and
#'   returning the peer share sealed to \code{peer_pk} for client
#'   relay. The subsequent Beaver vecmul pipeline uses these shares
#'   to fill the cross-server entries of X'X and X'y.
#'
#'   Cluster IDs must be broadcast via
#'   \code{dsvertLMMBroadcastClusterIDsDS} /
#'   \code{dsvertLMMReceiveClusterIDsDS} beforehand.
#'
#'   Only aggregates escape this server: scalar Gram entries (already
#'   computable from existing GLM pipeline) and transport-sealed FP
#'   share blobs (random to the peer until combined).
#'
#' @export
dsvertLMMLocalGramDS <- function(data_name, columns,
                                  y_var = NULL,
                                  lambda_per_cluster,
                                  create_intercept = FALSE,
                                  intercept_col = "dsvertlmmint",
                                  peer_pk,
                                  session_id = NULL,
                                  frac_bits = 20L,
                                  share_scale = 1.0,
                                  column_scales = NULL,
                                  standardize = FALSE) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  ss <- .S(session_id)
  ids <- ss$k2_lmm_cluster_ids
  if (is.null(ids)) stop("cluster IDs not in session", call. = FALSE)
  lambda <- as.numeric(lambda_per_cluster)
  lam_per_obs <- lambda[ids]
  n <- nrow(data)

  tx <- list()  # named numeric columns (transformed)
  # Column standardization (Codex-approved structural fix, 2026-04-19):
  # dividing each raw column by its public SD before cluster-mean centering
  # equalizes the Gram diagonal and reduces kappa(X~^T X~) from O(1e5-1e6)
  # to O(1-1e3), amplifying MPC precision from rel~1e-4 to rel~1e-8 on
  # |β|>1 coefficients. Scales are supplied by the client from the
  # already-documented scalar aggregate dsvertLocalMomentsDS (same P3 tier
  # as mean/sd releases in ds.vertDesc). Intercept column is NOT scaled
  # (its magnitude is governed by lambda_i, not user data). y_var is NOT
  # scaled so that β_std_j = β_raw_j × s_j and the client unscaling
  # β_raw_j = β_std_j / s_j is a clean per-coefficient divide.
  scale_vec <- function(v) {
    if (is.null(column_scales)) return(1.0)
    sj <- column_scales[[v]]
    if (is.null(sj) || length(sj) != 1L || !is.finite(as.numeric(sj)) ||
        as.numeric(sj) <= 0) return(1.0)
    as.numeric(sj)
  }
  # Transform local predictors.
  for (v in columns) {
    if (!v %in% names(data)) next
    x <- as.numeric(data[[v]])
    sj <- scale_vec(v)
    if (sj != 1.0) x <- x / sj
    cl_means <- tapply(x, ids, function(z) mean(z, na.rm = TRUE))
    cm_obs <- as.numeric(cl_means[as.character(ids)])
    out <- x - lam_per_obs * cm_obs
    out[is.na(out)] <- 0
    tx[[v]] <- out
  }
  # Intercept column on outcome server only.
  if (isTRUE(create_intercept)) {
    val <- 1 - lam_per_obs
    val[is.na(val)] <- 1
    tx[[intercept_col]] <- val
  }
  # Post-centering L2 standardization. This is the Codex-approved
  # structural fix (2026-04-19) that closes the X4 rel<1e-4 gap:
  # the raw Gram X~^T X~ has κ≈5.57e5 on mixed-scale designs; dividing
  # each centered column by its L2 norm shrinks κ to O(10), amplifying
  # MPC precision from rel~1e-4 to rel~1e-8. Scales are returned to the
  # client so it can unscale β at the end. L2 of each centered column
  # is a scalar aggregate (same P3 tier as mean/sd releases in
  # ds.vertDesc) — no new disclosure.
  use_std <- isTRUE(standardize)
  l2_scales <- setNames(rep(1.0, length(names(tx))), names(tx))
  if (use_std) {
    for (nm in names(tx)) {
      v <- tx[[nm]]
      l2 <- sqrt(sum(v * v))
      if (is.finite(l2) && l2 > 0) {
        tx[[nm]] <- v / l2
        l2_scales[nm] <- l2
      }
    }
  }
  # y is NOT standardized: unscaling then becomes β_raw_j = β_std_j / s_j
  # (and y stays in original units so downstream σ²/σ_b² consumers work
  # without re-scaling).
  # Transform y if this server owns it.
  y_tx <- NULL
  y_key <- NULL
  if (!is.null(y_var) && nzchar(y_var) && y_var %in% names(data)) {
    y <- as.numeric(data[[y_var]])
    cl_means <- tapply(y, ids, function(z) mean(z, na.rm = TRUE))
    cm_obs <- as.numeric(cl_means[as.character(ids)])
    y_tx <- y - lam_per_obs * cm_obs
    y_tx[is.na(y_tx)] <- 0
    y_key <- paste0(y_var, ".Y")
  }

  # Ordered column list for the local block (intercept first if owned,
  # then declared columns in `columns` order).
  col_order <- if (isTRUE(create_intercept))
    c(intercept_col, intersect(columns, names(tx))) else intersect(columns, names(tx))
  p_local <- length(col_order)
  X_local <- if (p_local > 0L)
    do.call(cbind, tx[col_order]) else matrix(0, n, 0)

  # Local Gram blocks. For the cross-Gram entries the client gets
  # scalar aggregates from downstream Beaver rounds; here we compute
  # the within-server blocks exactly.
  XtX_local <- as.matrix(crossprod(X_local))
  Xty_local <- if (!is.null(y_tx) && p_local > 0L)
    as.numeric(crossprod(X_local, y_tx)) else numeric(0)
  yty       <- if (!is.null(y_tx)) as.numeric(sum(y_tx^2)) else NA_real_

  # Share each transformed column as Ring63 FP for subsequent Beaver
  # dot products with the peer's columns. Own share stored under a
  # canonical session key; peer share sealed into a single blob.
  # SNR-boost via SHARE_SCALE (Codex 2026-04-19 late, band-aid for Ring63
  # FP floor): multiply every shared column by share_scale so cross-Gram
  # Beaver products operate on values with larger absolute magnitude
  # vs the fixed ~1e-4 absolute Ring63 noise. Per docs/acceptance
  # §LMM iterative-refinement band-aid. X̃, ỹ both pre-multiplied so the
  # GLS solution is INVARIANT (β = solve(c²XtX, c²Xty) = solve(XtX, Xty)).
  # The within-server XtX_local and Xty_local ALSO scale by c² and c²
  # so the client-side assembly is consistent.
  sc <- as.numeric(share_scale)
  if (!is.finite(sc) || sc <= 0) sc <- 1.0
  peer_shares <- list()
  share_col <- function(name, vec) {
    fp <- .callMpcTool("k2-float-to-fp",
      list(values = as.numeric(sc * vec),
           frac_bits = as.integer(frac_bits)))$fp_data
    split_res <- .callMpcTool("k2-split-fp-share",
      list(data_fp = fp, n = length(vec)))
    ss[[paste0("lmm_gram_col_", name)]] <- split_res$own_share
    peer_shares[[name]] <<- split_res$peer_share
  }
  for (nm in col_order) share_col(nm, tx[[nm]])
  if (!is.null(y_tx)) share_col(y_key, y_tx)
  # Scale the within-server XtX and Xty blocks to match the share-scale
  # applied to the Beaver cross blocks above; these are computed in
  # double precision (no FP floor) but their magnitudes must match the
  # cross blocks after scaling so client assembly is coherent.
  if (sc != 1.0) {
    XtX_local <- XtX_local * (sc * sc)
    if (length(Xty_local) > 0L) Xty_local <- Xty_local * (sc * sc)
    if (!is.na(yty)) yty <- yty * (sc * sc)
  }
  ss$lmm_gram_share_scale <- sc

  payload_json <- jsonlite::toJSON(peer_shares, auto_unbox = TRUE)
  payload_b64  <- jsonlite::base64_enc(charToRaw(as.character(payload_json)))
  sealed <- .callMpcTool("transport-encrypt",
    list(data = payload_b64,
         recipient_pk = .base64url_to_base64(peer_pk)))

  # Store n and a list of local column keys for R1/R2 helpers.
  ss$lmm_gram_n <- as.integer(n)
  ss$lmm_gram_local_cols <- col_order
  ss$lmm_gram_y_key <- y_key

  list(XtX_local   = XtX_local,
       Xty_local   = Xty_local,
       yty         = yty,
       n           = n,
       column_names = col_order,
       y_key       = y_key,
       l2_scales   = as.list(l2_scales[col_order]),
       peer_blob   = base64_to_base64url(sealed$sealed))
}

#' @title LMM closed-form GLS: receive peer's column shares
#' @description Per-party aggregate. Consumes the peer's sealed share
#'   blob (relayed via \code{mpcStoreBlobDS} under
#'   \code{"k2_lmm_gram_peer_shares"}), decrypts it, and stores each
#'   column's FP share under \code{ss$lmm_gram_col_<name>} so the
#'   subsequent Beaver vecmul rounds can dereference it by name.
#' @export
dsvertLMMReceiveGramSharesDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  blob <- .blob_consume("k2_lmm_gram_peer_shares", ss)
  if (is.null(blob))
    stop("LMM gram peer-shares blob missing; relay after LocalGram",
         call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport_sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  stored <- character(0)
  for (nm in names(payload)) {
    ss[[paste0("lmm_gram_col_", nm)]] <- payload[[nm]]
    stored <- c(stored, nm)
  }
  ss$lmm_gram_peer_cols <- stored
  list(stored = stored, n_cols = length(stored))
}

#' @title LMM closed-form GLS: Beaver dot product of two shared columns
#' @description Per-party aggregate. Given two session keys containing
#'   FP shares of vectors x and y (n-long), runs one round of Beaver
#'   multiplication followed by FP summation to produce this party's
#'   share of the scalar \code{x^T y}. Requires a Beaver triple to have
#'   been consumed into the session via
#'   \code{\link{k2BeaverVecmulConsumeTripleDS}} by the dealer relay.
#'
#'   The R1 variant produces masked outputs for the peer; the R2
#'   variant consumes the peer's masks and reveals the party's output
#'   share, then reduces to a scalar via \code{k2-fp-sum}.
#' @export
dsvertLMMGramR1DS <- function(peer_pk, x_col, y_col,
                               session_id = NULL, frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  x_key <- paste0("lmm_gram_col_", x_col)
  y_key <- paste0("lmm_gram_col_", y_col)
  if (is.null(ss[[x_key]]) || is.null(ss[[y_key]]))
    stop("column shares missing: ", x_col, " / ", y_col, call. = FALSE)
  n <- as.integer(ss$lmm_gram_n)
  r1 <- .callMpcTool("k2-beaver-vecmul-round1", list(
    x_fp = ss[[x_key]], y_fp = ss[[y_key]],
    triple_blob = ss$k2_beaver_vecmul_triple,
    n = n, frac_bits = as.integer(frac_bits)))
  payload <- jsonlite::toJSON(list(d_fp = r1$d_fp, e_fp = r1$e_fp),
                              auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(as.character(payload)))
  sealed <- .callMpcTool("transport-encrypt",
    list(data = payload_b64,
         recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed))
}

#' @export
dsvertLMMGramR2DS <- function(is_party0, x_col, y_col,
                               session_id = NULL, frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  x_key <- paste0("lmm_gram_col_", x_col)
  y_key <- paste0("lmm_gram_col_", y_col)
  blob <- .blob_consume("k2_beaver_vecmul_peer_masked", ss)
  if (is.null(blob))
    stop("peer masked blob missing; client must relay after R1",
         call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  n <- as.integer(ss$lmm_gram_n)
  res <- .callMpcTool("k2-beaver-vecmul-round2", list(
    x_fp = ss[[x_key]], y_fp = ss[[y_key]],
    triple_blob = ss$k2_beaver_vecmul_triple,
    peer_d_fp = payload$d_fp, peer_e_fp = payload$e_fp,
    is_party0 = isTRUE(is_party0),
    n = n, frac_bits = as.integer(frac_bits)))
  # Reduce to scalar: sum the element-wise product share.
  sc <- .callMpcTool("k2-fp-sum", list(fp_data = res$z_fp))
  list(scalar_share = sc$sum_fp,
       x_col = x_col, y_col = y_col)
}
