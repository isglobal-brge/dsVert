#' @title Broadcast cluster IDs to a DCF peer
#' @description On the outcome server, encode cluster membership as integer
#'   levels, store the integer membership locally, and return a
#'   transport-encrypted copy for one DCF peer. The analyst client only
#'   relays an opaque blob; it does not see patient-level cluster membership
#'   or original cluster labels.
#' @param data_name Aligned data frame.
#' @param cluster_col Cluster column.
#' @param peer_pk Transport public key of the DCF peer (base64url).
#' @param session_id Active MPC session identifier.
#' @return list(peer_blob, n_clusters).
#' @export
#' @noRd
dsvertClusterIDsBroadcastDS <- function(data_name, cluster_col, peer_pk,
                                        session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data)) {
    stop("cluster_col not found", call. = FALSE)
  }
  ids <- data[[cluster_col]]
  if (anyNA(ids)) stop("cluster_col contains missing values", call. = FALSE)
  lvls <- sort(unique(ids))
  ids_int <- as.integer(match(ids, lvls))
  sizes <- tabulate(ids_int, nbins = length(lvls))
  .dsvert_guard_cluster_sizes(sizes, "cluster-ID broadcast")
  ss <- .S(session_id)
  ss$dsvert_cluster_ids <- ids_int
  ss$dsvert_cluster_n <- length(lvls)
  payload <- list(ids = ids_int, n_clusters = length(lvls))
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(payload_json))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = payload_b64, recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed),
       n_clusters = length(lvls))
}

#' @title Receive cluster IDs from a DCF peer
#' @description Consume a relayed cluster-ID blob and store the decoded integer
#'   cluster labels in the active MPC session for per-cluster share sums.
#' @param session_id Active MPC session identifier.
#' @return list(stored, n_clusters).
#' @export
#' @noRd
dsvertClusterIDsReceiveDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("dsvert_cluster_ids_blob", ss)
  if (is.null(blob)) stop("cluster-ID blob missing", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport_sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$dsvert_cluster_ids <- as.integer(payload$ids)
  ss$dsvert_cluster_n <- as.integer(payload$n_clusters)
  list(stored = TRUE, n_clusters = ss$dsvert_cluster_n)
}

#' @title Broadcast guarded AR1 order metadata to a DCF peer
#' @description On the outcome server, derive predecessor/successor indices
#'   within each guarded cluster and send them only as a transport-encrypted
#'   blob to the DCF peer. The analyst client relays an opaque blob and never
#'   receives visit labels, row-level order, or adjacent-pair vectors.
#' @param data_name Aligned data frame.
#' @param cluster_col Cluster column.
#' @param order_col Within-cluster order column.
#' @param peer_pk Transport public key of the DCF peer (base64url).
#' @param session_id Active MPC session identifier.
#' @return list(peer_blob, n_clusters, n_pairs).
#' @export
#' @noRd
dsvertGEEAR1OrderBroadcastDS <- function(data_name, cluster_col, order_col,
                                         peer_pk, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data)) {
    stop("cluster_col not found", call. = FALSE)
  }
  if (!order_col %in% names(data)) {
    stop("order_col not found", call. = FALSE)
  }
  ids <- data[[cluster_col]]
  ord <- data[[order_col]]
  if (anyNA(ids)) stop("cluster_col contains missing values", call. = FALSE)
  if (anyNA(ord)) stop("order_col contains missing values", call. = FALSE)
  lvls <- sort(unique(ids))
  ids_int <- as.integer(match(ids, lvls))
  sizes <- tabulate(ids_int, nbins = length(lvls))
  .dsvert_guard_cluster_sizes(sizes, "AR1 order broadcast")

  n <- length(ids_int)
  next_index <- integer(n)
  prev_index <- integer(n)
  for (ci in seq_along(lvls)) {
    ix <- which(ids_int == ci)
    if (any(duplicated(ord[ix]))) {
      stop("order_col has ties within at least one cluster", call. = FALSE)
    }
    ix_ordered <- ix[order(ord[ix])]
    if (length(ix_ordered) > 1L) {
      from <- ix_ordered[-length(ix_ordered)]
      to <- ix_ordered[-1L]
      next_index[from] <- to
      prev_index[to] <- from
    }
  }

  ss <- .S(session_id)
  ss$dsvert_gee_ar1_next_index <- next_index
  ss$dsvert_gee_ar1_prev_index <- prev_index
  ss$dsvert_gee_ar1_n <- as.integer(n)
  ss$dsvert_gee_ar1_n_clusters <- as.integer(length(lvls))
  ss$dsvert_gee_ar1_n_pairs <- as.integer(sum(next_index > 0L))
  ss$dsvert_gee_ar1_max_lag <- as.integer(max(sizes) - 1L)

  payload <- list(
    next_index = next_index,
    prev_index = prev_index,
    n = as.integer(n),
    n_clusters = as.integer(length(lvls)),
    n_pairs = as.integer(sum(next_index > 0L)),
    max_lag = as.integer(max(sizes) - 1L))
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(payload_json))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = payload_b64, recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed),
       n_clusters = length(lvls),
       n_pairs = as.integer(sum(next_index > 0L)),
       max_lag = as.integer(max(sizes) - 1L))
}

#' @title Receive guarded AR1 order metadata from a DCF peer
#' @description Consume a relayed AR1 order blob and store the decoded
#'   predecessor/successor indices in the active MPC session. The metadata is
#'   used only to transform additive shares locally on the DCF parties.
#' @param session_id Active MPC session identifier.
#' @return list(stored, n_clusters, n_pairs).
#' @export
#' @noRd
dsvertGEEAR1OrderReceiveDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("dsvert_gee_ar1_order_blob", ss)
  if (is.null(blob)) stop("AR1 order blob missing", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport_sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  next_index <- as.integer(payload$next_index)
  prev_index <- as.integer(payload$prev_index)
  n <- as.integer(payload$n)
  if (length(next_index) != n || length(prev_index) != n) {
    stop("invalid AR1 order payload length", call. = FALSE)
  }
  ss$dsvert_gee_ar1_next_index <- next_index
  ss$dsvert_gee_ar1_prev_index <- prev_index
  ss$dsvert_gee_ar1_n <- n
  ss$dsvert_gee_ar1_n_clusters <- as.integer(payload$n_clusters)
  ss$dsvert_gee_ar1_n_pairs <- as.integer(payload$n_pairs)
  ss$dsvert_gee_ar1_max_lag <- as.integer(payload$max_lag %||% 1L)
  list(stored = TRUE,
       n_clusters = ss$dsvert_gee_ar1_n_clusters,
       n_pairs = ss$dsvert_gee_ar1_n_pairs,
       max_lag = ss$dsvert_gee_ar1_max_lag)
}

.dsvert_ar1_decode_share <- function(x) {
  tryCatch(jsonlite::base64_dec(x),
           error = function(e) jsonlite::base64_dec(.base64url_to_base64(x)))
}

#' @title Transform an FP share by guarded AR1 order metadata
#' @description Locally shifts or masks a party's additive share vector using
#'   stored predecessor/successor indices. Both DCF parties apply the same
#'   deterministic transformation, so reconstruction yields the transformed
#'   plaintext vector without exposing that vector to the client.
#' @param source_key Session slot holding an n-vector FP share.
#' @param output_key Session slot for the transformed share.
#' @param transform One of \code{"lead"}, \code{"lag"}, \code{"nonlast"},
#'   \code{"nonfirst"}, or \code{"interior"}.
#' @param session_id Active MPC session identifier.
#' @param frac_bits Fixed-point fractional bits.
#' @param ring Integer 63 or 127.
#' @return list(stored, output_key, n, transform).
#' @export
#' @noRd
dsvertGEEAR1TransformShareDS <- function(
    source_key, output_key,
    transform = c("lead", "lag", "nonlast", "nonfirst", "interior"),
    session_id = NULL, frac_bits = 20L, ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.character(source_key) || length(source_key) != 1L ||
      !nzchar(source_key) || !is.character(output_key) ||
      length(output_key) != 1L || !nzchar(output_key)) {
    stop("source_key and output_key must be non-empty strings",
         call. = FALSE)
  }
  transform <- match.arg(transform)
  ss <- .S(session_id)
  share <- ss[[source_key]]
  if (is.null(share) || !nzchar(share)) {
    stop("share slot '", source_key, "' missing", call. = FALSE)
  }
  next_index <- ss$dsvert_gee_ar1_next_index
  prev_index <- ss$dsvert_gee_ar1_prev_index
  if (is.null(next_index) || is.null(prev_index)) {
    stop("AR1 order metadata missing", call. = FALSE)
  }
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  bytes <- if (ring == 127L) 16L else 8L
  raw_src <- .dsvert_ar1_decode_share(share)
  if (length(raw_src) %% bytes != 0L) {
    stop("share length is not aligned to ring element size", call. = FALSE)
  }
  n <- as.integer(length(raw_src) / bytes)
  if (length(next_index) != n || length(prev_index) != n) {
    stop("AR1 order metadata length does not match share length",
         call. = FALSE)
  }
  raw_out <- raw(length(raw_src))
  copy_record <- function(dst_i, src_i) {
    dst_start <- (dst_i - 1L) * bytes + 1L
    src_start <- (src_i - 1L) * bytes + 1L
    raw_out[dst_start:(dst_start + bytes - 1L)] <<-
      raw_src[src_start:(src_start + bytes - 1L)]
  }
  for (i in seq_len(n)) {
    src_i <- switch(transform,
      lead = next_index[[i]],
      lag = prev_index[[i]],
      nonlast = if (next_index[[i]] > 0L) i else 0L,
      nonfirst = if (prev_index[[i]] > 0L) i else 0L,
      interior = if (prev_index[[i]] > 0L && next_index[[i]] > 0L) i else 0L)
    if (src_i > 0L) copy_record(i, src_i)
  }
  ss[[output_key]] <- jsonlite::base64_enc(raw_out)
  list(stored = TRUE, output_key = output_key,
       n = n, transform = transform)
}

#' @title Per-cluster FP sum of a shared vector
#' @description Sum an FP share vector within each stored cluster. The output
#'   is still one additive scalar share per cluster; the client must aggregate
#'   the two DCF parties' outputs to recover the cluster-level sums.
#' @param share_key Session slot holding the n-vector FP share.
#' @param session_id Active MPC session identifier.
#' @param frac_bits Fixed-point fractional bits.
#' @param ring Integer 63 or 127.
#' @return list(per_cluster_fp, cluster_sizes, n_clusters).
#' @export
#' @noRd
dsvertPerClusterSumShareDS <- function(share_key, session_id = NULL,
                                       frac_bits = 20L, ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  share <- ss[[share_key]]
  if (is.null(share)) {
    stop("share slot '", share_key, "' missing", call. = FALSE)
  }
  ids <- ss$dsvert_cluster_ids
  if (is.null(ids)) stop("cluster IDs missing", call. = FALSE)
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  lvls <- seq_len(max(ids))
  sizes <- tabulate(ids, nbins = length(lvls))
  .dsvert_guard_cluster_sizes(sizes, "per-cluster share aggregate")
  out_fp <- character(length(lvls))
  for (ci in seq_along(lvls)) {
    mask <- as.numeric(ids == lvls[[ci]])
    mask_fp <- .callMpcTool("k2-float-to-fp",
      list(values = mask, frac_bits = as.integer(frac_bits),
           ring = ring_tag))$fp_data
    masked <- .callMpcTool("k2-fp-vec-mul", list(
      a = share, b = mask_fp, frac_bits = as.integer(frac_bits),
      ring = ring_tag))
    s <- .callMpcTool("k2-fp-sum", list(fp_data = masked$result,
                                         ring = ring_tag))
    out_fp[[ci]] <- s$sum_fp
  }
  list(per_cluster_fp = out_fp,
       cluster_sizes = sizes,
       n_clusters = length(lvls))
}

#' @title Store a share of one minus the current binomial mean
#' @description Computes additive shares of \eqn{1-p} from the current
#'   \code{secure_mu_share} slot, used by GLMM to form
#'   \eqn{p(1-p)} with Beaver multiplication.
#' @param output_key Session slot for the result.
#' @param is_party0 Logical; TRUE for the first DCF party.
#' @param session_id Active MPC session identifier.
#' @param frac_bits Fixed-point fractional bits.
#' @param ring Integer 63 or 127.
#' @return list(stored, output_key, n).
#' @export
#' @noRd
dsvertGLMMOneMinusMuDS <- function(output_key = "glmm_one_minus_mu_share",
                                   is_party0 = FALSE,
                                   session_id = NULL,
                                   frac_bits = 20L,
                                   ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$secure_mu_share)) {
    stop("secure_mu_share missing", call. = FALSE)
  }
  n <- as.integer(ss$k2_x_n)
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  one_vals <- if (isTRUE(is_party0)) rep(1, n) else rep(0, n)
  one_fp <- .callMpcTool("k2-float-to-fp", list(
    values = one_vals, frac_bits = as.integer(frac_bits), ring = ring_tag))
  res <- .callMpcTool("k2-fp-sub", list(
    a = one_fp$fp_data, b = ss$secure_mu_share,
    frac_bits = as.integer(frac_bits), ring = ring_tag))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key, n = n)
}
