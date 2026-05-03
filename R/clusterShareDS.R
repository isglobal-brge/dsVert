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
