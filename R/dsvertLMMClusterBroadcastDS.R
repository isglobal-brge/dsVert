#' @title Broadcast per-patient cluster IDs to the peer (LMM exact)
#' @description On the outcome server (which holds the cluster
#'   membership column plaintext), encode the cluster IDs as an integer
#'   vector and transport-encrypt them to the peer so both DCF parties
#'   can compute per-cluster aggregates of their own r / r^2 shares.
#'
#'   This is the documented LMM inter-server leakage tier
#'   (cluster-ID membership, see V2_PROGRESS disclosure table). The
#'   shared cluster IDs are plaintext between the two DCF parties but
#'   NEVER reach the analyst client.
#' @param data_name Aligned data frame.
#' @param cluster_col Cluster column.
#' @param peer_pk Transport pk of the peer (base64url).
#' @param session_id MPC session id.
#' @return list(peer_blob, n_clusters, levels)
#' @export
dsvertLMMBroadcastClusterIDsDS <- function(data_name, cluster_col,
                                            peer_pk,
                                            session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data))
    stop("cluster_col not found", call. = FALSE)
  ids <- data[[cluster_col]]
  lvls <- sort(unique(ids))
  ids_int <- as.integer(match(ids, lvls))
  ss <- .S(session_id)
  ss$k2_lmm_cluster_ids <- ids_int
  ss$k2_lmm_cluster_levels <- as.character(lvls)
  payload <- list(ids = ids_int, levels = as.character(lvls))
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(payload_json))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = payload_b64, recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed),
       n_clusters = length(lvls),
       levels = as.character(lvls))
}

#' @title Receive + store peer's cluster IDs (LMM exact)
#' @description Per-party aggregate. Consume the relayed blob, decrypt,
#'   and store the integer cluster ID vector under
#'   \code{ss$k2_lmm_cluster_ids}.
#' @export
dsvertLMMReceiveClusterIDsDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("k2_lmm_cluster_ids_blob", ss)
  if (is.null(blob)) stop("cluster-ID blob missing", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport_sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$k2_lmm_cluster_ids <- as.integer(payload$ids)
  ss$k2_lmm_cluster_levels <- as.character(payload$levels)
  list(stored = TRUE, n_clusters = length(ss$k2_lmm_cluster_levels))
}

#' @title Per-cluster FP sum of a session share vector (LMM exact)
#' @description Sum \code{ss[[share_key]]} within each cluster defined
#'   by \code{ss$k2_lmm_cluster_ids}, returning one base64 FP scalar
#'   share per cluster. Linear op preserves additive sharing: the two
#'   parties' outputs aggregate (client-side k2-ring63-aggregate) to the
#'   per-cluster plaintext sum.
#'
#'   Aggregates only; no per-patient information returns to the client.
#' @param share_key Session slot holding the n-vector FP share.
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20).
#' @return list(per_cluster_fp: K-vector of base64 FP scalars,
#'              cluster_sizes, n_clusters).
#' @export
dsvertLMMPerClusterSumDS <- function(share_key, session_id = NULL,
                                      frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  share <- ss[[share_key]]
  if (is.null(share)) {
    stop("share slot '", share_key, "' missing", call. = FALSE)
  }
  ids <- ss$k2_lmm_cluster_ids
  if (is.null(ids)) {
    stop("cluster IDs missing; broadcast first via ",
         "dsvertLMMBroadcastClusterIDsDS / ReceiveClusterIDsDS",
         call. = FALSE)
  }
  n <- length(ids)
  lvls <- seq_len(max(ids))
  sizes <- tabulate(ids, nbins = length(lvls))
  out_fp <- character(length(lvls))
  for (ci in seq_along(lvls)) {
    mask <- as.numeric(ids == lvls[ci])
    mask_fp <- .callMpcTool("k2-float-to-fp",
      list(values = mask, frac_bits = as.integer(frac_bits)))$fp_data
    masked <- .callMpcTool("k2-fp-vec-mul", list(
      a = share, b = mask_fp,
      frac_bits = as.integer(frac_bits)))
    s <- .callMpcTool("k2-fp-sum", list(fp_data = masked$result))
    out_fp[ci] <- s$sum_fp
  }
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && privacy_min > 0L) {
    sizes[sizes > 0L & sizes < privacy_min] <- 0L
  }
  list(per_cluster_fp = out_fp,
       cluster_sizes = sizes,
       n_clusters = length(lvls))
}

#' @title Global FP sum of a session share vector (LMM exact)
#' @description Sum ALL elements of \code{ss[[share_key]]}, returning
#'   one base64 FP scalar share. Used for total \eqn{\sum r^2}.
#' @export
dsvertLMMGlobalSumDS <- function(share_key, session_id = NULL,
                                  frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  share <- ss[[share_key]]
  if (is.null(share)) stop("share slot missing", call. = FALSE)
  s <- .callMpcTool("k2-fp-sum", list(fp_data = share))
  list(sum_fp = s$sum_fp)
}
