#' @title Cluster-size aggregate (for LMM / GEE)
#' @description Return a vector of cluster sizes for an ID column on the
#'   outcome server. Only per-cluster counts leave the server; individual
#'   memberships are not revealed to the client. Subject to the standard
#'   \code{datashield.privacyLevel} suppression: clusters with fewer than
#'   the privacy threshold are returned as 0.
#' @param data_name Character. Aligned data-frame name.
#' @param cluster_col Character. Column holding the cluster id.
#' @return list(sizes: integer vector; n_clusters; n_total).
#' @export
dsvertClusterSizesDS <- function(data_name, cluster_col) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data))
    stop("cluster_col not found", call. = FALSE)
  id <- data[[cluster_col]]
  tbl <- as.integer(table(id))
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && privacy_min > 0L) {
    tbl[tbl > 0L & tbl < privacy_min] <- 0L
  }
  list(sizes = tbl,
       n_clusters = length(tbl),
       n_total = sum(tbl))
}

#' @title Per-cluster residual sums for LMM REML updates
#' @description Given a plaintext \code{betahat} and intercept from the
#'   client, compute per-cluster
#'     \eqn{\sum_{ij} r_{ij}} and \eqn{\sum_{ij} r_{ij}^2}
#'   and return the aggregate vector (one scalar per cluster). Clusters
#'   below the privacy threshold are suppressed.
#' @param data_name Character. Aligned data-frame name.
#' @param y_var Outcome column (on this server).
#' @param x_names Predictor names on this server.
#' @param betahat Coefficients for \code{x_names}.
#' @param intercept Scalar intercept.
#' @param cluster_col Cluster column.
#' @return list(rsum_per_cluster, rss_per_cluster, n_per_cluster).
#' @export
dsvertClusterResidualsDS <- function(data_name, y_var, x_names,
                                      betahat, intercept = 0,
                                      cluster_col) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!y_var %in% names(data)) stop("y_var not found", call. = FALSE)
  if (!cluster_col %in% names(data))
    stop("cluster_col not found", call. = FALSE)
  missing_x <- setdiff(x_names, names(data))
  if (length(missing_x) > 0L) {
    stop("x_names not local: ", paste(missing_x, collapse = ", "),
         call. = FALSE)
  }
  y <- data[[y_var]]
  X <- as.matrix(data[, x_names, drop = FALSE])
  fit <- as.numeric(intercept) + drop(X %*% as.numeric(betahat))
  r <- y - fit
  r2 <- r * r
  id <- data[[cluster_col]]
  by_cluster <- split(seq_len(nrow(data)), id)
  rsum <- vapply(by_cluster, function(ix) sum(r[ix]), numeric(1L))
  rss <- vapply(by_cluster, function(ix) sum(r2[ix]), numeric(1L))
  npc <- vapply(by_cluster, length, integer(1L))
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && privacy_min > 0L) {
    mask <- npc < privacy_min
    rsum[mask] <- 0; rss[mask] <- 0; npc[mask] <- 0L
  }
  list(rsum_per_cluster = as.numeric(rsum),
       rss_per_cluster  = as.numeric(rss),
       n_per_cluster    = as.integer(npc))
}

#' @title Expand a per-cluster weights vector into a per-patient column
#' @description Given a vector of weights indexed by cluster in the
#'   order returned by \code{dsvertClusterSizesDS}, write a per-patient
#'   weights column into the data frame. Used by \code{ds.vertLMM} to
#'   implement the REML variance-ratio-weighted inner fit without ever
#'   materialising an \eqn{n}-vector on the client.
#' @param data_name Character. Aligned data-frame name.
#' @param cluster_col Character. Cluster column.
#' @param weights_per_cluster Numeric vector (length = n_clusters) in
#'   the order of \code{sort(unique(data[[cluster_col]]))} (matching the
#'   \code{table()} order returned by \code{dsvertClusterSizesDS}).
#' @param output_column Column name for the expanded weights vector.
#' @return list(n_expanded, output_column).
#' @export
dsvertExpandClusterWeightsDS <- function(data_name, cluster_col,
                                          weights_per_cluster,
                                          output_column = "__dsvert_lmm_w") {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data))
    stop("cluster_col not found", call. = FALSE)
  id <- data[[cluster_col]]
  lvls <- sort(unique(id))
  if (length(weights_per_cluster) != length(lvls)) {
    stop("weights_per_cluster length (", length(weights_per_cluster),
         ") does not match n_clusters (", length(lvls), ")",
         call. = FALSE)
  }
  map <- stats::setNames(as.numeric(weights_per_cluster), as.character(lvls))
  data[[output_column]] <- as.numeric(map[as.character(id)])
  assign(data_name, data, envir = parent.frame())
  list(n_expanded = nrow(data), output_column = output_column)
}
