#' @title Cluster-mean-center columns for random-intercept GLS (LMM)
#' @description Apply the Laird-Ware closed-form GLS transform for a
#'   random-intercept LMM. For each requested column \code{v} and each
#'   cluster \code{i}, compute
#'     \deqn{\tilde v_j = v_j - \lambda_i \bar v_i, \quad j \in C_i}
#'   where \eqn{\bar v_i} is the within-cluster mean of \code{v} and
#'   \eqn{\lambda_i = 1 - \sqrt{\sigma^2 / (\sigma^2 + n_i \sigma_b^2)}}.
#'   OLS on the transformed design matrix (with an explicit
#'   cluster-specific intercept column \eqn{1 - \lambda_i}) yields the
#'   exact REML / GLS fixed-effects estimate -- matches
#'   \code{lme4::lmer} to machine precision.
#'
#'   Operates locally on the server: no cross-server traffic, no
#'   Beaver MPC. Just a per-cluster mean subtraction using the cluster
#'   IDs previously broadcast by \code{dsvertLMMBroadcastClusterIDsDS}.
#'
#' @param data_name Character. Aligned data frame on this server.
#' @param columns   Character vector of columns to transform.
#' @param lambda_per_cluster Numeric vector of length \code{n_clusters}
#'   giving \eqn{\lambda_i} (may include zeros for privacy-suppressed
#'   cluster ids).
#' @param output_suffix Suffix appended to the transformed column name.
#'   Default \code{"_lmmtx"}. Set to \code{""} to overwrite in place.
#' @param create_intercept Whether to add a
#'   \eqn{(1 - \lambda_i)} column (per-observation). Default TRUE on
#'   the server that holds the cluster_col; only one server should
#'   create it (the rest have it relayed via PSI-aligned rows).
#' @param intercept_col Name for the created intercept column. Default
#'   \code{"__dsvert_lmm_int"}.
#' @param session_id MPC session id.
#' @return list(n, columns_transformed, intercept_col, n_clusters).
#' @export
dsvertLMMGLSTransformDS <- function(data_name, columns,
                                     lambda_per_cluster,
                                     output_suffix = "_lmmtx",
                                     create_intercept = TRUE,
                                     intercept_col = "__dsvert_lmm_int",
                                     session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  ss <- .S(session_id)
  ids <- ss$k2_lmm_cluster_ids
  if (is.null(ids))
    stop("cluster IDs missing in session; call ",
         "dsvertLMMBroadcastClusterIDsDS / ReceiveClusterIDsDS first",
         call. = FALSE)
  if (length(ids) != nrow(data))
    stop("cluster id length != nrow(data)", call. = FALSE)
  lambda <- as.numeric(lambda_per_cluster)
  if (length(lambda) < max(ids, na.rm = TRUE))
    stop("lambda_per_cluster too short", call. = FALSE)
  lambda_per_obs <- lambda[ids]
  missing <- character(0)
  columns_done <- character(0)
  for (v in columns) {
    if (!v %in% names(data)) { missing <- c(missing, v); next }
    x <- as.numeric(data[[v]])
    # Per-cluster means. Use tapply for NA-robust aggregation.
    cluster_means <- tapply(x, ids, function(z) mean(z, na.rm = TRUE))
    means_per_obs <- as.numeric(
      cluster_means[as.character(ids)])
    out <- x - lambda_per_obs * means_per_obs
    out[is.na(out)] <- 0
    out_name <- if (nzchar(output_suffix)) paste0(v, output_suffix) else v
    data[[out_name]] <- out
    columns_done <- c(columns_done, out_name)
  }
  if (isTRUE(create_intercept)) {
    val <- 1 - lambda_per_obs
    val[is.na(val)] <- 1
    data[[intercept_col]] <- val
  }
  assign(data_name, data, envir = parent.frame())
  list(n = nrow(data),
       columns_transformed = length(columns_done),
       columns_out = columns_done,
       missing = missing,
       intercept_col = if (isTRUE(create_intercept)) intercept_col else NA_character_,
       n_clusters = length(lambda))
}

#' @title Aggregate sums weighted by (1 - lambda_i) for LMM GLS intercept
#' @description Compute the scalar aggregates
#'   \eqn{\sum_i (1 - \lambda_{c(i)})^2},
#'   \eqn{\sum_i (1 - \lambda_{c(i)})},
#'   and \eqn{\sum_i (1 - \lambda_{c(i)}) v_i} for each requested column
#'   \eqn{v}. Used client-side to recover the exact GLS intercept
#'   \deqn{\hat\beta_0 = \frac{\sum (1-\lambda_i) y_i - \sum_k \hat\beta_k
#'                                          \sum (1-\lambda_i) x_{ki}}
#'                                 {\sum (1-\lambda_i)^2}}
#'   without having to rely on a no-intercept OLS fit (which the K=2
#'   Beaver loop cannot do exactly when the design is standardised).
#'
#'   Only returns scalar dot products -- aggregate, no per-patient
#'   disclosure.
#' @param data_name Data frame on this server.
#' @param columns Character vector of local columns to aggregate.
#' @param lambda_per_cluster Numeric vector, length n_clusters.
#' @param session_id MPC session id (cluster IDs must be broadcast).
#' @return named list with \code{sum_omlambda_sq}, \code{sum_omlambda},
#'   \code{n}, and \code{sum_omlambda_\{col\}} per requested column.
#' @export
dsvertLMMGLSAggregatesDS <- function(data_name, columns,
                                      lambda_per_cluster,
                                      session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  ss <- .S(session_id)
  ids <- ss$k2_lmm_cluster_ids
  if (is.null(ids))
    stop("cluster IDs missing; broadcast first", call. = FALSE)
  lambda <- as.numeric(lambda_per_cluster)
  one_minus_lambda <- 1 - lambda[ids]
  out <- list(
    sum_omlambda_sq = sum(one_minus_lambda^2, na.rm = TRUE),
    sum_omlambda    = sum(one_minus_lambda, na.rm = TRUE),
    n               = length(one_minus_lambda))
  for (v in columns) {
    if (v %in% names(data)) {
      out[[paste0("sum_omlambda_", v)]] <-
        sum(one_minus_lambda * as.numeric(data[[v]]), na.rm = TRUE)
    }
  }
  out
}

