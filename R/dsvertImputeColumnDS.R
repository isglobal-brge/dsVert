#' @title Server-side Bayesian-ridge imputation of a single column
#' @description Draw a Bayesian-ridge posterior predictive imputation
#'   for the missing cells of a column, using the other
#'   complete-case columns of the aligned data frame as predictors.
#'   The imputed column is written back into the data frame under
#'   \code{output_column}. The client never sees the imputed values;
#'   only an aggregate "n imputed" count.
#'
#'   Fits a Bayesian ridge regression with default hyperparameters
#'   \eqn{\alpha_0 = 1, \beta_0 = 1}, draws a posterior sample
#'   \eqn{(\beta^*, \sigma^{2*})}, and imputes each missing cell as
#'   \eqn{x_\ast^T \beta^* + \sigma^* \epsilon},
#'   \eqn{\epsilon \sim N(0, 1)}.
#'
#'   For categorical \code{impute_column}: fits a logistic / multinomial
#'   ridge classifier and samples from the posterior predictive class
#'   distribution. (First pass: supports numeric and binary factor
#'   columns; K>2 factor support is Month 4.)
#'
#' @param data_name Character. Aligned data-frame name.
#' @param impute_column Character. Column with missingness.
#' @param output_column Character. Name under which the imputed column
#'   is written.
#' @param seed Integer. RNG seed for reproducible draws.
#' @return List with components \code{n_imputed} (count of cells
#'   imputed), \code{n_observed} (count with non-missing original
#'   values), \code{method} ("bayesian_ridge" or "bayesian_logit").
#' @export
dsvertImputeColumnDS <- function(data_name, impute_column,
                                  output_column = NULL,
                                  seed = 1L) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!impute_column %in% names(data)) {
    stop("impute_column '", impute_column, "' not found",
         call. = FALSE)
  }
  if (is.null(output_column) || !nzchar(output_column)) {
    output_column <- paste0(impute_column, "_imputed")
  }

  y <- data[[impute_column]]
  miss <- is.na(y)
  n_missing <- sum(miss)
  n_observed <- sum(!miss)
  if (n_missing == 0L) {
    data[[output_column]] <- y
    assign(data_name, data, envir = parent.frame())
    return(list(n_imputed = 0L, n_observed = n_observed,
                method = "none"))
  }

  other_cols <- setdiff(names(data), c(impute_column, output_column))
  # Keep only numeric/complete predictors to avoid leaking structure.
  keep <- character(0)
  for (c in other_cols) {
    col <- data[[c]]
    if (is.numeric(col) && !any(is.na(col))) keep <- c(keep, c)
  }
  if (length(keep) == 0L) {
    stop("no complete numeric predictors available for imputation",
         call. = FALSE)
  }

  set.seed(as.integer(seed))

  if (is.numeric(y)) {
    X_obs <- as.matrix(data[!miss, keep, drop = FALSE])
    y_obs <- y[!miss]
    # Bayesian ridge: beta_post ~ N((X^T X + alpha I)^-1 X^T y,
    #                                sigma^2 (X^T X + alpha I)^-1)
    alpha <- 1
    XtX <- crossprod(X_obs)
    Xty <- crossprod(X_obs, y_obs)
    prec <- XtX + alpha * diag(ncol(X_obs))
    Sigma <- tryCatch(solve(prec), error = function(e) {
      solve(prec + 1e-6 * diag(ncol(X_obs))) })
    beta_hat <- drop(Sigma %*% Xty)
    resid <- y_obs - X_obs %*% beta_hat
    sigma2_hat <- sum(resid^2) / max(length(y_obs) - ncol(X_obs), 1L)
    # Posterior draw
    L <- chol(Sigma * sigma2_hat + 1e-12 * diag(ncol(X_obs)))
    beta_draw <- beta_hat + drop(t(L) %*% stats::rnorm(ncol(X_obs)))
    sigma_draw <- sqrt(sigma2_hat)
    X_miss <- as.matrix(data[miss, keep, drop = FALSE])
    imp <- drop(X_miss %*% beta_draw) +
           sigma_draw * stats::rnorm(n_missing)
    y_out <- y
    y_out[miss] <- imp
    method <- "bayesian_ridge"
  } else {
    yf <- as.factor(y)
    lvls <- levels(yf)
    if (length(lvls) != 2L) {
      stop("multinomial imputation (>2 levels) scheduled for Month 4",
           call. = FALSE)
    }
    y01 <- as.integer(yf) - 1L
    X_obs <- as.matrix(data[!miss, keep, drop = FALSE])
    y_obs <- y01[!miss]
    alpha <- 1
    # IRLS Newton step for Bayesian logit posterior mode
    beta <- rep(0, ncol(X_obs))
    for (it in seq_len(25L)) {
      eta <- X_obs %*% beta
      p <- 1 / (1 + exp(-eta))
      W <- as.numeric(p * (1 - p)); W <- pmax(W, 1e-6)
      H <- crossprod(X_obs * W, X_obs) + alpha * diag(ncol(X_obs))
      g <- crossprod(X_obs, y_obs - p) - alpha * beta
      step <- tryCatch(solve(H, g), error = function(e) {
        solve(H + 1e-6 * diag(ncol(X_obs)), g) })
      beta <- beta + drop(step)
      if (max(abs(step)) < 1e-6) break
    }
    Sigma <- tryCatch(solve(H), error = function(e) {
      solve(H + 1e-6 * diag(ncol(X_obs))) })
    L <- chol(Sigma + 1e-12 * diag(ncol(X_obs)))
    beta_draw <- beta + drop(t(L) %*% stats::rnorm(ncol(X_obs)))
    X_miss <- as.matrix(data[miss, keep, drop = FALSE])
    p_miss <- 1 / (1 + exp(-drop(X_miss %*% beta_draw)))
    draws <- stats::rbinom(n_missing, 1L, p_miss)
    y_out <- y
    y_out[miss] <- lvls[draws + 1L]
    y_out <- factor(y_out, levels = lvls)
    method <- "bayesian_logit"
  }

  data[[output_column]] <- y_out
  assign(data_name, data, envir = parent.frame())
  list(n_imputed = as.integer(n_missing),
       n_observed = as.integer(n_observed),
       method = method)
}
