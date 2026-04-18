#' @title Materialise r^2 as a column on the outcome server (GEE sandwich prep)
#' @description On the outcome server (which holds \code{y} plaintext),
#'   compute the Pearson (Gaussian: plain) residual squared
#'   \eqn{r_i^2 = (y_i - x_i^T \hat\beta - \hat\beta_0)^2} using the
#'   plaintext \code{betahat} broadcast by the client, and write the
#'   result into the aligned data frame under \code{r2_column}. Used as
#'   the \code{weights=} column for the second-stage fit in
#'   \code{ds.vertGEE}, which produces the Liang-Zeger meat matrix
#'   without ever materialising \eqn{n}-length residuals on the client.
#'
#'   Only the outcome server participates; features on other servers
#'   are NOT consulted here, because the fitted values
#'   \eqn{x_i^T \hat\beta} only use the \code{x_names} provided (which
#'   must all live on the outcome server for the Gaussian sandwich to
#'   be tractable from this helper alone; a cross-server r^2 needs a
#'   Beaver path that is part of Month 4).
#'
#' @param data_name Character.
#' @param y_var Outcome column.
#' @param x_names Character vector of predictor names that live on this
#'   server.
#' @param betahat Numeric vector of coefficients matching \code{x_names}
#'   (plaintext; the client broadcasts these).
#' @param intercept Scalar intercept (default 0).
#' @param r2_column Name of the new column (default "__dsvert_r2").
#' @return list(n_observed, n_missing, method, scale) -- no per-patient
#'   values returned.
#' @export
dsvertPearsonR2ColDS <- function(data_name, y_var, x_names,
                                  betahat, intercept = 0,
                                  r2_column = "__dsvert_r2") {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!y_var %in% names(data)) stop("y_var not found", call. = FALSE)
  missing_x <- setdiff(x_names, names(data))
  if (length(missing_x) > 0L) {
    stop("x_names not local to this server: ",
         paste(missing_x, collapse = ", "),
         ". Cross-server r^2 requires the Beaver path (Month 4).",
         call. = FALSE)
  }
  if (length(x_names) != length(betahat)) {
    stop("length(x_names) must equal length(betahat)", call. = FALSE)
  }
  y <- data[[y_var]]
  X <- as.matrix(data[, x_names, drop = FALSE])
  fit <- as.numeric(intercept) + drop(X %*% as.numeric(betahat))
  r <- y - fit
  r2 <- r * r
  data[[r2_column]] <- as.numeric(r2)
  assign(data_name, data, envir = parent.frame())
  list(n_observed = sum(!is.na(y)),
       n_missing = sum(is.na(y)),
       method = "gaussian_plain_residual_squared")
}
