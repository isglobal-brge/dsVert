#' @title Calculate GLM Deviance Component (Server-Side)
#' @description Server-side aggregate function that calculates the deviance
#'   contribution from this partition for a fitted GLM. Used for model
#'   evaluation in vertically partitioned data.
#'
#' @param data_name Character string. Name of the data frame containing
#'   the response variable in the server environment.
#' @param y_name Character string. Name of the response variable.
#' @param eta Numeric vector. Total linear predictor (sum of all partitions).
#' @param family Character string. GLM family: "gaussian", "binomial",
#'   "poisson", "Gamma", or "inverse.gaussian". Default is "gaussian".
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{deviance}: Total deviance contribution
#'     \item \code{null_deviance}: Null model deviance (intercept only)
#'     \item \code{n_obs}: Number of observations
#'   }
#'
#' @details
#' The deviance is calculated as twice the difference between the saturated
#' model log-likelihood and the fitted model log-likelihood.
#'
#' Deviance formulas by family:
#' \itemize{
#'   \item \strong{Gaussian}: \eqn{\sum (y - \mu)^2}
#'   \item \strong{Binomial}: \eqn{2 \sum [y \log(y/\mu) + (1-y) \log((1-y)/(1-\mu))]}
#'   \item \strong{Poisson}: \eqn{2 \sum [y \log(y/\mu) - (y - \mu)]}
#'   \item \strong{Gamma}: \eqn{2 \sum [-\log(y/\mu) + (y - \mu)/\mu]}
#'   \item \strong{Inverse Gaussian}: \eqn{\sum (y - \mu)^2 / (\mu^2 y)}
#' }
#'
#' Privacy is preserved because only aggregate deviance values are returned,
#' not individual residuals.
#'
#' @seealso \code{\link{glmPartialFitDS}} for model fitting
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' # result <- datashield.aggregate(conn,
#' #   "glmDevianceDS('D', 'outcome', eta_total, 'gaussian')")
#' }
#'
#' @export
glmDevianceDS <- function(data_name, y_name, eta, family = "gaussian") {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(y_name) || length(y_name) != 1) {
    stop("y_name must be a single character string", call. = FALSE)
  }
  if (!family %in% c("gaussian", "binomial", "poisson", "Gamma", "inverse.gaussian")) {
    stop("family must be 'gaussian', 'binomial', 'poisson', 'Gamma', or 'inverse.gaussian'",
         call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  if (!y_name %in% names(data)) {
    stop("Variable '", y_name, "' not found in data", call. = FALSE)
  }

  # Extract response
  y <- as.numeric(data[[y_name]])
  n <- length(y)

  # Validate dimensions
  if (length(eta) != n) {
    stop("eta length (", length(eta), ") must match n_obs (", n, ")",
         call. = FALSE)
  }

  # Privacy check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  }

  # Compute mu from eta based on family
  if (family == "gaussian") {
    mu <- eta
    mu_null <- mean(y)
  } else if (family == "binomial") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- 1 / (1 + exp(-eta))
    mu <- pmax(pmin(mu, 1 - 1e-10), 1e-10)
    mu_null <- mean(y)
    mu_null <- pmax(pmin(mu_null, 1 - 1e-10), 1e-10)
  } else if (family == "poisson") {
    eta <- pmin(eta, 20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    mu_null <- mean(y)
    mu_null <- pmax(mu_null, 1e-10)
  } else if (family == "Gamma") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    mu_null <- mean(y)
    mu_null <- pmax(mu_null, 1e-10)
  } else if (family == "inverse.gaussian") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    mu_null <- mean(y)
    mu_null <- pmax(mu_null, 1e-10)
  }

  # Calculate deviance based on family
  if (family == "gaussian") {
    deviance <- sum((y - mu)^2)
    null_deviance <- sum((y - mu_null)^2)

  } else if (family == "binomial") {
    # Handle edge cases for log(0)
    deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) {
        deviance <- deviance + y[i] * log(y[i] / mu[i])
      }
      if (y[i] < 1) {
        deviance <- deviance + (1 - y[i]) * log((1 - y[i]) / (1 - mu[i]))
      }
    }
    deviance <- 2 * deviance

    null_deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) {
        null_deviance <- null_deviance + y[i] * log(y[i] / mu_null)
      }
      if (y[i] < 1) {
        null_deviance <- null_deviance + (1 - y[i]) * log((1 - y[i]) / (1 - mu_null))
      }
    }
    null_deviance <- 2 * null_deviance

  } else if (family == "poisson") {
    deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) {
        deviance <- deviance + y[i] * log(y[i] / mu[i])
      }
      deviance <- deviance - (y[i] - mu[i])
    }
    deviance <- 2 * deviance

    null_deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) {
        null_deviance <- null_deviance + y[i] * log(y[i] / mu_null)
      }
      null_deviance <- null_deviance - (y[i] - mu_null)
    }
    null_deviance <- 2 * null_deviance

  } else if (family == "Gamma") {
    deviance <- 2 * sum(-log(y / mu) + (y - mu) / mu)
    null_deviance <- 2 * sum(-log(y / mu_null) + (y - mu_null) / mu_null)

  } else if (family == "inverse.gaussian") {
    deviance <- sum((y - mu)^2 / (mu^2 * y))
    null_deviance <- sum((y - mu_null)^2 / (mu_null^2 * y))
  }

  list(
    deviance = deviance,
    null_deviance = null_deviance,
    n_obs = n
  )
}
