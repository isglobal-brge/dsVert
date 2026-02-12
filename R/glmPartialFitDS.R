#' @title GLM Partial Fit via Block Coordinate Descent (Server-Side)
#' @description Server-side aggregate function that performs one iteration
#'   of the Block Coordinate Descent algorithm for fitting Generalized Linear
#'   Models on vertically partitioned data.
#'
#' @param data_name Character string. Name of the data frame containing
#'   predictor variables in the server environment.
#' @param y_name Character string. Name of the response variable in the
#'   data frame.
#' @param x_vars Character vector. Names of predictor variables to use
#'   from this partition.
#' @param eta_other Numeric vector. Linear predictor contribution from
#'   other partitions (sum of X_j * beta_j for j != current partition).
#' @param beta_current Numeric vector. Current coefficient estimates for
#'   this partition's variables.
#' @param family Character string. GLM family: "gaussian", "binomial",
#'   "poisson", "Gamma", or "inverse.gaussian". Default is "gaussian".
#' @param lambda Numeric. L2 regularization parameter. Default is 1e-4.
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{beta}: Updated coefficient estimates for this partition
#'     \item \code{eta}: Linear predictor contribution from this partition
#'       (X * beta_new) to share with other partitions
#'     \item \code{converged}: Logical indicating if update was stable
#'   }
#'
#' @details
#' This function implements one step of the Block Coordinate Descent (BCD)
#' algorithm for distributed GLM fitting. The algorithm iteratively updates
#' coefficients for each partition while holding others fixed.
#'
#' For each partition i, the update is:
#' \deqn{\beta_i^{new} = (X_i^T W X_i + \lambda I)^{-1} X_i^T W (z - \eta_{-i})}
#'
#' Where:
#' \itemize{
#'   \item W = weight matrix (depends on family)
#'   \item z = working response (depends on family)
#'   \item \eqn{\eta_{-i}} = sum of linear predictors from other partitions
#' }
#'
#' The function supports five families:
#' \itemize{
#'   \item \strong{Gaussian}: Identity link, W = I, z = y
#'   \item \strong{Binomial}: Logit link, W = diag(mu*(1-mu))
#'   \item \strong{Poisson}: Log link, W = diag(mu)
#'   \item \strong{Gamma}: Log link, W = I (constant weights)
#'   \item \strong{Inverse Gaussian}: Log link, W = diag(1/mu)
#' }
#'
#' @references
#' van Kesteren, E.J. et al. (2019). Privacy-preserving generalized linear
#' models using distributed block coordinate descent. arXiv:1911.05935.
#'
#' @seealso \code{\link[dsVertClient]{ds.vertGLM}} for client-side interface
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' # result <- datashield.aggregate(conn,
#' #   "glmPartialFitDS('D', 'outcome', c('age', 'weight'),
#' #     eta_other, beta_current, 'gaussian', 1e-4)")
#' }
#'
#' @export
glmPartialFitDS <- function(data_name, y_name, x_vars, eta_other,
                             beta_current, family = "gaussian",
                             lambda = 1e-4, intercept = FALSE) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(y_name) || length(y_name) != 1) {
    stop("y_name must be a single character string", call. = FALSE)
  }
  if (!is.character(x_vars) || length(x_vars) == 0) {
    stop("x_vars must be a non-empty character vector", call. = FALSE)
  }
  if (!family %in% c("gaussian", "binomial", "poisson", "Gamma", "inverse.gaussian")) {
    stop("family must be 'gaussian', 'binomial', 'poisson', 'Gamma', or 'inverse.gaussian'",
         call. = FALSE)
  }

  # Get data from server environment (checks .mhe_storage for standardized data)
  data <- .resolveData(data_name, parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Check variables exist
  all_vars <- c(y_name, x_vars)
  missing_vars <- setdiff(all_vars, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found: ", paste(missing_vars, collapse = ", "),
         call. = FALSE)
  }

  # Extract data
  y <- as.numeric(data[[y_name]])
  X <- as.matrix(data[, x_vars, drop = FALSE])

  # Prepend intercept column if requested
  if (isTRUE(intercept)) {
    X <- cbind("(Intercept)" = rep(1, nrow(X)), X)
  }

  n <- length(y)
  p <- ncol(X)

  # Validate dimensions
  if (length(eta_other) != n) {
    stop("eta_other length (", length(eta_other), ") must match n_obs (", n, ")",
         call. = FALSE)
  }
  if (length(beta_current) != p) {
    stop("beta_current length (", length(beta_current),
         ") must match number of variables (", p, ")", call. = FALSE)
  }

  # Disclosure controls (dsBase pattern)
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  }

  # GLM disclosure checks: saturation + binary variable small cells
  .check_glm_disclosure(X, y)

  # Compute total linear predictor
  eta <- as.vector(eta_other + X %*% beta_current)

  # Compute mu, W, z based on family
  if (family == "gaussian") {
    mu <- eta
    w <- rep(1, n)
    z <- y
  } else if (family == "binomial") {
    # Clip eta to [-20, 20] to prevent exp() overflow/underflow.
    # exp(20) ~ 4.9e8, so sigmoid is effectively 0 or 1 beyond this range.
    eta <- pmax(pmin(eta, 20), -20)
    mu <- 1 / (1 + exp(-eta))
    # Clamp mu away from 0 and 1 to avoid division by zero in IRLS weights
    # w = mu*(1-mu) and working response z = eta + (y-mu)/w.
    mu <- pmax(pmin(mu, 1 - 1e-10), 1e-10)
    w <- mu * (1 - mu)
    z <- eta + (y - mu) / w
  } else if (family == "poisson") {
    # Clip eta at 20 to prevent exp() overflow (exp(20) ~ 4.9e8).
    # No lower clip needed: exp(-x) approaches 0 gracefully.
    eta <- pmin(eta, 20)
    mu <- exp(eta)
    # Floor at 1e-10 to avoid log(0) in deviance and 0/0 in working response.
    mu <- pmax(mu, 1e-10)
    w <- mu
    z <- eta + (y - mu) / mu
  } else if (family == "Gamma") {
    # Gamma with log link
    # Link: eta = log(mu), mu = exp(eta)
    # Variance: V(mu) = mu^2
    # IRLS weight: w = 1/(V(mu) * (d_eta/d_mu)^2) = 1/(mu^2 * 1/mu^2) = 1
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    w <- rep(1, n)
    z <- eta + (y - mu) / mu
  } else if (family == "inverse.gaussian") {
    # Inverse Gaussian with log link
    # Link: eta = log(mu), mu = exp(eta)
    # Variance: V(mu) = mu^3
    # IRLS weight: w = 1/(V(mu) * (d_eta/d_mu)^2) = 1/(mu^3 * 1/mu^2) = 1/mu
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    w <- 1 / mu
    z <- eta + (y - mu) / mu
  }

  # IRLS update with L2 regularization
  # beta_new = (X'WX + lambda*I)^{-1} * X'W(z - eta_other)
  W <- diag(w)
  XtWX <- crossprod(X, W %*% X) + diag(lambda, p)
  XtWz <- crossprod(X, w * (z - eta_other))

  # Solve system
  beta_new <- tryCatch(
    as.vector(solve(XtWX, XtWz)),
    error = function(e) {
      # If solve fails, use regularized pseudo-inverse
      warning("Matrix near-singular, using additional regularization")
      as.vector(solve(XtWX + diag(0.01, p), XtWz))
    }
  )

  # Guard against numerical blow-up. Can happen when X^T W X is
  # near-singular (collinear features) or early iterations of non-Gaussian
  # families produce extreme working responses. Scaling preserves the
  # direction of the update while keeping magnitudes reasonable.
  converged <- TRUE
  if (any(abs(beta_new) > 1e6)) {
    beta_new <- beta_new / max(abs(beta_new)) * 1e2
    converged <- FALSE
    warning("Large coefficient update detected, scaling applied")
  }

  # Compute eta for this partition
  eta_new <- as.vector(X %*% beta_new)

  list(
    beta = beta_new,
    eta = eta_new,
    converged = converged
  )
}
