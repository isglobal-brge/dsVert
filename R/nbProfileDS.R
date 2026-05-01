#' @title NB profile-MLE score sums for dispersion theta (aggregate)
#' @description Compute scalar sums needed to evaluate the profile
#'   log-likelihood score and its derivative for the negative-binomial
#'   dispersion parameter theta at a given theta value. The outcome variable is
#'   held in plaintext by a single (label) server; this function returns
#'   four scalar aggregates computed on that plaintext -- no per-patient
#'   disclosure.
#'
#'   The NB(mu, theta) log-likelihood, assuming a common mean mu, has score
#'     dell/dtheta = Sum_i psi(y_i + theta) - n psi(theta) + n log(theta/(ybar + theta))
#'   and Fisher-like curvature
#'     -d^2ell/dtheta^2 approx -[Sum_i psi_1(y_i + theta) - n psi_1(theta)] - n * [1/theta - 1/(ybar + theta)]
#'   where psi is the digamma function and psi_1 its derivative (trigamma).
#'   This is the Anscombe / Lawless parametrisation used by
#'   \code{MASS::theta.ml}, specialised to the homogeneous-mu case so that
#'   the outcome server does not need any beta / eta quantities -- only its own
#'   y plus a client-chosen scalar theta.
#'
#'   Reveals exactly four floats per call: Sumpsi(y+theta), Sumpsi_1(y+theta), n, ybar. All
#'   are already-aggregate functions of y. The caller iterates theta
#'   client-side via Newton-Raphson.
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param variable Character. Name of the non-negative integer outcome.
#' @param theta Numeric scalar. Candidate dispersion value (> 0).
#'
#' @return A list with four numeric scalars:
#'   \itemize{
#'     \item \code{sum_psi}: Sum psi(y_i + theta)
#'     \item \code{sum_tri}: Sum psi_1(y_i + theta)
#'     \item \code{n_total}: count of non-missing observations
#'     \item \code{y_mean}:  sample mean of y (ybar)
#'   }
#'   Returned as \code{NA_real_} if the cohort falls below the
#'   \code{datashield.privacyLevel} threshold.
#'
#' @seealso \code{dsvertLocalMomentsDS}, \code{ds.vertNB}, \code{dsvertNBMomentSumsDS}
#' @export
dsvertNBProfileSumsDS <- function(data_name, variable, theta) {
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variable) || length(variable) != 1) {
    stop("variable must be a single character string", call. = FALSE)
  }
  theta <- as.numeric(theta)
  if (!is.finite(theta) || length(theta) != 1L || theta <= 0) {
    stop("theta must be a single finite positive number", call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!variable %in% names(data)) {
    stop("Variable '", variable, "' not found in data frame '",
         data_name, "'", call. = FALSE)
  }

  raw <- data[[variable]]
  if (!is.numeric(raw)) {
    stop("Variable '", variable, "' must be numeric", call. = FALSE)
  }

  x <- raw[!is.na(raw)]
  n_total <- length(x)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n_total < privacy_min) {
    return(list(sum_psi = NA_real_, sum_tri = NA_real_,
                n_total = n_total, y_mean = NA_real_))
  }
  list(
    sum_psi = sum(digamma(x + theta)),
    sum_tri = sum(trigamma(x + theta)),
    n_total = n_total,
    y_mean  = mean(x)
  )
}

#' @title NB Method-of-Moments aggregate sufficient statistics
#' @description Returns the four scalar y-sufficient statistics needed
#'   to compute the iid-mu Method-of-Moments theta-estimator (Anscombe 1950
#'   Biometrika 37(3-4):358-382; Saha & Paul 2005 Biometrics 61(1):179-185
#'   Sec.3 reduction under common-mu). All outputs are functions of y alone
#'   (no mu or beta disclosure), revealing 4 floats per call (Sumy, Sumy^2, n, ybar).
#'   Disclosure budget is the SAME as \code{dsvertNBProfileSumsDS} --
#'   y aggregates only; ZERO new disclosure beyond the existing iid-mu
#'   path.
#'
#'   Under common-mu (mu == ybar), the regression-aware Saha-Paul 2005
#'   moment equation reduces to the Anscombe 1950 sample-moment form
#'     theta_MoM = ybar^2 / (s^2 - ybar)
#'   where s^2 = (Sumy^2 - n*ybar^2)/(n-1) is the bias-corrected sample
#'   variance. Closed form -- no Newton iteration on theta. The iid-mu
#'   approximation propagates through both estimators (iid-mu MLE and
#'   iid-mu MoM) with the same structural bias direction; full-regression
#'   MoM (Saha-Paul Method 2 with per-patient mu_i) requires eta at OS,
#'   currently outside the K=2-safe disclosure budget.
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param variable  Character. Name of the non-negative integer outcome.
#' @return List with \code{n_total}, \code{sum_y}, \code{sum_y_sq},
#'   \code{y_mean}, \code{y_var}.
#' @seealso \code{ds.vertNBMoMTheta}, \code{dsvertNBProfileSumsDS}
#' @export
dsvertNBMomentSumsDS <- function(data_name, variable) {
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variable) || length(variable) != 1) {
    stop("variable must be a single character string", call. = FALSE)
  }
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!variable %in% names(data)) {
    stop("Variable '", variable, "' not found in data frame '",
         data_name, "'", call. = FALSE)
  }
  raw <- data[[variable]]
  if (!is.numeric(raw)) {
    stop("Variable '", variable, "' must be numeric", call. = FALSE)
  }
  x <- raw[!is.na(raw)]
  n_total <- length(x)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n_total < privacy_min) {
    return(list(n_total = n_total, sum_y = NA_real_,
                sum_y_sq = NA_real_, y_mean = NA_real_,
                y_var = NA_real_))
  }
  sy   <- sum(x)
  sy2  <- sum(x * x)
  ybar <- sy / n_total
  yvar <- if (n_total > 1L) (sy2 - n_total * ybar * ybar) / (n_total - 1L)
          else NA_real_
  list(n_total = n_total, sum_y = sy, sum_y_sq = sy2,
       y_mean = ybar, y_var = yvar)
}
