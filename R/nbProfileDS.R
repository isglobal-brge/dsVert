#' @title NB profile-MLE score sums for dispersion θ (aggregate)
#' @description Compute scalar sums needed to evaluate the profile
#'   log-likelihood score and its derivative for the negative-binomial
#'   dispersion parameter θ at a given θ value. The outcome variable is
#'   held in plaintext by a single (label) server; this function returns
#'   four scalar aggregates computed on that plaintext — no per-patient
#'   disclosure.
#'
#'   The NB(μ, θ) log-likelihood, assuming a common mean μ, has score
#'     ∂ℓ/∂θ = Σᵢ ψ(yᵢ + θ) − n ψ(θ) + n log(θ/(ȳ + θ))
#'   and Fisher-like curvature
#'     −∂²ℓ/∂θ² ≈ −[Σᵢ ψ₁(yᵢ + θ) − n ψ₁(θ)] − n · [1/θ − 1/(ȳ + θ)]
#'   where ψ is the digamma function and ψ₁ its derivative (trigamma).
#'   This is the Anscombe / Lawless parametrisation used by
#'   \code{MASS::theta.ml}, specialised to the homogeneous-μ case so that
#'   the outcome server does not need any β / η quantities — only its own
#'   y plus a client-chosen scalar θ.
#'
#'   Reveals exactly four floats per call: Σψ(y+θ), Σψ₁(y+θ), n, ȳ. All
#'   are already-aggregate functions of y. The caller iterates θ
#'   client-side via Newton-Raphson.
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param variable Character. Name of the non-negative integer outcome.
#' @param theta Numeric scalar. Candidate dispersion value (> 0).
#'
#' @return A list with four numeric scalars:
#'   \itemize{
#'     \item \code{sum_psi}: Σ ψ(yᵢ + θ)
#'     \item \code{sum_tri}: Σ ψ₁(yᵢ + θ)
#'     \item \code{n_total}: count of non-missing observations
#'     \item \code{y_mean}:  sample mean of y (ȳ)
#'   }
#'   Returned as \code{NA_real_} if the cohort falls below the
#'   \code{datashield.privacyLevel} threshold.
#'
#' @seealso \code{dsvertLocalMomentsDS}, \code{ds.vertNB}
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
