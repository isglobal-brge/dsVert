#' @title Server-side local descriptive moments (aggregate)
#' @description Compute plaintext mean, standard deviation, optional min/max,
#'   counts of non-missing / missing observations for a numeric variable
#'   held by a single server. The variable never leaves the server; only the
#'   scalar summaries do. This is the building block for \code{ds.vertDesc}
#'   (client-side federated \code{summary()}).
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param variable Character. Name of the numeric column.
#' @param return_extrema Logical. Client REQUEST for exact min/max. Extrema are
#'   released only if BOTH this is \code{TRUE} AND the custodian option
#'   \code{getOption("dsvert.allow_exact_extrema", FALSE)} is \code{TRUE}
#'   (server-authoritative, F3): a client argument can never loosen the control,
#'   because exact extrema disclose two identifiable outliers.
#'
#' @return A list with elements:
#'   \itemize{
#'     \item \code{mean}: sample mean of non-missing values
#'     \item \code{sd}:   sample standard deviation (n-1 denominator)
#'     \item \code{min}:  minimum of non-missing values, or \code{NA} unless
#'       exact extrema are explicitly enabled
#'     \item \code{max}:  maximum of non-missing values, or \code{NA} unless
#'       exact extrema are explicitly enabled
#'     \item \code{n_total}: number of non-missing observations
#'     \item \code{n_na}:    number of missing observations
#'   }
#'   If the cohort is below the DataSHIELD privacy threshold the numeric
#'   summaries are returned as \code{NA} and only counts are released.
#'
#' @details Because the variable is held in plaintext by a single server,
#'   this is not a secure-computation step -- it is a plain release of
#'   aggregate statistics, subject to standard DataSHIELD disclosure control
#'   (minimum cohort size). The returned values are scalar aggregates over
#'   all non-missing observations and carry no per-observation information.
#'
#' @seealso \code{dsvertHistogramDS}
#' @importFrom stats sd
#' @export
dsvertLocalMomentsDS <- function(data_name, variable,
                                 return_extrema = FALSE) {
  # F3 (server-authoritative): a client arg may only REQUEST extrema; the
  # custodian option must also permit them. AND-combine so the analyst cannot
  # force exact min/max by passing return_extrema=TRUE.
  allow_extrema <- isTRUE(return_extrema) &&
    isTRUE(getOption("dsvert.allow_exact_extrema", FALSE))
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

  n_na <- sum(is.na(raw))
  x <- raw[!is.na(raw)]
  n_total <- length(x)

  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n_total < privacy_min) {
    return(list(
      mean = NA_real_, sd = NA_real_,
      min = NA_real_, max = NA_real_,
      n_total = n_total, n_na = n_na,
      extrema_released = FALSE
    ))
  }

  list(
    mean = mean(x),
    sd = if (n_total > 1L) sd(x) else NA_real_,
    min = if (allow_extrema) min(x) else NA_real_,
    max = if (allow_extrema) max(x) else NA_real_,
    n_total = n_total,
    n_na = n_na,
    extrema_released = allow_extrema
  )
}
