#' @title Get Observation Count (Server-Side)
#' @description Server-side aggregate function that returns the number of
#'   observations in a data frame. Used for validation and dimension matching
#'   in vertical federated analysis.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param variables Character vector. Optional. If provided, returns the count
#'   of complete cases for these variables only. Default is NULL (all rows).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{n_obs}: Number of observations (or complete cases)
#'     \item \code{n_vars}: Number of variables (if variables specified)
#'   }
#'
#' @details
#' This utility function supports the coordination of vertical federated
#' analysis by allowing the client to verify that all servers have matching
#' observation counts after record alignment.
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' # result <- datashield.aggregate(conn, "getObsCountDS('D')")
#' }
#'
#' @importFrom stats complete.cases
#' @export
getObsCountDS <- function(data_name, variables = NULL) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  if (is.null(variables)) {
    n_obs <- nrow(data)
    n_vars <- ncol(data)
  } else {
    # Check variables exist
    missing_vars <- setdiff(variables, names(data))
    if (length(missing_vars) > 0) {
      stop("Variables not found: ", paste(missing_vars, collapse = ", "),
           call. = FALSE)
    }

    subset_data <- data[, variables, drop = FALSE]
    n_obs <- sum(complete.cases(subset_data))
    n_vars <- length(variables)
  }

  list(
    n_obs = n_obs,
    n_vars = n_vars
  )
}
