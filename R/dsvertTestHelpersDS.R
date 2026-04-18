#' @title Inject missing values into a column (aggregate, test helper)
#' @description Set a fixed fraction of values in \code{column} to NA
#'   using the provided RNG seed, and write the result back to the
#'   data frame under \code{output_column}. Used to create reproducible
#'   synthetic-missingness scenarios for MI validation. Only returns
#'   aggregate counts; no per-patient information.
#' @export
dsvertInjectNADS <- function(data_name, column,
                              fraction = 0.2, seed = 7L,
                              output_column = NULL) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!column %in% names(data)) stop("column not found", call. = FALSE)
  if (is.null(output_column) || !nzchar(output_column))
    output_column <- column
  set.seed(as.integer(seed))
  n <- nrow(data)
  k <- max(1L, floor(as.numeric(fraction) * n))
  idx <- sample.int(n, k)
  col <- data[[column]]
  col[idx] <- NA
  data[[output_column]] <- col
  assign(data_name, data, envir = parent.frame())
  list(n = n, n_na_injected = k, output_column = output_column)
}

#' @title Append a contiguous-block cluster column (aggregate, test helper)
#' @description Append a cluster id column where each block of
#'   \code{block_size} consecutive rows shares a cluster. Used to
#'   validate \code{ds.vertLMM} on datasets that do not ship with a
#'   natural cluster variable.
#' @export
dsvertAddClusterColumnDS <- function(data_name, block_size = 13L,
                                      output_column = "cluster") {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  n <- nrow(data)
  bs <- as.integer(block_size)
  if (bs <= 0L) stop("block_size must be positive", call. = FALSE)
  data[[output_column]] <- as.integer((seq_len(n) - 1L) %/% bs) + 1L
  assign(data_name, data, envir = parent.frame())
  list(n = n, n_clusters = length(unique(data[[output_column]])),
       output_column = output_column)
}

#' @title Append synthetic exponential time + binary event columns (test helper)
#' @description Draw \code{time ~ Exp(lambda_i)} with
#'   \code{lambda_i = 1 / (base_scale * (1 + beta * x))} where \code{x}
#'   is a covariate column held on this server, and a binary
#'   \code{event} indicator with rate \code{event_rate}. Used to
#'   validate \code{ds.vertCox} on datasets that do not ship with
#'   native time-to-event data. Both new columns are written back to
#'   the data frame. Only aggregate counts are returned.
#' @export
dsvertAddSyntheticSurvivalDS <- function(data_name,
                                          covariate_column,
                                          beta = 0.05,
                                          base_scale = 20,
                                          event_rate = 0.6,
                                          time_column = "time",
                                          event_column = "event",
                                          seed = 13L) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!covariate_column %in% names(data))
    stop("covariate_column not found", call. = FALSE)
  set.seed(as.integer(seed))
  x <- data[[covariate_column]]
  x[is.na(x)] <- mean(x, na.rm = TRUE)
  lambda <- pmax(1e-3, 1 / (as.numeric(base_scale) *
                             (1 + as.numeric(beta) * x)))
  n <- nrow(data)
  data[[time_column]] <- stats::rexp(n, lambda)
  data[[event_column]] <- as.integer(stats::rbinom(n, 1L,
                                                    as.numeric(event_rate)))
  assign(data_name, data, envir = parent.frame())
  list(n = n, n_events = sum(data[[event_column]]),
       time_column = time_column, event_column = event_column)
}

#' @title Append an age-quartile factor column (test helper)
#' @description Compute quartile boundaries of the named column
#'   (defaulting to \code{age}) and attach a factor column with levels
#'   Q1..Q4. Used to validate \code{ds.vertChisqCross}.
#' @export
dsvertAddQuartileColumnDS <- function(data_name, column = "age",
                                       output_column = "age_q") {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!column %in% names(data)) stop("column not found", call. = FALSE)
  x <- data[[column]]
  q <- stats::quantile(x, probs = c(0, .25, .5, .75, 1), na.rm = TRUE)
  q[1L] <- q[1L] - 1e-9
  q[length(q)] <- q[length(q)] + 1e-9
  data[[output_column]] <- cut(x, breaks = as.numeric(q),
                                include.lowest = TRUE,
                                labels = c("Q1", "Q2", "Q3", "Q4"))
  assign(data_name, data, envir = parent.frame())
  list(n = nrow(data), breaks = as.numeric(q),
       output_column = output_column)
}

#' @title Copy a data frame to a new name (test helper)
#' @export
dsvertCopyDfDS <- function(data_name, output_name) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  assign(output_name, data, envir = parent.frame())
  list(n = nrow(data), output_name = output_name)
}
