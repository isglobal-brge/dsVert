#' @title Remove dsVert-internal columns from the aligned data frame
#' @description Aggregate helper. Strips any column whose name starts
#'   with \code{__dsvert_} (e.g. \code{__dsvert_lmm_w},
#'   \code{__dsvert_r2}) that previous methods added to the aligned
#'   data frame. Combined with the existing \code{mpcCleanupDS}
#'   (wipes MPC session) this provides a complete per-method teardown
#'   so running multiple dsVert methods sequentially cannot corrupt
#'   each other's state.
#'
#'   Convention: every dsVert server helper that materialises a new
#'   column on the data frame prefixes the name with \code{__dsvert_}.
#'   Client wrappers should call this at the end of their on.exit
#'   cleanup chain to restore the data frame to its post-PSI state.
#' @param data_name Aligned data-frame name.
#' @param keep Optional character vector of column names to preserve
#'   (e.g. synthetic columns that the caller added on purpose and
#'   wants to keep — "cluster", "time", "event", "age_q").
#' @return list(columns_removed = character, n_removed = integer).
#' @export
dsvertResetDataFrameDS <- function(data_name, keep = character(0)) {
  .validate_data_name(data_name)
  data <- tryCatch(get(data_name, envir = parent.frame()),
                    error = function(e) NULL)
  if (is.null(data) || !is.data.frame(data)) {
    return(list(columns_removed = character(0), n_removed = 0L))
  }
  cols <- names(data)
  drop <- grepl("^__dsvert_", cols) & !(cols %in% as.character(keep))
  if (any(drop)) {
    data <- data[, !drop, drop = FALSE]
    assign(data_name, data, envir = parent.frame())
  }
  list(columns_removed = cols[drop],
       n_removed = as.integer(sum(drop)))
}
