#' Get Correlation Matrix for two Vertically Partitioned datasets
#'
#' @param data1 Partition 1
#' @param data2 Partition 2 w/ assumption that the two datasets are already alligned
#'
#' @return correlation matrix obtained via block SVD results of the two partitions
#' @export
#'
#' @examples vertical_corr(Partition1, Partition2)
#'

vertical_corr <- function(data1, data2) {
  # Initialize an empty matrix
  #U_combined <- matrix(, nrow = nrow(data1), ncol = 0)
  U_combined <- NULL
  # The block SVD algo requires partitioning of our data into columns.
  #So that is what we are doing here, computing svd on each column.
  #Bascially immitating a block svd currently
  for(i in seq_len(ncol(data1))) {
    svd_col <- svd(data1[, i, drop = FALSE])
    U_combined <- cbind(U_combined, svd_col$u %*% svd_col$d)
  }

  for(i in seq_len(ncol(data2))) {
    svd_col <- svd(data2[, i, drop = FALSE])
    U_combined <- cbind(U_combined, svd_col$u %*% svd_col$d)
  }

  # Perform SVD on the combined U matrix
  svd_final <- svd(U_combined)

  # Calculate and scale the correlation matrix
  correlation <- svd_final$v %*% diag(svd_final$d^2) %*% t(svd_final$v)
  correlation <- correlation / correlation[1, 1]

  return(correlation)
}
