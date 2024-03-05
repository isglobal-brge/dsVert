#' Get Correlation Matrix from a single dataset using SVD components
#'
#' @param data any matrix containing numerical variables
#'
#' @return correlation matrix
#' @export
#'
#' @examples get_corr(any_data)
#'

get_corr <- function(data) {
  #first need to center and scale data to be able to get corr matrix from svd
  data_centered_scaled <- scale(data)
  svd_result <- svd(data_centered_scaled)

  #get each svd component
  U <- svd_result$u
  D <- svd_result$d
  V <- svd_result$v

  #formula for correlation from svd
  correlation_matrix <- V %*% diag(D^2) %*% t(V)

  #For some reason there is a need to scale our correlation matrix
  correlation_matrix <- correlation_matrix/correlation_matrix[1,1]

  return(correlation_matrix)
}
