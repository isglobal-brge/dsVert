vertCorDS <- function(data_name, variable_names = NULL) {

  U_combined <- NULL

  for(var_name in variable_names) {
    result <- data_name[[var_name]]
    result <- scale(result)
    svd_result <- svd(result)
    U_combined <- cbind(U_combined, svd_result$u %*% svd_result$d)
  }

  return(U_combined)
}
