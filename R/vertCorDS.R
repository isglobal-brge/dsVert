#' Serverside function used for vertCor
#'
#' @param variable_names variables to be used in correlation matrix
#'
#' @return the combined matrix for the intermidiary step of the block SVD algorithm
#' @export
#'
#' @examples TODO
vertCorDS <- function(variable_names = NULL) {

  U_combined <- NULL

  for (var_name in variable_names) {
    result <- eval(parse(text=var_name), envir = parent.frame())
    result[is.na(result)] <- 0
    result <- scale(result)
    #print(result)
    svd_result <- svd(result)
    U_combined <- cbind(U_combined, svd_result$u %*% svd_result$d)

    ##### first version of code
    #if (exists(var_name, envir = parent.frame())) {
    #  #go ahead with eval
    #  result <- eval(parse(text=var_name), envir = parent.frame())
    #
    #  svd_result <- svd(result)
    #  U_combined <- cbind(U_combined, svd_result$u %*% svd_result$d)
    #} else {
    #  #var is likely in other server
    #}
  }

  return(U_combined)
}
