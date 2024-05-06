#' Serverside function used to has an Id variable of a dataframe, taking full advantage of digest library
#'
#' @param data_name The name of the dataframe on the server
#' @param id_variable Variable to be hashed
#' @param algo Which digest algorithm to use, it is set to sha256 is a base
#'
#' @return vector of hashes
#' @export
#'
#' @examples hashIdDS(D, "id", "sha256")
hashIdDS <- function(data_name, id_variable, algo = "sha256") {

  # basically just taking advantage of the digest library

  beforeHash <- data_name[[id_variable]]
  orderHash1 <- vector("character", length(beforeHash))
  for(i in 1:length(beforeHash)){
    orderHash1[i] <- digest(beforeHash[i], algo = algo)
  }

  return(orderHash1)
}
